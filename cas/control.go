package cas

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	terminalRulesPath = "/enlink/api/client/user/terminal/rules/"

	defaultRulesAttempts = 6
	defaultRulesInterval = 2 * time.Second
	defaultMinLoginGap   = 5 * time.Second
)

// Endpoint 是控制器下发的一个网关候选地址。
type Endpoint struct {
	Host string
	Port int
}

func (e Endpoint) String() string {
	return net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
}

// Rules 是 GET /user/terminal/rules 返回的隧道参数。
type Rules struct {
	// Token 是隧道握手帧的 B 字段，必须原样发送（不要 base64、不要去横线）。
	Token string
	// Servers 是网关候选列表。
	Servers []Endpoint
	// SPAPort 是 SPA 敲门端口，通常 62201。
	SPAPort int
	// SPAStatus 是控制器认为 SPA 是否已启用。
	SPAStatus bool
	// AdminPort 是管理端口，仅在需要时使用。
	AdminPort int
	// Raw 保留原始字段。
	Raw map[string]any
}

// FirstEndpoint 返回首选的网关地址。
func (r *Rules) FirstEndpoint() (Endpoint, error) {
	if r == nil || len(r.Servers) == 0 {
		return Endpoint{}, errors.New("cas: 没有可用的网关地址")
	}
	return r.Servers[0], nil
}

// SPAHost 返回发送 SPA 的目标主机：优先用列表里的第二个候选（通常是网关真实 IP）。
func (r *Rules) SPAHost() string {
	if r == nil || len(r.Servers) == 0 {
		return ""
	}
	if len(r.Servers) > 1 && r.Servers[1].Host != "" {
		return r.Servers[1].Host
	}
	return r.Servers[0].Host
}

// parseServers 解析 "host:port||ip:port||443" 形式的候选列表。
// 不含冒号的纯端口项会沿用上一个 host。
func parseServers(raw string) []Endpoint {
	var out []Endpoint
	for _, part := range strings.Split(raw, "||") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		host, portText, err := net.SplitHostPort(part)
		if err != nil {
			// 纯端口：沿用上一个 host
			port, convErr := strconv.Atoi(part)
			if convErr != nil || port <= 0 || len(out) == 0 {
				continue
			}
			out = append(out, Endpoint{Host: out[len(out)-1].Host, Port: port})
			continue
		}
		port, convErr := strconv.Atoi(portText)
		if convErr != nil || port <= 0 {
			port = 443
		}
		out = append(out, Endpoint{Host: host, Port: port})
	}
	return out
}

func parseRules(data map[string]any) (*Rules, error) {
	token := stringOf(data["token"])
	if token == "" {
		return nil, errors.New("cas: terminal/rules 未返回 token（同账号可能已有其它会话占用）")
	}
	rules := &Rules{
		Token:     token,
		Servers:   parseServers(stringOf(data["server"])),
		SPAPort:   intOf(data["spa_port"]),
		SPAStatus: boolOf(data["spa_status"]),
		AdminPort: intOf(data["admin_port"]),
		Raw:       data,
	}
	if len(rules.Servers) == 0 {
		return nil, errors.New("cas: terminal/rules 未返回可用的网关地址")
	}
	return rules, nil
}

// FetchRules 拉取隧道 token 与网关列表。
//
// 同一账号同时只允许一条会话：被占用时接口会返回不带 token 的错误体，所以这里
// 带重试与退避。检测到会话失效（重定向到 SSO 登录页）时立即返回 ErrSessionExpired，
// 不做无谓重试。
func (s *Session) FetchRules(ctx context.Context, attempts int, interval time.Duration) (*Rules, error) {
	if attempts <= 0 {
		attempts = defaultRulesAttempts
	}
	if interval <= 0 {
		interval = defaultRulesInterval
	}
	rawURL := s.cfg.Controller + terminalRulesPath + s.UserID

	var lastErr error
	for i := 1; i <= attempts; i++ {
		rules, err := s.fetchRulesOnce(ctx, rawURL)
		if err == nil {
			s.cfg.logf("cas: 取得隧道 token（第 %d 次尝试）", i)
			return rules, nil
		}
		lastErr = err
		if errors.Is(err, ErrSessionExpired) {
			return nil, err
		}
		s.cfg.logf("cas: terminal/rules 第 %d/%d 次失败: %v", i, attempts, err)
		if i == attempts {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}
	return nil, fmt.Errorf("cas: 拉取 terminal/rules 失败: %w", lastErr)
}

func (s *Session) fetchRulesOnce(ctx context.Context, rawURL string) (*Rules, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", s.cfg.UserAgent)

	resp, err := s.controllerNoFollowClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cas: terminal/rules 请求失败: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return nil, err
	}

	// 控制器把请求踢回登录页 = 会话失效。webvpn 对失效会话也会返回 200 的访客页，
	// 所以除了看状态码，还要在响应体里找登录页路径。
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if strings.Contains(location, VPNSsoLoginPath) || IsVPNSsoPage(location) {
			return nil, fmt.Errorf("%w: terminal/rules 被重定向到登录页", ErrSessionExpired)
		}
		return nil, fmt.Errorf("cas: terminal/rules 返回重定向 %d → %s", resp.StatusCode, truncate([]byte(location), 120))
	}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, ErrSessionExpired
		}
		return nil, fmt.Errorf("cas: terminal/rules 返回 HTTP %d: %s", resp.StatusCode, truncate(body, 200))
	}
	if bytes.Contains(body, []byte(VPNSsoLoginPath)) {
		return nil, fmt.Errorf("%w: terminal/rules 返回了登录页", ErrSessionExpired)
	}

	var parsed struct {
		Code     string         `json:"code"`
		Messages string         `json:"messages"`
		Data     map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("cas: terminal/rules 响应不是 JSON: %w（%s）", err, truncate(body, 120))
	}
	if parsed.Code == "401" {
		return nil, ErrSessionExpired
	}
	if parsed.Data == nil {
		return nil, fmt.Errorf("cas: terminal/rules 没有 data（code=%q messages=%q）", parsed.Code, parsed.Messages)
	}
	return parseRules(parsed.Data)
}

// CookieCache 抽象会话 Cookie 的持久化，用于跨重启复用会话、避免每次都跑 CAS 登录。
type CookieCache interface {
	Load() (map[string]string, error)
	Store(cookies map[string]string) error
}

// FileCookieCache 把 Cookie 以 JSON 落盘（0600）。
type FileCookieCache struct {
	Path string
}

// Load 读取缓存的 Cookie；文件不存在不算错误。
func (c FileCookieCache) Load() (map[string]string, error) {
	if c.Path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(c.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cookies map[string]string
	if err := json.Unmarshal(data, &cookies); err != nil {
		// 缓存损坏就当作没有缓存，不要因此登录失败。
		return nil, nil
	}
	return cookies, nil
}

// Store 写入缓存。
func (c FileCookieCache) Store(cookies map[string]string) error {
	if c.Path == "" {
		return nil
	}
	data, err := json.Marshal(cookies)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(c.Path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	file, err := os.CreateTemp(filepath.Dir(c.Path), ".session-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), c.Path)
}

// ManagerOptions 是 Manager 的配置。
type ManagerOptions struct {
	// Config 是登录配置。
	Config Config
	// RulesAttempts 是拉取 terminal/rules 的重试次数，默认 6。
	RulesAttempts int
	// RulesInterval 是重试间隔，默认 2s。
	RulesInterval time.Duration
	// MinLoginGap 是两次重新登录之间的最小间隔，默认 5s。
	// 同账号单会话 + 风控，重登过快会互相踢掉。
	MinLoginGap time.Duration
	// Cache 可选：持久化 Cookie。
	Cache CookieCache
}

// Manager 维护"CAS 会话"与"隧道 token"两层凭据，并在失效时自动重登。
//
// 所有对外方法都必须单飞：同一账号同时只允许一条会话，并发登录会互相踢掉，
// 还可能触发风控锁账号。
type Manager struct {
	opts ManagerOptions

	mu        contextMutex
	ctx       context.Context
	cancel    context.CancelFunc
	session   *Session
	rules     *Rules
	lastLogin time.Time
	// forceLogin 为 true 时忽略磁盘上的 Cookie 缓存，直接重新登录。
	// 它只在"已判定会话失效"后置位，冷启动时为 false。
	forceLogin bool
}

// contextMutex 保留同步状态访问，同时允许网络调用的等待者及时取消。
type contextMutex struct {
	once sync.Once
	ch   chan struct{}
}

func (m *contextMutex) LockContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.once.Do(func() { m.ch = make(chan struct{}, 1) })
	select {
	case m.ch <- struct{}{}:
		if err := ctx.Err(); err != nil {
			m.Unlock()
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (m *contextMutex) Lock()   { _ = m.LockContext(context.Background()) }
func (m *contextMutex) Unlock() { <-m.ch }

// operationContext 同时受调用者和 Manager.Close 控制，兼容 Go 1.20。
func (m *Manager) operationContext(parent context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-m.ctx.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, func() { cancel(); <-done }
}

// NewManager 构造 Manager。不会立刻登录。
func NewManager(opts ManagerOptions) (*Manager, error) {
	cfg, err := opts.Config.withDefaults()
	if err != nil {
		return nil, err
	}
	opts.Config = cfg
	if opts.RulesAttempts <= 0 {
		opts.RulesAttempts = defaultRulesAttempts
	}
	if opts.RulesInterval <= 0 {
		opts.RulesInterval = defaultRulesInterval
	}
	if opts.MinLoginGap <= 0 {
		opts.MinLoginGap = defaultMinLoginGap
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{opts: opts, ctx: ctx, cancel: cancel}, nil
}

// Session 返回当前会话，可能为 nil。
func (m *Manager) Session() *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.session
}

// EnsureRules 返回可用的隧道参数，必要时自动重新登录。
// force 为 true 时先丢弃缓存的 token。
func (m *Manager) EnsureRules(ctx context.Context, force bool) (*Rules, error) {
	ctx, cancel := m.operationContext(ctx)
	defer cancel()
	if err := m.mu.LockContext(ctx); err != nil {
		return nil, err
	}
	defer m.mu.Unlock()
	if m.ctx.Err() != nil {
		return nil, net.ErrClosed
	}

	if force {
		m.rules = nil
	}
	if m.rules != nil {
		return m.rules, nil
	}

	// 1) 冷启动：先用磁盘上的 Cookie 恢复会话，避免每次重启都跑一遍 CAS 登录。
	// forceLogin 为 true（刚判定会话失效）时跳过缓存，直接重新登录。
	if m.session == nil && !m.forceLogin {
		if cached, err := m.loadCache(); err == nil && len(cached) > 0 {
			session, err := NewSession(m.opts.Config, cached)
			if err != nil {
				m.opts.Config.logf("cas: 缓存 Cookie 无法恢复会话: %v", err)
			} else {
				m.session = session
			}
		}
	}

	// 2) 用现有会话再试一次（可能只是上一次拉取被单会话限制挡了）。
	if m.session != nil {
		rules, err := m.session.FetchRules(ctx, m.opts.RulesAttempts, m.opts.RulesInterval)
		if err == nil {
			m.rules = rules
			m.storeCache(m.session.Cookies())
			return rules, nil
		}
		if !errors.Is(err, ErrSessionExpired) {
			return nil, err
		}
		m.discardSessionLocked()
	}

	// 3) 重新登录后再拉。
	if err := m.loginLocked(ctx); err != nil {
		return nil, err
	}
	rules, err := m.session.FetchRules(ctx, m.opts.RulesAttempts, m.opts.RulesInterval)
	if err != nil {
		return nil, err
	}
	m.rules = rules
	m.storeCache(m.session.Cookies())
	return rules, nil
}

// Invalidate 丢弃缓存的 token；sessionExpired 为 true 时连会话一起丢弃，
// 并跳过 Cookie 缓存、强制重新登录。
func (m *Manager) Invalidate(sessionExpired bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules = nil
	if sessionExpired {
		m.discardSessionLocked()
	}
}

// Login 强制重新登录并刷新 token。
func (m *Manager) Login(ctx context.Context) (*Rules, error) {
	ctx, cancel := m.operationContext(ctx)
	defer cancel()
	if err := m.mu.LockContext(ctx); err != nil {
		return nil, err
	}
	defer m.mu.Unlock()
	if m.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if err := m.loginLocked(ctx); err != nil {
		return nil, err
	}
	rules, err := m.session.FetchRules(ctx, m.opts.RulesAttempts, m.opts.RulesInterval)
	if err != nil {
		return nil, err
	}
	m.rules = rules
	return rules, nil
}

// Username 返回学号（会话尚未建立时从 bundle 反解）。
func (m *Manager) Username() string {
	if session := m.Session(); session != nil && session.Username != "" {
		return session.Username
	}
	if m.opts.Config.Bundle != nil {
		if name, err := m.opts.Config.Bundle.Username(); err == nil {
			return name
		}
	}
	return ""
}

// Close 释放 HTTP 连接池。
func (m *Manager) Close() {
	m.cancel()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.discardSessionLocked()
}

func (m *Manager) discardSessionLocked() {
	if m.session != nil {
		m.session.Close()
	}
	m.session = nil
	m.rules = nil
	m.forceLogin = true
}

// loginLocked 重新登录。调用方必须持有 m.mu。
func (m *Manager) loginLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !m.lastLogin.IsZero() {
		if wait := m.opts.MinLoginGap - time.Since(m.lastLogin); wait > 0 {
			m.opts.Config.logf("cas: 距上次登录仅 %s，等待 %s 以避免互相踢会话",
				time.Since(m.lastLogin).Round(time.Millisecond), wait.Round(time.Millisecond))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}
	}

	m.opts.Config.logf("cas: 开始 Passkey 登录")
	session, err := Login(ctx, m.opts.Config)
	m.lastLogin = time.Now()
	if err != nil {
		return err
	}
	if m.session != nil {
		m.session.Close()
	}
	m.session = session
	m.rules = nil
	m.forceLogin = false
	m.storeCache(session.Cookies())
	return nil
}

func (m *Manager) loadCache() (map[string]string, error) {
	if m.opts.Cache == nil {
		return nil, nil
	}
	return m.opts.Cache.Load()
}

func (m *Manager) storeCache(cookies map[string]string) {
	if m.opts.Cache == nil || len(cookies) == 0 {
		return
	}
	if err := m.opts.Cache.Store(cookies); err != nil {
		m.opts.Config.logf("cas: 写入会话缓存失败: %v", err)
	}
}

func stringOf(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case nil:
		return ""
	default:
		return ""
	}
}

func intOf(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case json.Number:
		if n, err := t.Int64(); err == nil {
			return int(n)
		}
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
			return n
		}
	}
	return 0
}

func boolOf(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(strings.TrimSpace(t), "true")
	case float64:
		return t != 0
	}
	return false
}
