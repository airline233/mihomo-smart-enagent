// Package cas 实现 NUIST 统一身份认证的 Passkey（CAS + WebAuthn）登录，以及
// Enlink 控制面的会话维护。
//
// 与 authserver_login/NuistLogin.py 的 use_vpn=True 路径等价，但**只保留隧道需要
// 的那一段**：在真实 authserver 上做一次 CAS 断言，service 指向控制器的 CAS 回调，
// 从而拿到 client.vpn.nuist.edu.cn 域的会话 Cookie。webvpn 代理那条分支隧道用不到，
// 没有实现。
//
// 登录是纯网络层 + 本地私钥签名，不需要浏览器、不需要验证码、不需要口令加密。
package cas

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/airline233/mihomo-smart-enagent/passkey"
)

const (
	// AuthServerNormal 是统一身份认证地址。
	AuthServerNormal = "https://authserver.nuist.edu.cn"
	// ControllerNormal 是 Enlink 控制器地址。
	ControllerNormal = "https://client.vpn.nuist.edu.cn"
	// VPNCASCallback 是默认控制器的 CAS 回调；自定义控制器时使用对应地址。
	VPNCASCallback = ControllerNormal + "/enlink/api/client/callback/cas"
	// VPNDomain 是会话 Cookie 所属的域。
	VPNDomain = "client.vpn.nuist.edu.cn"
	// WebAuthnOrigin 是 clientDataJSON 里必须填的 origin。
	//
	// 它必须固定为**真实 authserver**：即使经 webvpn 代理访问，填代理域名也会被
	// 服务端以 401 拒绝。
	WebAuthnOrigin = AuthServerNormal
	// VPNSsoLoginPath 是 VPN 域的 SSO 登录页路径。落到这里说明 VPN 会话已失效，
	// 而不是登录成功——webvpn 对失效会话也会返回 200 的访客页，所以无法预探测。
	VPNSsoLoginPath = "/enlink/sso/login"

	loginPath          = "/authserver/login"
	startAssertionPath = "/authserver/startAssertion"

	// defaultExecution 是登录页里抓不到 execution 时的后备值（来自抓包）。
	defaultExecution = "e1s1"

	defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"

	// maxBodySize 限制读取的响应体，防止异常响应撑爆内存。
	maxBodySize = 4 << 20

	// authenticatorFlags 是 UP(0x01)|UV(0x04)：前端要求 userVerification。
	authenticatorFlags = 0x05
)

// ErrSessionExpired 表示控制器会话已失效，需要重新登录。
var ErrSessionExpired = errors.New("cas: 会话已失效")

// executionRe 从 CAS 登录页的隐藏 input 里取 execution。
var executionRe = regexp.MustCompile(`name=["']execution["'][^>]*value=["']([^"']+)`)

// Config 是登录与控制面访问的配置。
type Config struct {
	// Bundle 是已解析的 passkey 凭据，必填。
	Bundle *passkey.Bundle
	// AuthServer 是统一身份认证地址，默认 AuthServerNormal。
	// 覆盖它可以指向 httptest 服务，用于离线测试。
	AuthServer string
	// Controller 是 Enlink 控制器地址（可带端口），默认 ControllerNormal。
	Controller string
	// UserAgent 默认与参考实现一致的 Firefox UA。
	UserAgent string
	// Timeout 是单次 HTTP 请求超时，默认 30s。
	Timeout time.Duration
	// Rand 是断言签名的随机源，默认 crypto/rand.Reader。
	Rand io.Reader
	// AuthServerInsecure 关闭 authserver 的证书校验（默认 false，即校验）。
	AuthServerInsecure bool
	// ControllerSkipVerify 关闭控制器的证书校验。
	//
	// 参考实现（vpn_client.py 里的 session.verify = False）是关闭的，说明控制器
	// 可能使用自签证书。不确定时设 true；想校验就显式设 false。
	ControllerSkipVerify bool
	// DialContext 可选，注入控制面流量的底层拨号器。
	//
	// mihomo 侧应注入 component/dialer 的实现（支持 interface-name / routing-mark），
	// 否则控制面请求会走系统默认路由，在 TUN auto-route 场景下可能绕回自己的隧道。
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	// Logf 是可选日志回调。
	Logf func(format string, args ...any)
}

func (c Config) withDefaults() (Config, error) {
	if c.Bundle == nil {
		return c, errors.New("cas: 缺少 passkey bundle")
	}
	if c.AuthServer == "" {
		c.AuthServer = AuthServerNormal
	}
	if c.Controller == "" {
		c.Controller = ControllerNormal
	}
	c.AuthServer = strings.TrimRight(c.AuthServer, "/")
	c.Controller = strings.TrimRight(c.Controller, "/")
	controller, err := url.Parse(c.Controller)
	if err != nil || controller.Scheme != "https" || controller.Hostname() == "" {
		return c, errors.New("cas: 控制器地址必须是有效的 HTTPS URL")
	}
	if controller.Port() == "443" {
		controller.Host = strings.TrimSuffix(controller.Host, ":443")
	}
	c.Controller = controller.String()
	if c.UserAgent == "" {
		c.UserAgent = defaultUserAgent
	}
	if c.Timeout <= 0 {
		c.Timeout = 30 * time.Second
	}
	if c.Rand == nil {
		c.Rand = rand.Reader
	}
	return c, nil
}

func (c Config) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

// ClientInfo 是从 clientInfo cookie（base64 的 JSON）里解出的会话信息。
type ClientInfo struct {
	// UserID 是 32 位 hex 的 Enlink 用户 ID，**不是学号**。
	UserID string `json:"userId"`
	// Username 是学号。
	Username string `json:"username"`
	// Raw 保留全部字段，协议可能新增字段。
	Raw map[string]any `json:"-"`
}

// Session 是一次已建立的控制器会话：持有 VPN 域 Cookie 与用户身份。
type Session struct {
	// Username 是明文学号，隧道握手帧的 A 字段用它。
	Username string
	// UserID 是 32 位 hex 的 Enlink 用户 ID。
	UserID string
	// ClientInfo 是 clientInfo cookie 解出的原始信息。
	ClientInfo ClientInfo

	cfg     Config
	vpnHost string
	jar     http.CookieJar

	// authserver 与控制器使用不同的 TLS 校验策略，因此各有一组客户端；
	// CookieJar 是共享的。
	followClient   *http.Client
	noFollowClient *http.Client

	controllerClient         *http.Client
	controllerNoFollowClient *http.Client
}

// newHTTPClient 构造带 CookieJar 与注入拨号器的客户端。
func (c Config) newHTTPClient(jar http.CookieJar, insecure bool, checkRedirect func(*http.Request, []*http.Request) error) *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: insecure, //nolint:gosec // 与参考实现一致，可配置
		},
		DialContext:         c.DialContext,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &http.Client{
		Jar:           jar,
		Timeout:       c.Timeout,
		Transport:     transport,
		CheckRedirect: checkRedirect,
	}
}

func noRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// NewSession 用已知 Cookie 恢复会话（例如从本地缓存），不发起登录。
func NewSession(cfg Config, cookies map[string]string) (*Session, error) {
	cfg, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	s := &Session{
		cfg:                      cfg,
		vpnHost:                  hostOf(cfg.Controller),
		jar:                      jar,
		followClient:             cfg.newHTTPClient(jar, cfg.AuthServerInsecure, nil),
		noFollowClient:           cfg.newHTTPClient(jar, cfg.AuthServerInsecure, noRedirect),
		controllerClient:         cfg.newHTTPClient(jar, cfg.ControllerSkipVerify, nil),
		controllerNoFollowClient: cfg.newHTTPClient(jar, cfg.ControllerSkipVerify, noRedirect),
	}
	if err := s.setCookies(cookies); err != nil {
		return nil, err
	}
	if err := s.loadIdentity(); err != nil {
		s.Close()
		return nil, err
	}
	name, err := cfg.Bundle.Username()
	if err != nil || s.ClientInfo.Username != name {
		s.Close()
		return nil, errors.New("cas: 缓存会话账号与配置不一致")
	}
	s.Username = name
	return s, nil
}

// Login 走一遍完整的 Passkey 登录，返回可用会话。
func Login(ctx context.Context, cfg Config) (*Session, error) {
	cfg, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	s := &Session{
		cfg:                      cfg,
		vpnHost:                  hostOf(cfg.Controller),
		jar:                      jar,
		followClient:             cfg.newHTTPClient(jar, cfg.AuthServerInsecure, nil),
		noFollowClient:           cfg.newHTTPClient(jar, cfg.AuthServerInsecure, noRedirect),
		controllerClient:         cfg.newHTTPClient(jar, cfg.ControllerSkipVerify, nil),
		controllerNoFollowClient: cfg.newHTTPClient(jar, cfg.ControllerSkipVerify, noRedirect),
	}
	if err := s.login(ctx); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// Close 释放本会话的全部 HTTP 连接池；可重复调用。
func (s *Session) Close() {
	for _, client := range []*http.Client{s.followClient, s.noFollowClient, s.controllerClient, s.controllerNoFollowClient} {
		if client != nil {
			client.CloseIdleConnections()
		}
	}
}

// vpnCookieURL 是 VPN 域 Cookie 的作用域。
func (s *Session) vpnCookieURL() *url.URL {
	return &url.URL{Scheme: "https", Host: s.vpnHost}
}

// Cookies 返回当前 VPN 域的 Cookie 快照，可用于持久化。
func (s *Session) Cookies() map[string]string {
	out := make(map[string]string)
	for _, c := range s.jar.Cookies(s.vpnCookieURL()) {
		out[c.Name] = c.Value
	}
	return out
}

func (s *Session) setCookies(cookies map[string]string) error {
	if len(cookies) == 0 {
		return nil
	}
	jarCookies := make([]*http.Cookie, 0, len(cookies))
	for name, value := range cookies {
		jarCookies = append(jarCookies, &http.Cookie{Name: name, Value: value, Path: "/"})
	}
	s.jar.SetCookies(s.vpnCookieURL(), jarCookies)
	return nil
}

// loadIdentity 从 clientInfo cookie 解出身份信息。
func (s *Session) loadIdentity() error {
	cookies := s.Cookies()
	raw, ok := cookies["clientInfo"]
	if !ok || raw == "" {
		return fmt.Errorf("cas: 会话里没有 clientInfo cookie（拿到 %d 个）", len(cookies))
	}
	info, err := DecodeClientInfo(raw)
	if err != nil {
		return err
	}
	if info.UserID == "" {
		return errors.New("cas: clientInfo 里没有 userId")
	}
	s.ClientInfo = info
	s.UserID = info.UserID
	return nil
}

// login 执行 CAS + WebAuthn 断言流程。
func (s *Session) login(ctx context.Context) error {
	loginURL := s.loginURL(s.cfg.Controller + "/enlink/api/client/callback/cas")
	s.cfg.logf("cas: 访问登录页 %s", loginURL)

	execution, landed, err := s.openLoginPage(ctx, loginURL)
	if err != nil {
		return err
	}
	if execution == "" {
		// CAS 侧已登录，直接跳转，不必再提交断言。
		s.cfg.logf("cas: SSO 已登录，自动跳转")
		return s.finishLogin(landed)
	}

	assertion, err := s.startAssertion(ctx, loginURL, s.cfg.Bundle.UserID, s.cfg.Bundle.StartID)
	if err != nil {
		return err
	}
	credential, err := buildAssertion(s.cfg.Bundle, assertion, s.cfg.Rand)
	if err != nil {
		return err
	}
	location, err := s.submitLogin(ctx, loginURL, execution, credential, assertion.RequestID)
	if err != nil {
		return err
	}
	landed, err = s.followLanding(ctx, loginURL, location)
	if err != nil {
		return err
	}
	return s.finishLogin(landed)
}

func (s *Session) loginURL(service string) string {
	u := s.cfg.AuthServer + loginPath
	if service == "" {
		return u
	}
	return u + "?service=" + quoteService(service)
}

// openLoginPage 访问登录页，取回 execution。
// 返回的 execution 为空表示已被 SSO 直接跳转，不需要提交断言。
func (s *Session) openLoginPage(ctx context.Context, loginURL string) (execution, landed string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, loginURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", s.cfg.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "zh-CN,en;q=0.9,en-US;q=0.8")

	resp, err := s.followClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("cas: 打开登录页失败: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return "", "", fmt.Errorf("cas: 读取登录页失败: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("cas: 登录页返回 HTTP %d", resp.StatusCode)
	}
	landed = resp.Request.URL.String()
	if !strings.Contains(landed, loginPath) {
		return "", landed, nil
	}
	text := html.UnescapeString(string(body))
	if m := executionRe.FindStringSubmatch(text); len(m) > 1 {
		execution = m[1]
	} else {
		execution = defaultExecution
	}
	s.cfg.logf("cas: execution=%s", execution)
	return execution, landed, nil
}

// assertionRequest 是 startAssertion 返回的断言参数。
type assertionRequest struct {
	RequestID                         string `json:"requestId"`
	PublicKeyCredentialRequestOptions struct {
		Challenge        string `json:"challenge"`
		RPID             string `json:"rpId"`
		AllowCredentials []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	} `json:"publicKeyCredentialRequestOptions"`
}

type startAssertionResponse struct {
	Success  *bool            `json:"success"`
	Messages any              `json:"messages"`
	Result   assertionWrapper `json:"result"`
	Datas    assertionWrapper `json:"datas"`
}

type assertionWrapper struct {
	Request *assertionRequest `json:"request"`
}

func (s *Session) startAssertion(ctx context.Context, loginURL, userID, startID string) (*assertionRequest, error) {
	payload, err := json.Marshal(map[string]string{"userId": userID, "id": startID})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.cfg.AuthServer+startAssertionPath, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Origin", originOf(s.cfg.AuthServer))
	req.Header.Set("Referer", loginURL)
	req.Header.Set("User-Agent", s.cfg.UserAgent)

	resp, err := s.followClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cas: startAssertion 请求失败: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("cas: startAssertion 返回 HTTP %d: %s", resp.StatusCode, truncate(body, 200))
	}

	var parsed startAssertionResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("cas: startAssertion 响应不是 JSON: %w", err)
	}
	if parsed.Success != nil && !*parsed.Success {
		return nil, fmt.Errorf("cas: startAssertion 失败: %s", truncate(body, 200))
	}
	assertion := parsed.Result.Request
	if assertion == nil {
		assertion = parsed.Datas.Request
	}
	if assertion == nil || assertion.RequestID == "" {
		return nil, fmt.Errorf("cas: startAssertion 响应里没有有效 request: %s", truncate(body, 200))
	}
	return assertion, nil
}

type webauthnClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

type webauthnResponse struct {
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	Signature         string `json:"signature"`
}

type webauthnCredential struct {
	Type       string           `json:"type"`
	ID         string           `json:"id"`
	Response   webauthnResponse `json:"response"`
	Extensions map[string]any   `json:"clientExtensionResults"`
}

type loginSubmit struct {
	RequestID    string             `json:"requestId"`
	Credential   webauthnCredential `json:"credential"`
	SessionToken *string            `json:"sessionToken"`
}

// buildAssertion 用 bundle 里的私钥离线完成 WebAuthn 断言签名。
func buildAssertion(bundle *passkey.Bundle, assertion *assertionRequest, random io.Reader) (*webauthnCredential, error) {
	if bundle == nil || bundle.PrivateKey == nil {
		return nil, errors.New("cas: bundle 不可用")
	}
	options := assertion.PublicKeyCredentialRequestOptions
	if options.Challenge == "" {
		return nil, errors.New("cas: startAssertion 缺少 challenge")
	}
	rpID := options.RPID
	if rpID == "" {
		rpID = bundle.RPID
	}
	if rpID == "" {
		return nil, errors.New("cas: startAssertion 与 bundle 都没有 rpId")
	}

	if len(options.AllowCredentials) > 0 {
		allowed := false
		for _, c := range options.AllowCredentials {
			if c.ID == bundle.CredentialID {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, errors.New("cas: bundle 的 credentialId 不在 allowCredentials 中，该 Passkey 可能已被吊销")
		}
	}

	clientData, err := marshalCompact(webauthnClientData{
		Type:        "webauthn.get",
		Challenge:   options.Challenge,
		Origin:      WebAuthnOrigin,
		CrossOrigin: false,
	})
	if err != nil {
		return nil, err
	}

	rpHash := sha256.Sum256([]byte(rpID))
	authData := make([]byte, 0, sha256.Size+1+4)
	authData = append(authData, rpHash[:]...)
	authData = append(authData, authenticatorFlags)
	authData = append(authData, 0x00, 0x00, 0x00, 0x00) // 计数器固定 0

	clientDataHash := sha256.Sum256(clientData)
	message := make([]byte, 0, len(authData)+len(clientDataHash))
	message = append(message, authData...)
	message = append(message, clientDataHash[:]...)

	signature, err := bundle.SignES256(random, message)
	if err != nil {
		return nil, fmt.Errorf("cas: 断言签名失败: %w", err)
	}

	return &webauthnCredential{
		Type: "public-key",
		ID:   bundle.CredentialID,
		Response: webauthnResponse{
			AuthenticatorData: base64.RawURLEncoding.EncodeToString(authData),
			ClientDataJSON:    base64.RawURLEncoding.EncodeToString(clientData),
			Signature:         base64.RawURLEncoding.EncodeToString(signature),
		},
		Extensions: map[string]any{"appid": false},
	}, nil
}

// submitLogin 把断言提交到 CAS 登录表单，返回 302 的 Location。
func (s *Session) submitLogin(ctx context.Context, loginURL, execution string, credential *webauthnCredential, requestID string) (string, error) {
	responseJSON, err := marshalCompact(loginSubmit{RequestID: requestID, Credential: *credential})
	if err != nil {
		return "", err
	}

	form := url.Values{}
	form.Set("_eventId", "submit")
	// username 字段发的是 **base64url 的 userId**，不是明文学号——传明文学号会被
	// 服务端以 401 拒绝。隧道握手帧的 A 字段才用明文学号，两者别混。
	form.Set("username", s.cfg.Bundle.UserID)
	form.Set("responseJson", string(responseJSON))
	form.Set("cllt", "fidoLogin")
	form.Set("dllt", "generalLogin")
	form.Set("lt", "")
	form.Set("execution", execution)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Origin", originOf(s.cfg.AuthServer))
	req.Header.Set("Referer", loginURL)
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("User-Agent", s.cfg.UserAgent)

	resp, err := s.noFollowClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("cas: 提交断言失败: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodySize))

	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return "", fmt.Errorf("cas: 登录未返回重定向: HTTP %d（Passkey 可能已失效，请重新注册）", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	if location == "" {
		return "", errors.New("cas: 登录返回重定向但缺少 Location")
	}
	return location, nil
}

// followLanding 跟随 Location 落地，返回最终 URL。
func (s *Session) followLanding(ctx context.Context, base, location string) (string, error) {
	target, err := resolveURL(base, location)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", s.cfg.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "zh-CN,en;q=0.9,en-US;q=0.8")

	resp, err := s.followClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("cas: 跟随跳转失败: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodySize))
	return resp.Request.URL.String(), nil
}

// finishLogin 校验落地页并提取身份信息。
func (s *Session) finishLogin(landed string) error {
	if IsVPNSsoPage(landed) {
		return fmt.Errorf("%w: 被重定向到 VPN 登录页 %s", ErrSessionExpired, truncate([]byte(landed), 120))
	}
	if strings.Contains(landed, loginPath) {
		return fmt.Errorf("cas: 登录后又跳回认证页，service 可能不正确: %s", truncate([]byte(landed), 120))
	}
	cookies := s.Cookies()
	if len(cookies) == 0 {
		return errors.New("cas: 登录成功但没拿到 VPN cookies")
	}
	if err := s.loadIdentity(); err != nil {
		return err
	}
	if name, err := s.cfg.Bundle.Username(); err == nil {
		s.Username = name
	}
	if s.Username == "" {
		s.Username = s.ClientInfo.Username
	}
	s.cfg.logf("cas: 会话就绪 username=%s uid=%s cookie=%d 个", s.Username, s.UserID, len(cookies))
	return nil
}

// IsVPNSsoPage 判断 URL 是否落在 VPN 的 SSO 登录页。
func IsVPNSsoPage(rawURL string) bool {
	return strings.Contains(rawURL, VPNDomain) && strings.Contains(rawURL, VPNSsoLoginPath)
}

// DecodeClientInfo 解出 clientInfo cookie（base64 的 JSON）。
//
// 参考实现用的是标准 base64（容忍被截掉的补位 '='）；这里再容忍 url-safe 变体，
// 因为不同部署的编码方式未必一致。
func DecodeClientInfo(value string) (ClientInfo, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ClientInfo{}, errors.New("cas: clientInfo 为空")
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var raw []byte
	for _, enc := range encodings {
		if decoded, err := enc.DecodeString(trimmed); err == nil {
			raw = decoded
			break
		}
	}
	if raw == nil {
		return ClientInfo{}, errors.New("cas: clientInfo 不是合法 base64")
	}

	var info ClientInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return ClientInfo{}, fmt.Errorf("cas: clientInfo 不是合法 JSON: %w", err)
	}
	if err := json.Unmarshal(raw, &info.Raw); err != nil {
		return ClientInfo{}, fmt.Errorf("cas: clientInfo 不是合法 JSON 对象: %w", err)
	}
	return info, nil
}

// marshalCompact 序列化 JSON 且不转义 HTML 字符。
//
// clientDataJSON 的字节内容会被拿去算 SHA-256 参与签名，任何多余转义都会让
// 服务端验签失败，所以这里显式关掉 EscapeHTML 并去掉 Encoder 追加的换行。
func marshalCompact(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// quoteService 复刻 requests.utils.quote(service, safe=':/')：保留 ':' 和 '/'。
func quoteService(service string) string {
	escaped := url.QueryEscape(service)
	escaped = strings.ReplaceAll(escaped, "%3A", ":")
	escaped = strings.ReplaceAll(escaped, "%2F", "/")
	return escaped
}

func originOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return rawURL
	}
	return u.Scheme + "://" + u.Host
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	return u.Host
}

// resolveURL 以 base 为基准解析相对 Location。
func resolveURL(base, location string) (string, error) {
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	ref, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	return baseURL.ResolveReference(ref).String(), nil
}

func truncate(data []byte, n int) string {
	if len(data) <= n {
		return string(data)
	}
	return string(data[:n]) + "…"
}
