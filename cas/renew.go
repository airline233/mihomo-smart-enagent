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
	"strings"
)

// ErrRenewUnsupported 表示该部署不支持会话维护接口，应停止周期调用。
var ErrRenewUnsupported = errors.New("cas: 控制器不支持 updateUserSession")

// SessionUpdate 是原客户端 sendVirIP2Controller 提交的已知字段。
// 接口会更新虚拟 IP 登记；是否同时延长服务器 TTL 取决于部署策略。
type SessionUpdate struct {
	VirtualIP   string `json:"virtualIp"`
	VirtualIPv6 string `json:"virtualIpV6"`
	Gateway     string `json:"gateway"`
}

// Renew 更新当前控制器会话，不登录、不刷新隧道 token。
// 只有明确的会话失效响应才清除凭据；网络/业务错误保留现有会话。
func (m *Manager) Renew(ctx context.Context, update SessionUpdate) error {
	ctx, cancel := m.operationContext(ctx)
	defer cancel()
	if err := m.mu.LockContext(ctx); err != nil {
		return err
	}
	defer m.mu.Unlock()
	if m.ctx.Err() != nil {
		return net.ErrClosed
	}
	if m.session == nil {
		return ErrSessionExpired
	}
	err := m.session.updateUserSession(ctx, update)
	if errors.Is(err, ErrSessionExpired) {
		m.discardSessionLocked()
	} else if err == nil {
		m.storeCache(m.session.Cookies())
	}
	return err
}

func (s *Session) updateUserSession(ctx context.Context, update SessionUpdate) error {
	if net.ParseIP(update.VirtualIP).To4() == nil || update.Gateway == "" {
		return errors.New("cas: 会话维护缺少有效虚拟 IPv4 或网关")
	}
	sid := s.Cookies()["ENSSESSIONID"]
	if sid == "" {
		return ErrSessionExpired
	}
	payload, err := json.Marshal(struct {
		SessionID string `json:"sessionId"`
		SessionUpdate
	}{sid, update})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		s.cfg.Controller+"/enlink/api/client/user/updateUserSession", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", s.cfg.UserAgent)
	resp, err := s.controllerNoFollowClient.Do(req)
	if err != nil {
		return fmt.Errorf("cas: 会话维护请求失败: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized ||
		(resp.StatusCode >= 300 && resp.StatusCode < 400 && strings.Contains(resp.Header.Get("Location"), VPNSsoLoginPath)) ||
		bytes.Contains(body, []byte(VPNSsoLoginPath)) {
		return ErrSessionExpired
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented {
		return ErrRenewUnsupported
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cas: 会话维护返回 HTTP %d", resp.StatusCode)
	}
	var result struct {
		Code     json.RawMessage `json:"code"`
		Messages string          `json:"messages"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("cas: 会话维护响应不是 JSON: %w", err)
	}
	code := strings.Trim(string(result.Code), "\"")
	if code == "401" {
		return ErrSessionExpired
	}
	if code != "200" {
		return fmt.Errorf("cas: 会话维护失败 code=%s messages=%s", code, result.Messages)
	}
	return nil
}
