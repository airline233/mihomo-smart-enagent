package cas

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/airline233/mihomo-smart-enagent/passkey"
)

// 全部使用合成凭据：测试里绝不出现真实学号、真实 user_id 或真实 token。
const (
	testUsername  = "202500000000"
	testUID       = "0123456789abcdef0123456789abcdef"
	testToken     = "00000000-0000-0000-0000-000000000001"
	testCredID    = "test-credential-id"
	testRPID      = "authserver.nuist.edu.cn"
	testChallenge = "dGVzdC1jaGFsbGVuZ2U"
)

func newTestBundle(t *testing.T) (*passkey.Bundle, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成测试密钥失败: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("序列化私钥失败: %v", err)
	}
	bundle, err := passkey.Parse(map[string]any{
		passkey.FieldRPID:       testRPID,
		passkey.FieldCredential: testCredID,
		passkey.FieldKeyPEM:     string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		passkey.FieldUserID:     passkey.UserIDFor(testUsername),
		passkey.FieldStartID:    "anon-start-id",
	})
	if err != nil {
		t.Fatalf("构造 bundle 失败: %v", err)
	}
	return bundle, key
}

func makeClientInfo(t *testing.T) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"userId":   testUID,
		"username": testUsername,
		"nickName": "合成的测试用户",
	})
	if err != nil {
		t.Fatalf("序列化 clientInfo 失败: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// fakeEnv 是离线版的 authserver + 控制器。
type fakeEnv struct {
	authSrv *httptest.Server
	ctrlSrv *httptest.Server

	clientInfo string

	mu                sync.Mutex
	logins            int
	rulesCalls        int
	rulesWithoutToken int
	expired           bool
	signatureVerified bool
	logs              []string
}

func newFakeEnv(t *testing.T, bundle *passkey.Bundle, pub *ecdsa.PublicKey) *fakeEnv {
	t.Helper()
	env := &fakeEnv{clientInfo: makeClientInfo(t), rulesWithoutToken: 1}

	authMux := http.NewServeMux()
	authMux.HandleFunc(loginPath, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if got := r.URL.Query().Get("service"); got != VPNCASCallback {
				t.Errorf("service 参数 = %q，期望 %q", got, VPNCASCallback)
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprint(w, `<html><body><input name="execution" value="test-exec"/></body></html>`)
		case http.MethodPost:
			env.handleSubmit(t, w, r, bundle, pub)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	authMux.HandleFunc(startAssertionPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("startAssertion 请求体不是 JSON: %v", err)
		}
		if body["userId"] != bundle.UserID {
			t.Errorf("startAssertion userId = %q，期望 %q", body["userId"], bundle.UserID)
		}
		if body["id"] != bundle.StartID {
			t.Errorf("startAssertion id = %q，期望 %q", body["id"], bundle.StartID)
		}
		if got := r.Header.Get("X-Requested-With"); got != "XMLHttpRequest" {
			t.Errorf("startAssertion 缺少 X-Requested-With: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"result": map[string]any{
				"request": map[string]any{
					"requestId": "req-1",
					"publicKeyCredentialRequestOptions": map[string]any{
						"challenge":        testChallenge,
						"rpId":             testRPID,
						"allowCredentials": []map[string]string{{"id": bundle.CredentialID}},
					},
				},
			},
		})
	})
	env.authSrv = httptest.NewServer(authMux)

	ctrlMux := http.NewServeMux()
	ctrlMux.HandleFunc("/enlink/api/client/callback/cas", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "ENSSESSIONID", Value: "test-session", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "clientInfo", Value: env.clientInfo, Path: "/"})
		w.WriteHeader(http.StatusOK)
	})
	ctrlMux.HandleFunc(terminalRulesPath, func(w http.ResponseWriter, r *http.Request) {
		env.mu.Lock()
		env.rulesCalls++
		calls := env.rulesCalls
		expired := env.expired
		withoutToken := env.rulesWithoutToken
		env.mu.Unlock()

		if expired {
			http.Redirect(w, r, "https://"+VPNDomain+VPNSsoLoginPath, http.StatusFound)
			return
		}
		data := map[string]any{
			"spa_port":   float64(62201),
			"spa_status": false,
			"admin_port": float64(20203),
		}
		if calls > withoutToken {
			data["token"] = testToken
			data["server"] = "client.vpn.nuist.edu.cn:443||202.195.225.220:443||443"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"code": "200", "data": data})
	})
	env.ctrlSrv = httptest.NewServer(ctrlMux)
	return env
}

// handleSubmit 像真服务端那样校验断言：重算 clientDataJSON 的 SHA-256、
// 检查 authenticatorData 布局，并用公钥验证 DER 签名。
func (e *fakeEnv) handleSubmit(t *testing.T, w http.ResponseWriter, r *http.Request, bundle *passkey.Bundle, pub *ecdsa.PublicKey) {
	t.Helper()
	if err := r.ParseForm(); err != nil {
		t.Errorf("解析表单失败: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if got := r.Form.Get("_eventId"); got != "submit" {
		t.Errorf("_eventId = %q", got)
	}
	if got := r.Form.Get("cllt"); got != "fidoLogin" {
		t.Errorf("cllt = %q", got)
	}
	if got := r.Form.Get("dllt"); got != "generalLogin" {
		t.Errorf("dllt = %q", got)
	}
	if got := r.Form.Get("execution"); got != "test-exec" {
		t.Errorf("execution = %q，期望从登录页抓到的 test-exec", got)
	}
	// username 必须是 base64url 的 userId，不是明文学号。
	if got := r.Form.Get("username"); got != bundle.UserID {
		t.Errorf("username = %q，期望 base64url 的 userId %q", got, bundle.UserID)
	}

	var submit struct {
		RequestID  string `json:"requestId"`
		Credential struct {
			Type     string `json:"type"`
			ID       string `json:"id"`
			Response struct {
				AuthenticatorData string `json:"authenticatorData"`
				ClientDataJSON    string `json:"clientDataJSON"`
				Signature         string `json:"signature"`
			} `json:"response"`
		} `json:"credential"`
		SessionToken *string `json:"sessionToken"`
	}
	if err := json.Unmarshal([]byte(r.Form.Get("responseJson")), &submit); err != nil {
		t.Errorf("responseJson 不是合法 JSON: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if submit.RequestID != "req-1" {
		t.Errorf("requestId = %q", submit.RequestID)
	}
	if submit.Credential.ID != bundle.CredentialID {
		t.Errorf("credential.id = %q", submit.Credential.ID)
	}
	if submit.SessionToken != nil {
		t.Errorf("sessionToken 应为 null，实际 %q", *submit.SessionToken)
	}

	authData, err := base64.RawURLEncoding.DecodeString(submit.Credential.Response.AuthenticatorData)
	if err != nil {
		t.Errorf("authenticatorData 不是 base64url: %v", err)
		return
	}
	clientDataJSON, err := base64.RawURLEncoding.DecodeString(submit.Credential.Response.ClientDataJSON)
	if err != nil {
		t.Errorf("clientDataJSON 不是 base64url: %v", err)
		return
	}
	signature, err := base64.RawURLEncoding.DecodeString(submit.Credential.Response.Signature)
	if err != nil {
		t.Errorf("signature 不是 base64url: %v", err)
		return
	}

	// authenticatorData = SHA256(rpId) ‖ flags(0x05) ‖ counter(0)
	if len(authData) != 37 {
		t.Errorf("authenticatorData 长度 = %d，期望 37", len(authData))
		return
	}
	rpHash := sha256.Sum256([]byte(testRPID))
	if !bytes.Equal(authData[:32], rpHash[:]) {
		t.Errorf("authenticatorData 前 32 字节不是 SHA256(rpId)")
	}
	if authData[32] != authenticatorFlags {
		t.Errorf("flags = %#02x，期望 %#02x（UP|UV）", authData[32], authenticatorFlags)
	}
	if !bytes.Equal(authData[33:], []byte{0, 0, 0, 0}) {
		t.Errorf("计数器应为 0，实际 % x", authData[33:])
	}

	// clientDataJSON 的 origin 必须是真实 authserver，即使本次请求打到了假服务端。
	var clientData webauthnClientData
	if err := json.Unmarshal(clientDataJSON, &clientData); err != nil {
		t.Errorf("clientDataJSON 不是合法 JSON: %v", err)
		return
	}
	if clientData.Origin != WebAuthnOrigin {
		t.Errorf("clientDataJSON.origin = %q，期望 %q", clientData.Origin, WebAuthnOrigin)
	}
	if clientData.Type != "webauthn.get" {
		t.Errorf("clientDataJSON.type = %q", clientData.Type)
	}
	if clientData.Challenge != testChallenge {
		t.Errorf("clientDataJSON.challenge = %q", clientData.Challenge)
	}
	if clientData.CrossOrigin {
		t.Error("crossOrigin 应为 false")
	}

	// 真验签：签名是 DER 编码，摘要 = SHA256(authenticatorData ‖ SHA256(clientDataJSON))
	cdHash := sha256.Sum256(clientDataJSON)
	message := make([]byte, 0, len(authData)+len(cdHash))
	message = append(message, authData...)
	message = append(message, cdHash[:]...)
	digest := sha256.Sum256(message)
	if len(signature) == 0 || signature[0] != 0x30 {
		t.Errorf("签名不是 DER 编码（首字节 %#02x）", signature[0])
	}
	if !ecdsa.VerifyASN1(pub, digest[:], signature) {
		t.Errorf("断言签名验证失败")
		return
	}

	e.mu.Lock()
	e.logins++
	e.signatureVerified = true
	e.mu.Unlock()

	http.Redirect(w, r, e.ctrlSrv.URL+"/enlink/api/client/callback/cas", http.StatusFound)
}

func (e *fakeEnv) logf(format string, args ...any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.logs = append(e.logs, fmt.Sprintf(format, args...))
}

func (e *fakeEnv) loginCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.logins
}

func (e *fakeEnv) close() {
	e.authSrv.Close()
	e.ctrlSrv.Close()
}

func (e *fakeEnv) config(bundle *passkey.Bundle) Config {
	return Config{
		Bundle:     bundle,
		AuthServer: e.authSrv.URL,
		Controller: e.ctrlSrv.URL,
		Logf:       e.logf,
	}
}

func TestLoginAndFetchRules(t *testing.T) {
	bundle, key := newTestBundle(t)
	env := newFakeEnv(t, bundle, &key.PublicKey)
	defer env.close()

	ctx := context.Background()
	session, err := Login(ctx, env.config(bundle))
	if err != nil {
		t.Fatalf("Login 失败: %v（日志: %v）", err, env.logs)
	}
	if !env.signatureVerified {
		t.Fatal("假服务端没有收到可验证的断言签名")
	}
	if session.UserID != testUID {
		t.Errorf("UserID = %q，期望 %q", session.UserID, testUID)
	}
	if session.Username != testUsername {
		t.Errorf("Username = %q，期望 %q", session.Username, testUsername)
	}
	if session.ClientInfo.Username != testUsername {
		t.Errorf("ClientInfo.Username = %q", session.ClientInfo.Username)
	}
	cookies := session.Cookies()
	if _, ok := cookies["ENSSESSIONID"]; !ok {
		t.Errorf("会话缺少 ENSSESSIONID，实际有 %v", cookies)
	}

	// 首次 rules 调用故意不返回 token，用来验证重试。
	rules, err := session.FetchRules(ctx, 3, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("FetchRules 失败: %v", err)
	}
	if rules.Token != testToken {
		t.Errorf("Token = %q，期望 %q", rules.Token, testToken)
	}
	if rules.SPAPort != 62201 {
		t.Errorf("SPAPort = %d，期望 62201", rules.SPAPort)
	}
	if rules.SPAStatus {
		t.Error("SPAStatus 应为 false")
	}
	if len(rules.Servers) != 3 {
		t.Fatalf("网关候选数 = %d，期望 3（%v）", len(rules.Servers), rules.Servers)
	}
	if got := rules.Servers[0].String(); got != "client.vpn.nuist.edu.cn:443" {
		t.Errorf("Servers[0] = %s", got)
	}
	if got := rules.Servers[1].String(); got != "202.195.225.220:443" {
		t.Errorf("Servers[1] = %s", got)
	}
	// 第三个是不带 host 的纯端口，沿用上一个 host。
	if got := rules.Servers[2].String(); got != "202.195.225.220:443" {
		t.Errorf("Servers[2] = %s", got)
	}
	if got := rules.SPAHost(); got != "202.195.225.220" {
		t.Errorf("SPAHost = %s，期望 202.195.225.220", got)
	}
}

func TestFetchRulesReportsSessionExpired(t *testing.T) {
	bundle, key := newTestBundle(t)
	env := newFakeEnv(t, bundle, &key.PublicKey)
	defer env.close()

	session, err := Login(context.Background(), env.config(bundle))
	if err != nil {
		t.Fatalf("Login 失败: %v", err)
	}
	env.mu.Lock()
	env.expired = true
	env.mu.Unlock()

	_, err = session.FetchRules(context.Background(), 3, 5*time.Millisecond)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("err = %v，期望 ErrSessionExpired", err)
	}
}

func TestManagerCachesTokenAndRelogins(t *testing.T) {
	bundle, key := newTestBundle(t)
	env := newFakeEnv(t, bundle, &key.PublicKey)
	defer env.close()

	opts := ManagerOptions{
		Config:        env.config(bundle),
		RulesInterval: 5 * time.Millisecond,
		MinLoginGap:   time.Millisecond,
		Cache:         FileCookieCache{Path: t.TempDir() + "/cookies.json"},
	}
	mgr, err := NewManager(opts)
	if err != nil {
		t.Fatalf("NewManager 失败: %v", err)
	}
	defer mgr.Close()

	ctx := context.Background()
	first, err := mgr.EnsureRules(ctx, false)
	if err != nil {
		t.Fatalf("EnsureRules 失败: %v", err)
	}
	second, err := mgr.EnsureRules(ctx, false)
	if err != nil {
		t.Fatalf("EnsureRules(第二次) 失败: %v", err)
	}
	if first.Token != second.Token {
		t.Errorf("token 不一致: %q vs %q", first.Token, second.Token)
	}
	if got := env.loginCount(); got != 1 {
		t.Fatalf("登录次数 = %d，期望 1（token 应被缓存复用）", got)
	}
	if mgr.Username() != testUsername {
		t.Errorf("Username = %q", mgr.Username())
	}

	// 会话失效后应自动重新登录。
	mgr.Invalidate(true)
	if _, err := mgr.EnsureRules(ctx, false); err != nil {
		t.Fatalf("失效后 EnsureRules 失败: %v", err)
	}
	if got := env.loginCount(); got != 2 {
		t.Fatalf("登录次数 = %d，期望 2（失效后应重登）", got)
	}
}

func TestManagerRestoresFromCookieCache(t *testing.T) {
	bundle, key := newTestBundle(t)
	env := newFakeEnv(t, bundle, &key.PublicKey)
	defer env.close()

	cache := FileCookieCache{Path: t.TempDir() + "/cookies.json"}
	opts := ManagerOptions{
		Config:        env.config(bundle),
		RulesInterval: 5 * time.Millisecond,
		MinLoginGap:   time.Millisecond,
		Cache:         cache,
	}

	first, err := NewManager(opts)
	if err != nil {
		t.Fatalf("NewManager 失败: %v", err)
	}
	if _, err := first.EnsureRules(context.Background(), false); err != nil {
		t.Fatalf("首次 EnsureRules 失败: %v", err)
	}
	if got := env.loginCount(); got != 1 {
		t.Fatalf("登录次数 = %d，期望 1", got)
	}
	first.Close()

	// 第二个 Manager 应该直接用磁盘上的 Cookie，不重新登录。
	second, err := NewManager(opts)
	if err != nil {
		t.Fatalf("NewManager(第二次) 失败: %v", err)
	}
	defer second.Close()
	rules, err := second.EnsureRules(context.Background(), false)
	if err != nil {
		t.Fatalf("恢复会话后 EnsureRules 失败: %v", err)
	}
	if rules.Token != testToken {
		t.Errorf("Token = %q", rules.Token)
	}
	if got := env.loginCount(); got != 1 {
		t.Fatalf("登录次数 = %d，期望仍为 1（应复用缓存 Cookie）", got)
	}
}

func TestDecodeClientInfo(t *testing.T) {
	raw, err := json.Marshal(map[string]any{"userId": testUID, "username": testUsername})
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	variants := map[string]string{
		"标准 base64":    base64.StdEncoding.EncodeToString(raw),
		"无补位":          base64.RawStdEncoding.EncodeToString(raw),
		"url-safe":     base64.URLEncoding.EncodeToString(raw),
		"url-safe 无补位": base64.RawURLEncoding.EncodeToString(raw),
	}
	for name, value := range variants {
		t.Run(name, func(t *testing.T) {
			info, err := DecodeClientInfo(value)
			if err != nil {
				t.Fatalf("DecodeClientInfo 失败: %v", err)
			}
			if info.UserID != testUID {
				t.Errorf("UserID = %q，期望 %q", info.UserID, testUID)
			}
			if info.Username != testUsername {
				t.Errorf("Username = %q", info.Username)
			}
			if info.Raw["username"] != testUsername {
				t.Errorf("Raw 未保留原始字段: %v", info.Raw)
			}
		})
	}

	if _, err := DecodeClientInfo(""); err == nil {
		t.Error("空值应报错")
	}
	if _, err := DecodeClientInfo("!!!not-base64!!!"); err == nil {
		t.Error("非法 base64 应报错")
	}
	if _, err := DecodeClientInfo(base64.StdEncoding.EncodeToString([]byte("not json"))); err == nil {
		t.Error("非 JSON 应报错")
	}
}

func TestParseServers(t *testing.T) {
	got := parseServers("client.vpn.nuist.edu.cn:443||202.195.225.220:443||443")
	if len(got) != 3 {
		t.Fatalf("解析出 %d 项: %v", len(got), got)
	}
	if got[0] != (Endpoint{Host: "client.vpn.nuist.edu.cn", Port: 443}) {
		t.Errorf("got[0] = %+v", got[0])
	}
	if got[2] != (Endpoint{Host: "202.195.225.220", Port: 443}) {
		t.Errorf("got[2] = %+v（纯端口应沿用上一个 host）", got[2])
	}
	if len(parseServers("")) != 0 {
		t.Error("空串应解析出 0 项")
	}
	if len(parseServers("||  ||")) != 0 {
		t.Error("空白项应被跳过")
	}
}

func TestParseRulesRequiresToken(t *testing.T) {
	if _, err := parseRules(map[string]any{"server": "a:443"}); err == nil {
		t.Error("缺少 token 应报错")
	}
	if _, err := parseRules(map[string]any{"token": "t"}); err == nil {
		t.Error("缺少 server 应报错")
	}
	rules, err := parseRules(map[string]any{"token": "t", "server": "a:443"})
	if err != nil {
		t.Fatalf("parseRules 失败: %v", err)
	}
	if rules.Token != "t" || len(rules.Servers) != 1 {
		t.Errorf("解析结果异常: %+v", rules)
	}
}

func TestQuoteServiceKeepsSchemeAndSlash(t *testing.T) {
	got := quoteService(VPNCASCallback)
	if !strings.HasPrefix(got, "https://") {
		t.Errorf("quoteService 应保留 ':' 和 '/'，实际 %q", got)
	}
	if strings.Contains(got, "%3A") || strings.Contains(got, "%2F") {
		t.Errorf("quoteService 不应转义 ':' 或 '/'，实际 %q", got)
	}
	if got != VPNCASCallback {
		t.Errorf("quoteService = %q，期望原样 %q", got, VPNCASCallback)
	}
}

func TestIsVPNSsoPage(t *testing.T) {
	if !IsVPNSsoPage("https://" + VPNDomain + VPNSsoLoginPath + "?x=1") {
		t.Error("应识别为 SSO 登录页")
	}
	if IsVPNSsoPage("https://" + VPNDomain + "/enlink/api/client/callback/cas") {
		t.Error("CAS 回调不应被识别为登录页")
	}
	if IsVPNSsoPage("https://other.example.com" + VPNSsoLoginPath) {
		t.Error("其它域的登录页不应被识别")
	}
}

func TestFileCookieCacheRoundTrip(t *testing.T) {
	path := t.TempDir() + "/nested/cookies.json"
	cache := FileCookieCache{Path: path}

	got, err := cache.Load()
	if err != nil {
		t.Fatalf("Load 空缓存报错: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("空缓存应返回空 map，实际 %v", got)
	}

	want := map[string]string{"ENSSESSIONID": "abc", "clientInfo": "xyz"}
	if err := cache.Store(want); err != nil {
		t.Fatalf("Store 失败: %v", err)
	}
	got, err = cache.Load()
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("cookie %s = %q，期望 %q", k, got[k], v)
		}
	}
}

func TestNewSessionRequiresClientInfo(t *testing.T) {
	bundle, _ := newTestBundle(t)
	cfg := Config{Bundle: bundle, AuthServer: AuthServerNormal, Controller: ControllerNormal}
	if _, err := NewSession(cfg, map[string]string{"ENSSESSIONID": "x"}); err == nil {
		t.Fatal("缺少 clientInfo 应报错")
	}
	info := makeClientInfo(t)
	session, err := NewSession(cfg, map[string]string{"clientInfo": info})
	if err != nil {
		t.Fatalf("NewSession 失败: %v", err)
	}
	if session.UserID != testUID {
		t.Errorf("UserID = %q", session.UserID)
	}
	if session.Username != testUsername {
		t.Errorf("Username = %q", session.Username)
	}
}

func TestResolveURL(t *testing.T) {
	got, err := resolveURL("https://a.example.com/authserver/login?service=x", "/enlink/api/client/callback/cas")
	if err != nil {
		t.Fatalf("resolveURL 失败: %v", err)
	}
	if got != "https://a.example.com/enlink/api/client/callback/cas" {
		t.Errorf("resolveURL = %q", got)
	}
}

func TestHostOfAndOriginOf(t *testing.T) {
	if got := hostOf("https://client.vpn.nuist.edu.cn/enlink/x"); got != "client.vpn.nuist.edu.cn" {
		t.Errorf("hostOf = %q", got)
	}
	if got := originOf("https://authserver.nuist.edu.cn/authserver/login"); got != "https://authserver.nuist.edu.cn" {
		t.Errorf("originOf = %q", got)
	}
}

// 确保 url.Values 的表单编码与服务端解析一致（含空值的 lt 字段）。
func TestSubmitFormEncoding(t *testing.T) {
	form := url.Values{}
	form.Set("lt", "")
	if got := form.Encode(); got != "lt=" {
		t.Errorf("空值编码 = %q，期望 lt=", got)
	}
}
