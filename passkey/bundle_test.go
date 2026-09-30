package passkey

import (
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
	"strings"
	"testing"
)

// 测试数据一律用合成值。
//
// 绝不把真实学号、真实 credentialId、真实主机名/MAC，或任何来自真实
// passkey bundle 的字段写进仓库——即使它已经出现在本仓库的文档里。
// 测试要验的是"字段能否被正确解析"，与哪个账号无关。
const (
	syntheticUsername = "202500000000"
	syntheticCredID   = "test-credential-id"
	syntheticCredIDB  = "test-credential-id-other"
)

// webauthnOrigin 是 clientDataJSON 里必须使用的真实 authserver origin：
// 即使经 webvpn 代理，填代理域名也会被服务端以 401 拒绝。
const webauthnOrigin = "https://authserver.nuist.edu.cn"

func genKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("生成测试密钥失败: %v", err)
	}
	return key
}

func pemText(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("序列化 PKCS#8 失败: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// jwkOf 把测试密钥导成 JWK；withXY=false 时不带 x/y，覆盖两种输入形态。
func jwkOf(key *ecdsa.PrivateKey, withXY bool) map[string]any {
	jwk := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"d":   b64(key.D.FillBytes(make([]byte, 32))),
	}
	if withXY {
		jwk["x"] = b64(key.X.FillBytes(make([]byte, 32)))
		jwk["y"] = b64(key.Y.FillBytes(make([]byte, 32)))
	}
	return jwk
}

// roundTripJSON 让字段走一遍 JSON 编解码，得到与配置解码器同形的
// map[string]any（嵌套对象也是 map[string]any、数字是 float64）。
// 只构造 map 而不做这一步，就测不出类型断言上的坑。
func roundTripJSON(t *testing.T, fields map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}
	return out
}

// webAuthnMessage 按 WebAuthn 的断言布局拼出待签消息：
// authenticatorData ‖ SHA256(clientDataJSON)
// authenticatorData = SHA256(rpId) ‖ flags(0x05 = UP|UV) ‖ counter(0)
func webAuthnMessage(rpID string) (message, clientDataJSON []byte) {
	rpHash := sha256.Sum256([]byte(rpID))
	authData := make([]byte, 0, 37)
	authData = append(authData, rpHash[:]...)
	authData = append(authData, 0x05)
	authData = append(authData, 0x00, 0x00, 0x00, 0x00)

	clientDataJSON = []byte(`{"type":"webauthn.get","challenge":"challenge-b64url","origin":"` +
		webauthnOrigin + `","crossOrigin":false}`)
	cdHash := sha256.Sum256(clientDataJSON)

	message = make([]byte, 0, len(authData)+len(cdHash))
	message = append(message, authData...)
	message = append(message, cdHash[:]...)
	return message, clientDataJSON
}

func inlinePEMBundle(t *testing.T, key *ecdsa.PrivateKey) map[string]any {
	t.Helper()
	return roundTripJSON(t, map[string]any{
		FieldRPID:       "authserver.nuist.edu.cn",
		FieldCredential: syntheticCredID,
		FieldKeyPEM:     pemText(t, key),
		FieldUserID:     UserIDFor(syntheticUsername),
		FieldStartID:    "anon-start-id",
	})
}

// TestParseInlineBundle 覆盖配置里的内联形态，并验证签名能被公钥验通。
func TestParseInlineBundle(t *testing.T) {
	key := genKey(t, elliptic.P256())
	b, err := Parse(inlinePEMBundle(t, key))
	if err != nil {
		t.Fatalf("Parse 失败: %v", err)
	}
	if b.RPID != "authserver.nuist.edu.cn" {
		t.Errorf("RPID = %q", b.RPID)
	}
	if b.CredentialID != syntheticCredID {
		t.Errorf("CredentialID = %q", b.CredentialID)
	}
	if b.StartID != "anon-start-id" {
		t.Errorf("StartID = %q", b.StartID)
	}
	username, err := b.Username()
	if err != nil {
		t.Fatalf("Username 失败: %v", err)
	}
	if username != syntheticUsername {
		t.Errorf("Username = %q，期望 %q", username, syntheticUsername)
	}

	message, clientDataJSON := webAuthnMessage(b.RPID)
	if !strings.Contains(string(clientDataJSON), webauthnOrigin) {
		t.Fatalf("clientDataJSON 缺少 origin: %s", clientDataJSON)
	}
	sig, err := b.SignES256(rand.Reader, message)
	if err != nil {
		t.Fatalf("SignES256 失败: %v", err)
	}
	if len(sig) == 0 || sig[0] != 0x30 {
		t.Fatalf("签名不是 DER 编码（首字节 %#x）", sig[0])
	}
	digest := sha256.Sum256(message)
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig) {
		t.Fatal("签名验不过：待签消息布局或 DER 编码有问题")
	}
}

// TestParseJWKBundle 覆盖 privateKeyJwk 的两种形态。
func TestParseJWKBundle(t *testing.T) {
	key := genKey(t, elliptic.P256())
	for _, withXY := range []bool{true, false} {
		name := "无 x/y"
		if withXY {
			name = "带 x/y"
		}
		t.Run(name, func(t *testing.T) {
			fields := roundTripJSON(t, map[string]any{
				FieldRPID:       "authserver.nuist.edu.cn",
				FieldCredential: syntheticCredID,
				FieldKeyJWK:     jwkOf(key, withXY),
				FieldUserID:     UserIDFor(syntheticUsername),
				FieldStartID:    "anon-start-id",
			})
			b, err := Parse(fields)
			if err != nil {
				t.Fatalf("Parse 失败: %v", err)
			}
			if b.PrivateKey.D.Cmp(key.D) != 0 {
				t.Fatal("JWK 还原出的私钥与原始私钥不一致")
			}
			if b.PrivateKey.X.Cmp(key.X) != 0 || b.PrivateKey.Y.Cmp(key.Y) != 0 {
				t.Fatal("JWK 还原出的公钥与原始公钥不一致")
			}
		})
	}
}

// TestParseFromLiteralPasskeyJSON 直接用 passkey.local.json 的原文形态，
// 证明字段名可以整段粘贴、无需改名。
func TestParseFromLiteralPasskeyJSON(t *testing.T) {
	key := genKey(t, elliptic.P256())
	raw := fmt.Sprintf(`{
  "rpId": "authserver.nuist.edu.cn",
  "credentialId": %q,
  "privateKeyPkcs8Pem": %q,
  "userId": %q,
  "anonbiometricsd": "anon-start-id"
}`, syntheticCredIDB, pemText(t, key), UserIDFor(syntheticUsername))

	var fields map[string]any
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		t.Fatalf("解析 JSON 失败: %v", err)
	}
	b, err := Parse(fields)
	if err != nil {
		t.Fatalf("Parse 失败: %v", err)
	}
	if b.CredentialID != syntheticCredIDB {
		t.Errorf("CredentialID = %q，期望 %q", b.CredentialID, syntheticCredIDB)
	}
	if username, _ := b.Username(); username != syntheticUsername {
		t.Errorf("Username = %q", username)
	}
}

func TestParseMissingFields(t *testing.T) {
	_, err := Parse(map[string]any{FieldRPID: "authserver.nuist.edu.cn"})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v，期望 ErrInvalid", err)
	}
	for _, want := range []string{FieldCredential, FieldUserID, FieldStartID} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误信息未提到 %s: %v", want, err)
		}
	}
}

func TestParseMissingKey(t *testing.T) {
	_, err := Parse(map[string]any{
		FieldRPID:       "authserver.nuist.edu.cn",
		FieldCredential: syntheticCredID,
		FieldUserID:     UserIDFor(syntheticUsername),
		FieldStartID:    "anon-start-id",
	})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v，期望 ErrInvalid", err)
	}
	for _, want := range []string{FieldKeyPEM, FieldKeyJWK} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误信息未提到 %s: %v", want, err)
		}
	}
}

// TestParseRejectsNonStringField 覆盖粘贴错误：把学号写成 JSON 数字。
func TestParseRejectsNonStringField(t *testing.T) {
	fields := inlinePEMBundle(t, genKey(t, elliptic.P256()))
	fields[FieldUserID] = float64(202500000000)
	_, err := Parse(fields)
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), FieldUserID) {
		t.Fatalf("err = %v，期望针对 %s 的 ErrInvalid", err, FieldUserID)
	}
}

func TestParseRejectsNonP256(t *testing.T) {
	key := genKey(t, elliptic.P384())
	fields := inlinePEMBundle(t, genKey(t, elliptic.P256()))
	fields[FieldKeyPEM] = pemText(t, key)
	_, err := Parse(fields)
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "P-256") {
		t.Fatalf("err = %v，期望提示曲线必须是 P-256", err)
	}
}

func TestParseRejectsBrokenPEM(t *testing.T) {
	fields := inlinePEMBundle(t, genKey(t, elliptic.P256()))
	fields[FieldKeyPEM] = "not a pem at all"
	if _, err := Parse(fields); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v，期望 ErrInvalid", err)
	}
}

// TestParseRejectsTamperedJWK 覆盖粘贴截断/损坏导致 x/y 与 d 不一致。
func TestParseRejectsTamperedJWK(t *testing.T) {
	key := genKey(t, elliptic.P256())
	jwk := jwkOf(key, true)
	jwk["x"] = b64(genKey(t, elliptic.P256()).X.FillBytes(make([]byte, 32)))
	fields := roundTripJSON(t, map[string]any{
		FieldRPID:       "authserver.nuist.edu.cn",
		FieldCredential: syntheticCredID,
		FieldKeyJWK:     jwk,
		FieldUserID:     UserIDFor(syntheticUsername),
		FieldStartID:    "anon-start-id",
	})
	_, err := Parse(fields)
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "不一致") {
		t.Fatalf("err = %v，期望提示 x/y 与 d 不一致", err)
	}
}

func TestParseRejectsBadJWKCurve(t *testing.T) {
	key := genKey(t, elliptic.P256())
	jwk := jwkOf(key, false)
	jwk["crv"] = "P-384"
	fields := roundTripJSON(t, map[string]any{
		FieldRPID:       "authserver.nuist.edu.cn",
		FieldCredential: syntheticCredID,
		FieldKeyJWK:     jwk,
		FieldUserID:     UserIDFor(syntheticUsername),
		FieldStartID:    "anon-start-id",
	})
	if _, err := Parse(fields); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v，期望 ErrInvalid", err)
	}
}

// TestParseToleratesMapAnyAny 覆盖 map[any]any 形态的嵌套对象。
func TestParseToleratesMapAnyAny(t *testing.T) {
	key := genKey(t, elliptic.P256())
	jwk := map[any]any{}
	for k, v := range jwkOf(key, false) {
		jwk[k] = v
	}
	b, err := Parse(map[string]any{
		FieldRPID:       "authserver.nuist.edu.cn",
		FieldCredential: syntheticCredID,
		FieldKeyJWK:     jwk,
		FieldUserID:     UserIDFor(syntheticUsername),
		FieldStartID:    "anon-start-id",
	})
	if err != nil {
		t.Fatalf("Parse 失败: %v", err)
	}
	if b.PrivateKey.D.Cmp(key.D) != 0 {
		t.Fatal("map[any]any 形态下私钥还原错误")
	}
}

func TestParseEmptyFields(t *testing.T) {
	if _, err := Parse(nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v，期望 ErrInvalid", err)
	}
	if _, err := Parse(map[string]any{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v，期望 ErrInvalid", err)
	}
}

func TestSignES256WithoutKey(t *testing.T) {
	b := &Bundle{}
	if _, err := b.SignES256(rand.Reader, []byte("x")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v，期望 ErrInvalid", err)
	}
}

func TestUserIDForRoundTrip(t *testing.T) {
	for _, username := range []string{syntheticUsername, "x", "合成的中文占位学号"} {
		b := &Bundle{UserID: UserIDFor(username)}
		got, err := b.Username()
		if err != nil {
			t.Fatalf("Username(%q) 失败: %v", username, err)
		}
		if got != username {
			t.Errorf("Username() = %q，期望 %q", got, username)
		}
	}
}

func TestDecodeBase64URL(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"MjAyNTAwMDAwMDAw", syntheticUsername, false},
		{"MjAyNTAwMDAwMDAw==", syntheticUsername, false},
		{"  dXNlcg==  ", "user", false},
		{"", "", false},
		{"!!!not-base64!!!", "", true},
	}
	for _, c := range cases {
		got, err := DecodeBase64URL(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("DecodeBase64URL(%q) 期望报错，实际得到 %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("DecodeBase64URL(%q) 报错: %v", c.in, err)
			continue
		}
		if string(got) != c.want {
			t.Errorf("DecodeBase64URL(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}
}
