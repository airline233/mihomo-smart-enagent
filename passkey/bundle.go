// Package passkey 解析软件 Passkey bundle，并用其中的 P-256 私钥离线完成
// WebAuthn 断言签名。
//
// 字段名与 authserver_login 导出的 passkey.local.json 完全一致，可以整段内联到
// mihomo 配置的 passkey 字段里（不做任何改名）：
//
//	passkey:
//	  rpId: authserver.nuist.edu.cn
//	  credentialId: "..."
//	  privateKeyPkcs8Pem: |
//	    -----BEGIN PRIVATE KEY-----
//	    ...
//	    -----END PRIVATE KEY-----
//	  userId: MjAyNTYzMTYwMDIx
//	  anonbiometricsd: "..."
//
// 因此本包对字段名**不做大小写或连字符归一化**：mihomo 的 structure 解码器会把
// rpId 压成 rpid、privateKeyPkcs8Pem 压成 privatekeypkcs8pem，在配置层把这个嵌套
// 对象声明成 map[string]any 就是为了绕开那条规则，保证粘贴即用。
//
// 只用标准库：解析和签名都不依赖第三方包。
package passkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// bundle 字段名，与 passkey.local.json 一字不差。
const (
	FieldRPID       = "rpId"
	FieldCredential = "credentialId"
	FieldKeyPEM     = "privateKeyPkcs8Pem"
	FieldKeyJWK     = "privateKeyJwk"
	FieldUserID     = "userId"
	FieldStartID    = "anonbiometricsd"
)

// ErrInvalid 表示 bundle 本身不可用（字段缺失、密钥类型不对、粘贴损坏等）。
// 与"服务端拒绝了这次断言"区分开，便于上层决定是重登还是报配置错误。
var ErrInvalid = errors.New("passkey: bundle 无效")

// Bundle 是一份已加载的 Passkey 凭据。
type Bundle struct {
	// RPID 是 WebAuthn 依赖方 ID，用于 authenticatorData 的 SHA-256 前缀。
	RPID string
	// CredentialID 是凭据 ID，原样回传给服务端。
	CredentialID string
	// UserID 是学号的 base64url 形式（CAS 表单的 username 字段用的就是它）。
	UserID string
	// StartID 即 bundle 里的 anonbiometricsd，startAssertion 的 id 参数。
	StartID string
	// PrivateKey 是 ES256 私钥（P-256）。
	PrivateKey *ecdsa.PrivateKey
}

// Parse 从内联配置（或 passkey.local.json 解析后的 map）构造 Bundle。
//
// 接受的键与 passkey.local.json 相同，密钥部分二选一：
// privateKeyPkcs8Pem 或 privateKeyJwk。
func Parse(fields map[string]any) (*Bundle, error) {
	if len(fields) == 0 {
		return nil, fmt.Errorf("%w: 缺少 passkey 字段", ErrInvalid)
	}

	b := &Bundle{
		RPID:         attr(fields, FieldRPID),
		CredentialID: attr(fields, FieldCredential),
		UserID:       attr(fields, FieldUserID),
		StartID:      attr(fields, FieldStartID),
	}

	var missing []string
	for _, f := range [...]struct {
		name  string
		value string
	}{
		{FieldRPID, b.RPID},
		{FieldCredential, b.CredentialID},
		{FieldUserID, b.UserID},
		{FieldStartID, b.StartID},
	} {
		if f.value == "" {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: 缺少字段或类型不是字符串: %s", ErrInvalid, strings.Join(missing, ", "))
	}

	key, err := parseKey(fields)
	if err != nil {
		return nil, err
	}
	b.PrivateKey = key
	return b, nil
}

// Username 反解 bundle 里的 userId，得到明文学号。
// 隧道握手帧的 A 字段用的是明文学号，而不是这个 base64url 串。
func (b *Bundle) Username() (string, error) {
	raw, err := DecodeBase64URL(b.UserID)
	if err != nil {
		return "", fmt.Errorf("%w: %s 不是合法的 base64url: %v", ErrInvalid, FieldUserID, err)
	}
	if len(raw) == 0 {
		return "", fmt.Errorf("%w: %s 解码后为空", ErrInvalid, FieldUserID)
	}
	return string(raw), nil
}

// UserIDFor 是 Username() 的逆运算，供只有学号、没有 bundle 的场合使用。
func UserIDFor(username string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(username))
}

// SignES256 对 message 做 ECDSA-P256/SHA-256 签名，返回 **DER 编码**的签名。
//
// WebAuthn 断言里 message = authenticatorData ‖ SHA256(clientDataJSON)，
// 服务端期待的就是 DER（与抓包里 MEUCIQ... 开头一致），所以这里必须用
// SignASN1，不能用返回 (r, s) 的 Sign 再手工拼接。
func (b *Bundle) SignES256(rand io.Reader, message []byte) ([]byte, error) {
	if b.PrivateKey == nil {
		return nil, fmt.Errorf("%w: 私钥未加载", ErrInvalid)
	}
	digest := sha256.Sum256(message)
	return ecdsa.SignASN1(rand, b.PrivateKey, digest[:])
}

// DecodeBase64URL 解码 WebAuthn/JWK 使用的无填充 base64url，容忍尾部 '=' 与空白。
func DecodeBase64URL(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	if s == "" {
		return nil, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// attr 读取字符串字段。字段名不做任何归一化，也不做模糊匹配——
// 内联配置能"粘贴即用"全靠这一点。
func attr(fields map[string]any, name string) string {
	v, ok := fields[name]
	if !ok || v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

// parseKey 按 privateKeyPkcs8Pem → privateKeyJwk 的顺序取私钥。
func parseKey(fields map[string]any) (*ecdsa.PrivateKey, error) {
	if text := attr(fields, FieldKeyPEM); text != "" {
		key, err := parsePEMPrivateKey(text)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrInvalid, FieldKeyPEM, err)
		}
		return key, nil
	}
	if jwk := stringMap(fields[FieldKeyJWK]); jwk != nil {
		key, err := parseJWK(jwk)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrInvalid, FieldKeyJWK, err)
		}
		return key, nil
	}
	return nil, fmt.Errorf("%w: 缺少 %s 或 %s", ErrInvalid, FieldKeyPEM, FieldKeyJWK)
}

func parsePEMPrivateKey(text string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil, errors.New("不是 PEM 文本")
	}
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return asP256(parsed)
	} else {
		pkcs8Err := err
		if parsed, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return asP256(parsed)
		} else {
			return nil, fmt.Errorf("无法解析私钥（PKCS#8: %v；SEC1: %v）", pkcs8Err, err)
		}
	}
}

func parseJWK(jwk map[string]any) (*ecdsa.PrivateKey, error) {
	if kty := attr(jwk, "kty"); kty != "" && kty != "EC" {
		return nil, fmt.Errorf("kty 必须是 %q，实际是 %q", "EC", kty)
	}
	if crv := attr(jwk, "crv"); crv != "" && crv != "P-256" {
		return nil, fmt.Errorf("crv 必须是 %q，实际是 %q", "P-256", crv)
	}

	dText := attr(jwk, "d")
	if dText == "" {
		return nil, errors.New("缺少 d")
	}
	d, err := DecodeBase64URL(dText)
	if err != nil {
		return nil, fmt.Errorf("d 不是合法的 base64url: %v", err)
	}
	if len(d) == 0 {
		return nil, errors.New("d 解码后为空")
	}

	curve := elliptic.P256()
	scalar := new(big.Int).SetBytes(d)
	// 先验范围再算公钥：越界的 d 会让 ScalarBaseMult 返回 nil。
	if scalar.Sign() <= 0 || scalar.Cmp(curve.Params().N) >= 0 {
		return nil, errors.New("d 不在 P-256 私钥标量范围内")
	}

	// Curve/X/Y 是通过嵌入的 PublicKey 提升上来的字段，Go 不允许在复合字面量里
	// 直接用提升字段作键名（spec: promoted fields ... cannot be used as field names
	// in composite literals），所以这里必须写嵌套的 PublicKey。
	x, y := curve.ScalarBaseMult(d)
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         scalar,
	}

	// JWK 里若同时给了 x/y，校验与 d 推导出的一致，能挡住粘贴截断导致的静默损坏。
	if xText, yText := attr(jwk, "x"), attr(jwk, "y"); xText != "" && yText != "" {
		x, err := DecodeBase64URL(xText)
		if err != nil {
			return nil, fmt.Errorf("x 不是合法的 base64url: %v", err)
		}
		y, err := DecodeBase64URL(yText)
		if err != nil {
			return nil, fmt.Errorf("y 不是合法的 base64url: %v", err)
		}
		if priv.X.Cmp(new(big.Int).SetBytes(x)) != 0 || priv.Y.Cmp(new(big.Int).SetBytes(y)) != 0 {
			return nil, errors.New("x/y 与 d 推导出的公钥不一致")
		}
	}
	return priv, nil
}

func asP256(key any) (*ecdsa.PrivateKey, error) {
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("私钥类型是 %T，不是 ECDSA", key)
	}
	if name := priv.Curve.Params().Name; name != "P-256" {
		return nil, fmt.Errorf("曲线必须是 P-256(ES256)，实际是 %s", name)
	}
	return priv, nil
}

// stringMap 把嵌套对象统一成 map[string]any。
// 同时容忍 map[any]any：不同 YAML 库产出的嵌套类型并不一致。
func stringMap(v any) map[string]any {
	switch m := v.(type) {
	case map[string]any:
		return m
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			key, ok := k.(string)
			if !ok {
				return nil
			}
			out[key] = val
		}
		return out
	default:
		return nil
	}
}
