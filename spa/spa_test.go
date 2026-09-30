package spa

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// referenceVector 是 testdata/gen_reference.py 从 Python 参考实现导出的黄金向量。
// 字段定义在 reference_vectors_test.go 里被填充。
type referenceVector struct {
	name    string
	user    string
	access  string
	saltHex string
	randVal string
	useHMAC bool
	wantKIV string
	want    string
}

// fixedClock 与生成向量时固定的时间一致。
func fixedClock() time.Time { return time.Unix(1700000000, 0) }

// referenceRand 复现生成向量时的随机源：先 8 字节 salt，再 16 个"数字字节"。
//
// randomDigits 用 '0' + b%10 取数字，所以要让 b%10 == d 必须喂字节值 d，
// 不能喂 ASCII 字符 '0'+d（'1' 是 0x31，0x31%10 == 9）。
func referenceRand(t *testing.T, saltHex, randVal string) *bytes.Reader {
	t.Helper()
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		t.Fatalf("salt 不是合法 hex: %v", err)
	}
	buf := make([]byte, 0, len(salt)+len(randVal))
	buf = append(buf, salt...)
	for i := 0; i < len(randVal); i++ {
		if randVal[i] < '0' || randVal[i] > '9' {
			t.Fatalf("randVal 含非数字字符: %q", randVal)
		}
		buf = append(buf, randVal[i]-'0')
	}
	return bytes.NewReader(buf)
}

func buildReference(t *testing.T, v referenceVector) []byte {
	t.Helper()
	out, err := Build(Options{
		User:        v.user,
		Access:      v.access,
		DisableHMAC: !v.useHMAC,
		Now:         fixedClock,
		Rand:        referenceRand(t, v.saltHex, v.randVal),
	})
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	return out
}

// TestBuildMatchesPythonReference 是核心对拍：Go 实现必须与 Python 参考实现
// （vpn_client.build_spa）逐字节一致。它同时覆盖了 MD5 链密钥派生、AES-256-CBC、
// PKCS#7 填充、b64("Salted__") 前 10 字符的掐除，以及 HMAC 的半开半闭两个分支。
func TestBuildMatchesPythonReference(t *testing.T) {
	if len(referenceVectors) == 0 {
		t.Fatal("黄金向量为空，检查 testdata/gen_reference.py")
	}
	for _, v := range referenceVectors {
		t.Run(v.name, func(t *testing.T) {
			got := buildReference(t, v)
			if string(got) != v.want {
				t.Fatalf("与 Python 参考实现不一致:\n got = %s\nwant = %s", got, v.want)
			}
		})
	}
}

// TestDeriveKIVMatchesReference 单独钉住密钥派生，出问题时便于定位。
func TestDeriveKIVMatchesReference(t *testing.T) {
	key, err := hex.DecodeString(DefaultKeyHex)
	if err != nil {
		t.Fatalf("DefaultKeyHex 不是合法 hex: %v", err)
	}
	if len(key) != keyLen {
		t.Fatalf("DefaultKeyHex 解出 %d 字节，期望 %d", len(key), keyLen)
	}
	for _, v := range referenceVectors {
		salt, err := hex.DecodeString(v.saltHex)
		if err != nil {
			t.Fatalf("salt: %v", err)
		}
		got := hex.EncodeToString(deriveKIV(key, salt, ivMaterial))
		if got != v.wantKIV {
			t.Fatalf("KIV 与参考实现不一致:\n got = %s\nwant = %s", got, v.wantKIV)
		}
	}
}

// TestKeyFromUserKey 确认文档里那个"产品出厂默认"常量确实是 MD5(USER_KEY)。
func TestKeyFromUserKey(t *testing.T) {
	if got := KeyFromUserKey("Enlink@123"); got != DefaultKeyHex {
		t.Fatalf("MD5(\"Enlink@123\") = %s，期望 %s", got, DefaultKeyHex)
	}
}

// TestOutputStartsWithStrippedSaltPrefix 验证被掐掉的 10 字符确实是常量，
// 且补回去能解出 "Salted__" 魔数与 salt。
func TestOutputStartsWithStrippedSaltPrefix(t *testing.T) {
	v := referenceVectors[len(referenceVectors)-1]
	if v.useHMAC {
		t.Skip("需要一条未启用 HMAC 的向量才能整体解码")
	}
	out := string(buildReference(t, v))

	// 服务端会把掐掉的前缀补回来再 base64 解码。
	full := "U2FsdGVkX1" + out
	if !strings.HasPrefix(full, "U2FsdGVkX1") {
		t.Fatal("b64(\"Salted__\") 前缀常量不对")
	}
	blob, err := base64.RawStdEncoding.DecodeString(full)
	if err != nil {
		t.Fatalf("补回前缀后无法解码: %v", err)
	}
	if !bytes.HasPrefix(blob, []byte(saltedHead)) {
		t.Fatalf("解出的 blob 不以 %q 开头: % x", saltedHead, blob[:8])
	}
	salt, err := hex.DecodeString(v.saltHex)
	if err != nil {
		t.Fatalf("salt: %v", err)
	}
	if !bytes.Equal(blob[len(saltedHead):len(saltedHead)+len(salt)], salt) {
		t.Fatalf("blob 里的 salt = % x，期望 % x", blob[8:16], salt)
	}
}

// TestDecryptedPlaintextLayout 把自己的输出解回明文，钉住内层报文的字段顺序与
// 自校验摘要（msg 的 sha256），这是"SHA-256 校验"这一层的唯一防线。
func TestDecryptedPlaintextLayout(t *testing.T) {
	v := referenceVectors[len(referenceVectors)-1]
	if v.useHMAC {
		t.Skip("需要一条未启用 HMAC 的向量才能整体解码")
	}
	out := string(buildReference(t, v))

	blob, err := base64.RawStdEncoding.DecodeString("U2FsdGVkX1" + out)
	if err != nil {
		t.Fatalf("解码 blob 失败: %v", err)
	}
	key, err := hex.DecodeString(DefaultKeyHex)
	if err != nil {
		t.Fatalf("DefaultKeyHex: %v", err)
	}
	salt, err := hex.DecodeString(v.saltHex)
	if err != nil {
		t.Fatalf("salt: %v", err)
	}
	kiv := deriveKIV(key, salt, ivMaterial)

	block, err := aes.NewCipher(kiv[:32])
	if err != nil {
		t.Fatalf("构造 AES 失败: %v", err)
	}
	cipherText := blob[len(saltedHead)+len(salt):]
	if len(cipherText)%block.BlockSize() != 0 {
		t.Fatalf("密文长度 %d 不是块大小的整数倍", len(cipherText))
	}
	plain := make([]byte, len(cipherText))
	cipher.NewCBCDecrypter(block, kiv[32:48]).CryptBlocks(plain, cipherText)
	plain, err = pkcs7Unpad(plain, block.BlockSize())
	if err != nil {
		t.Fatalf("去填充失败: %v", err)
	}

	parts := strings.Split(string(plain), ":")
	if len(parts) != 7 {
		t.Fatalf("明文分为 %d 段，期望 7 段: %q", len(parts), plain)
	}
	if parts[0] != v.randVal {
		t.Errorf("randVal = %q，期望 %q", parts[0], v.randVal)
	}
	if parts[1] != b64([]byte(v.user)) {
		t.Errorf("user 段 = %q，期望 %q", parts[1], b64([]byte(v.user)))
	}
	if parts[2] != strconv.FormatInt(fixedClock().Unix(), 10) {
		t.Errorf("时间戳 = %q", parts[2])
	}
	if parts[3] != ProtoVersion {
		t.Errorf("协议版本 = %q，期望 %q", parts[3], ProtoVersion)
	}
	if parts[4] != strconv.Itoa(MessageTypeAccess) {
		t.Errorf("message_type = %q，期望 %d", parts[4], MessageTypeAccess)
	}
	if parts[5] != b64([]byte(v.access)) {
		t.Errorf("access 段 = %q，期望 %q", parts[5], b64([]byte(v.access)))
	}
	msg := strings.Join(parts[:6], ":")
	digest := sha256.Sum256([]byte(msg))
	if parts[6] != b64(digest[:]) {
		t.Errorf("摘要段 = %q，期望 b64(sha256(msg)) = %q", parts[6], b64(digest[:]))
	}
}

func TestBuildRejectsBadInput(t *testing.T) {
	if _, err := Build(Options{}); err == nil {
		t.Fatal("缺少 User 应报错")
	}
	if _, err := Build(Options{User: "u", KeyHex: "zz"}); err == nil {
		t.Fatal("非法 hex 应报错")
	}
	if _, err := Build(Options{User: "u", KeyHex: "0011"}); err == nil {
		t.Fatal("长度不是 16 字节应报错")
	}
}

func TestBuildUsesDefaults(t *testing.T) {
	// 不传 Access/KeyHex/Now/Rand 也必须能构造出来（走默认值路径）。
	out, err := Build(Options{User: "202500000000"})
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	if len(out) < 36 {
		t.Fatalf("载荷长度 %d 小于 MIN_SPA_ENCODED_MSG_SIZE(36)", len(out))
	}
	if len(out) > 1500 {
		t.Fatalf("载荷长度 %d 超过 MAX_SPA_ENCRYPTED_SIZE(1500)", len(out))
	}
}

// pkcs7Unpad 仅用于测试侧验证。
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errBadPadding
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > blockSize || pad > len(data) {
		return nil, errBadPadding
	}
	for _, b := range data[len(data)-pad:] {
		if int(b) != pad {
			return nil, errBadPadding
		}
	}
	return data[:len(data)-pad], nil
}

var errBadPadding = errors.New("pkcs7 填充非法")
