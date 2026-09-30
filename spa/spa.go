// Package spa 实现 Enlink 的 SPA（Single Packet Authorization）敲门包构造。
//
// 算法与 fwknop 2.6.10 一致，Enlink 的改动集中在两点：
//   - 加密密钥与 HMAC 密钥共用同一把 K = MD5(USER_KEY)，长度硬编码 16 字节（不是 32）
//   - AES 固定 AES-256-CBC，密钥派生走 OpenSSL EVP_BytesToKey 兼容的 MD5 链
//
// ⚠️ SPA 对数据面**并非必需**：11 条没有发 SPA 的隔离隧道照样收发数据，与真实
// 客户端日志里的 spa_status:false 一致。因此默认关闭，只在需要时打开。
package spa

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultPort 是 SPA 的 UDP 端口。
	DefaultPort = 62201
	// DefaultAccess 是敲门时声明的访问意图。
	DefaultAccess = "tcp/443"
	// ProtoVersion 是 FKO 协议版本串。
	ProtoVersion = "3.0.0"
	// MessageTypeAccess 是最常用的 message_type（1 = Access）。
	// 其余取值：0 Command / 2 NAT access / 3 Client timeout NAT access /
	// 4 Local NAT access / 5 Client timeout local NAT access / 6 Client timeout access。
	MessageTypeAccess = 1
	// DefaultKeyHex 是产品出厂默认 USER-KEY "Enlink@123" 的派生值：
	// MD5("Enlink@123") = ffcbbd5d0ff16b8d161b80a8be26b918
	//
	// 这是全站共用、随安装包分发的常量，所以 SPA 的"隐形"防护实际退化为固定
	// 常量；真正的鉴权仍在控制器登录。允许通过 Options.KeyHex 覆盖。
	DefaultKeyHex = "ffcbbd5d0ff16b8d161b80a8be26b918"

	keyLen     = 16
	saltLen    = 8
	ivMaterial = 48 // 32 字节 AES key + 16 字节 IV
	saltedHead = "Salted__"
)

// Options 是构造 SPA 包的参数。
type Options struct {
	// User 是账号。必填。
	User string
	// Access 是访问意图，默认 "tcp/443"。
	Access string
	// KeyHex 是 16 字节 K 的 hex 形式，默认 DefaultKeyHex。
	KeyHex string
	// DisableHMAC 关闭尾部的 HMAC-SHA256。
	DisableHMAC bool
	// Now 可注入时钟，便于测试。默认 time.Now。
	Now func() time.Time
	// Rand 可注入随机源，便于测试。默认 crypto/rand.Reader。
	Rand io.Reader
}

// KeyFromUserKey 返回 K = MD5(USER_KEY)。
// 产品出厂默认 USER_KEY 是 "Enlink@123"，对应 DefaultKeyHex。
func KeyFromUserKey(userKey string) string {
	sum := md5.Sum([]byte(userKey))
	return hex.EncodeToString(sum[:])
}

func (o Options) withDefaults() (Options, error) {
	if o.User == "" {
		return o, errors.New("spa: 缺少 User")
	}
	if o.Access == "" {
		o.Access = DefaultAccess
	}
	if o.KeyHex == "" {
		o.KeyHex = DefaultKeyHex
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Rand == nil {
		o.Rand = rand.Reader
	}
	return o, nil
}

// Build 构造 SPA 单包，返回可直接 sendto 的字节。
//
//	salt  = 8 字节随机
//	kiv   = MD5(K‖salt) ‖ MD5(MD5(K‖salt)‖K‖salt) ‖ … 取前 48 字节
//	        → aesKey = kiv[0:32]，aesIV = kiv[32:48]
//	msg   = randVal : b64(user) : unix : "3.0.0" : "1" : b64(access)
//	明文   = msg : b64(sha256(msg))
//	blob  = "Salted__" ‖ salt ‖ AES-256-CBC(PKCS7(明文))
//	out   = b64(blob)[10:]                 ← 掐掉固定的 b64("Salted__") 前 10 字符
//	out  += b64(HMAC-SHA256(K, b64(blob))) ← 若启用，覆盖的是完整 base64 串
func Build(opts Options) ([]byte, error) {
	o, err := opts.withDefaults()
	if err != nil {
		return nil, err
	}

	key, err := hex.DecodeString(o.KeyHex)
	if err != nil {
		return nil, fmt.Errorf("spa: KeyHex 不是合法 hex: %w", err)
	}
	if len(key) != keyLen {
		return nil, fmt.Errorf("spa: K 必须是 %d 字节，实际 %d", keyLen, len(key))
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(o.Rand, salt); err != nil {
		return nil, fmt.Errorf("spa: 生成 salt 失败: %w", err)
	}

	kiv := deriveKIV(key, salt, ivMaterial)
	aesKey, aesIV := kiv[:32], kiv[32:48]

	randVal, err := randomDigits(o.Rand, 16)
	if err != nil {
		return nil, err
	}

	msg := strings.Join([]string{
		randVal,
		b64([]byte(o.User)),
		strconv.FormatInt(o.Now().Unix(), 10),
		ProtoVersion,
		strconv.Itoa(MessageTypeAccess),
		b64([]byte(o.Access)),
	}, ":")
	digest := sha256.Sum256([]byte(msg))
	plain := []byte(msg + ":" + b64(digest[:]))

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("spa: 构造 AES 失败: %w", err)
	}
	padded := pkcs7Pad(plain, block.BlockSize())
	cipherText := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, aesIV).CryptBlocks(cipherText, padded)

	blob := make([]byte, 0, len(saltedHead)+len(salt)+len(cipherText))
	blob = append(blob, saltedHead...)
	blob = append(blob, salt...)
	blob = append(blob, cipherText...)

	full := b64(blob)
	if len(full) <= 10 {
		return nil, errors.New("spa: base64 结果异常短")
	}
	out := full[10:] // 这 10 个字符是常量 b64("Salted__") 的前缀
	if !o.DisableHMAC {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(full))
		out += b64(mac.Sum(nil))
	}
	return []byte(out), nil
}

// Knock 通过 UDP 发出一个 SPA 包。port <= 0 时用 DefaultPort。
func Knock(ctx context.Context, host string, port int, opts Options) error {
	packet, err := Build(opts)
	if err != nil {
		return err
	}
	if port <= 0 {
		port = DefaultPort
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("spa: 连接 %s 失败: %w", host, err)
	}
	defer conn.Close()
	if _, err := conn.Write(packet); err != nil {
		return fmt.Errorf("spa: 发送失败: %w", err)
	}
	return nil
}

// deriveKIV 是 fwknop 的 MD5 链密钥派生，等价于 OpenSSL 的 EVP_BytesToKey。
func deriveKIV(password, salt []byte, need int) []byte {
	out := make([]byte, 0, need+md5.Size)
	var prev []byte
	for len(out) < need {
		h := md5.New()
		h.Write(prev)
		h.Write(password)
		h.Write(salt)
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:need]
}

// randomDigits 生成 n 位十进制数字串（原客户端用 16 位）。
func randomDigits(r io.Reader, n int) (string, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", fmt.Errorf("spa: 生成随机数失败: %w", err)
	}
	var sb strings.Builder
	sb.Grow(n)
	for _, b := range buf {
		sb.WriteByte('0' + b%10)
	}
	return sb.String(), nil
}

// pkcs7Pad 做 PKCS#7 填充（Go 标准库不提供，这里只是填充，不是密码学实现）。
func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

// b64 是 Python 侧 b64s 的等价实现：标准 base64 去掉尾部 '='。
func b64(data []byte) string {
	return base64.RawStdEncoding.EncodeToString(data)
}
