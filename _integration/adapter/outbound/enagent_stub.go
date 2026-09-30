//go:build !with_gvisor || no_enagent

// EnAgent outbound 的占位实现。
//
// 与 tailscale_stub.go 同理：EnAgent 依赖用户态协议栈（gVisor），需要 with_gvisor
// 构建标签；在其它构建配置下必须仍能编译，所以这里提供同名的类型与构造函数。
package outbound

import "fmt"

// EnAgent 在未启用 with_gvisor 时是空壳。
type EnAgent struct {
	*Base
}

// EnAgentOption 必须与真实实现保持字段一致，否则 parser.go 在两种构建配置下
// 解出来的配置不同。
type EnAgentOption struct {
	BasicOption
	Name           string         `proxy:"name"`
	Server         string         `proxy:"server"`
	Port           int            `proxy:"port,omitempty"`
	Username       string         `proxy:"username,omitempty"`
	Passkey        map[string]any `proxy:"passkey"`
	SPA            bool           `proxy:"spa,omitempty"`
	SkipCertVerify bool           `proxy:"skip-cert-verify,omitempty"`
	StateDir       string         `proxy:"state-dir,omitempty"`
	UDP            bool           `proxy:"udp,omitempty"`
}

// NewEnAgent 在未启用 with_gvisor 时直接报错。
func NewEnAgent(option EnAgentOption) (*EnAgent, error) {
	return nil, fmt.Errorf("enagent support is disabled by \"no_enagent\" build tag or not include \"with_gvisor\" build tag")
}
