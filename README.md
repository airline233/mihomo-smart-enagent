# mihomo-smart-enagent

为 mihomo 兼容了 SwordAgent(EnAgent) 协议，暂时仅对南信大vpn进行了测试与passkey登录适配。

上游项目 [mihomo-smart](https://github.com/lux5am/mihomo-smart)

## 开始使用

1. 从 [Releases](https://github.com/airline233/mihomo-smart-enagent/releases) 下载内核，或从 [Actions](https://github.com/airline233/mihomo-smart-enagent/actions/workflows/build.yml) 获取日常构建。
2. 将客户端内核替换为下载的版本。
3. 准备已注册到南信大统一身份认证的软件 Passkey 凭据（`passkey.local.json`），将下面的节点加入现有配置。
4. 正常使用Clash即可

提供 Windows x64、Linux x64 和 Linux ARM64 构建；x64 版本需要支持 x86-64-v3 的 CPU。

### 配置示例
```yaml
proxies:
  - name: nuist
    type: enagent
    server: client.vpn.nuist.edu.cn
    port: 443
    passkey:
      rpId: authserver.nuist.edu.cn
      credentialId: "填写凭据中的 credentialId"
      userId: "填写凭据中的 userId"
      anonbiometricsd: "填写凭据中的 anonbiometricsd"
      privateKeyPkcs8Pem: "-----BEGIN PRIVATE KEY-----\nxxxxxx\n-----END PRIVATE KEY-----"
```

获取凭据请看 [nuist-authserver-login](https://github.com/airline233/nuist-authserver-login)