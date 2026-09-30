# 打给 mihomo-smart 的补丁

## 这里只有**一个**补丁，而且只做"注册"

`0001-register-enagent.patch` 只改上游的 3 个文件、共 16 行：

| 文件 | 改动 | 为什么必须改上游 |
|---|---|---|
| `adapter/parser.go` | `case "enagent":` +7 行 | mihomo 的 outbound 注册是硬编码 switch，没有注册表机制 |
| `constant/adapters.go` | `AdapterType` 枚举 + `String()` +3 行 | `Type()` 要返回一个类型标识 |
| `go.mod` | `require` + `replace` +6 行 | 指向本地 enagent 模块 |

**我们自己新增的文件不走补丁**，由 `scripts/build-mihomo.*` 直接拷进源码树：

```
_integration/adapter/outbound/enagent.go       → mihomo/adapter/outbound/
_integration/adapter/outbound/enagent_stub.go  → mihomo/adapter/outbound/
（模块本身）                                     → mihomo/enagent/
```

这样分工的理由：新增文件永远不会冲突，只有"改上游已有文件"才有冲突风险。所以补丁面越小越好。

`go.sum` **不需要改**：enagent 的依赖（gvisor / x-sys / x-time / btree）在 mihomo 的 go.sum 里已存在，且 enagent 要求的版本都 ≤ mihomo 的版本，MVS 会解析到 mihomo 已有的版本，加上 `replace` 指向本地目录也不需要 go.sum 条目。因此 CI 里**不用**跑 `go mod tidy`。

## 上游挪了锚点怎么办

`upstream-canary` workflow 每天会试一次"打补丁 + 编译"，一旦补丁应用失败它会直接红，不用等到发版才发现。

修法（在本地 clone 上操作）：

```bash
# 1) 拉最新上游到缓存目录
pwsh -File scripts/build-mihomo.ps1 -Targets windows-amd64
#    如果卡在“打注册补丁”，说明 hunk 上下文对不上了，往下走：

# 2) 手工把这三处改动重新做一遍（改动内容见上面的表格）
cd <CacheRoot>/mihomo-smart
#    ……编辑 adapter/parser.go、constant/adapters.go、go.mod……

# 3) 重新导出补丁（覆盖旧的）
#    必须用 git 的 --output 让 git 自己写文件：
#    ⚠️ 在 Windows 上写 `git diff ... > patch` 会把行尾变成 CRLF，而上游源码是 LF，
#    之后 git apply 会因上下文不匹配而失败（这个坑真踩过）。
git diff --output=<仓库>/_integration/patches/0001-register-enagent.patch \
  -- adapter/parser.go constant/adapters.go go.mod
```

导出的补丁必须带 `index` 行（`git diff` 默认会带），否则 CI 里的 `git apply -3` 失去三方合并能力。

另外注意：**补丁里不要夹带改动的 `go.sum`**。如果哪天真的动了 go.sum，说明 enagent 引入了 mihomo 没有的依赖版本，那时要重新评估"用已有依赖"这个约束（见 `stack/stack.go` 的包注释）。
