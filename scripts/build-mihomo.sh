#!/usr/bin/env bash
# 本地 / CI 共用的构建入口：clone 上游 → 打补丁 → 注入 enagent 模块 → 编译。
#
# 与 scripts/build-mihomo.ps1 步骤必须保持一致（改一个记得改另一个）。
#
# 用法：
#   scripts/build-mihomo.sh                          # 默认 Alpha + linux-amd64
#   UPSTREAM_REF=v1.2.3 TARGETS="windows-amd64 linux-arm64" scripts/build-mihomo.sh
#
# 环境变量：
#   UPSTREAM_REF  上游 ref，默认 Alpha
#   UPSTREAM      上游仓库，默认 lux5am/mihomo-smart
#   TARGETS       空格分隔的构建目标
#   CACHE_ROOT    构建缓存与上游 clone 的存放位置（默认不放仓库里，避免污染工作区）
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPSTREAM="${UPSTREAM:-https://github.com/lux5am/mihomo-smart.git}"
UPSTREAM_REF="${UPSTREAM_REF:-Alpha}"
TARGETS="${TARGETS:-linux-amd64}"
CACHE_ROOT="${CACHE_ROOT:-${MIHOMO_ENAGENT_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/mihomo-smart-enagent}}"

CLONE_DIR="$CACHE_ROOT/mihomo-smart"
PATCH_FILE="$REPO_ROOT/_integration/patches/0001-register-enagent.patch"
ADAPTER_DIR="$REPO_ROOT/_integration/adapter/outbound"
DIST_DIR="$REPO_ROOT/dist"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m!!\033[0m %s\n' "$*" >&2; exit 1; }

# Go 缓存放到 CACHE_ROOT 下：既不污染 $HOME，也让重复构建更快。
# 已经由环境变量指定的（例如 CI 上的 setup-go）优先保留。
export GOPATH="${GOPATH:-$CACHE_ROOT/gopath}"
export GOCACHE="${GOCACHE:-$CACHE_ROOT/gobuild}"
export GOMODCACHE="${GOMODCACHE:-$CACHE_ROOT/gomod}"
export GOTMPDIR="${GOTMPDIR:-$CACHE_ROOT/tmp}"
mkdir -p "$GOPATH" "$GOCACHE" "$GOMODCACHE" "$GOTMPDIR"

log "上游 $UPSTREAM @ $UPSTREAM_REF"
if [ -d "$CLONE_DIR/.git" ]; then
  # 复用 clone：先恢复成上游原样（clean 会删掉上次注入的 enagent/ 与 adapter 文件）
  git -C "$CLONE_DIR" fetch --depth 1 origin "$UPSTREAM_REF"
  git -C "$CLONE_DIR" checkout -q --force FETCH_HEAD
  git -C "$CLONE_DIR" reset -q --hard FETCH_HEAD
  git -C "$CLONE_DIR" clean -qfd
else
  mkdir -p "$CACHE_ROOT"
  git clone --depth 1 --branch "$UPSTREAM_REF" "$UPSTREAM" "$CLONE_DIR"
fi
UPSTREAM_SHA="$(git -C "$CLONE_DIR" rev-parse --short HEAD)"
log "上游 HEAD = $UPSTREAM_SHA"

log "打注册补丁"
# -3：三方合并，上游挪动锚点时交给 git 自己合
git -C "$CLONE_DIR" apply -3 --verbose "$PATCH_FILE"

log "注入 enagent 模块与 adapter"
# 顺序很重要：补丁会改 mihomo/go.mod，之后再把我们的模块放进去。
mkdir -p "$CLONE_DIR/enagent"
cp "$REPO_ROOT/go.mod" "$REPO_ROOT/go.sum" "$CLONE_DIR/enagent/"
for pkg in passkey cas spa tunnel stack session; do
  cp -r "$REPO_ROOT/$pkg" "$CLONE_DIR/enagent/"
done
cp "$ADAPTER_DIR"/enagent*.go "$CLONE_DIR/adapter/outbound/"

mkdir -p "$DIST_DIR"
for target in $TARGETS; do
  case "$target" in
    windows-amd64) GOOS=windows GOARCH=amd64 GOAMD64=v3 EXT=.exe ;;
    windows-arm64) GOOS=windows GOARCH=arm64 GOAMD64=    EXT=.exe ;;
    linux-amd64)   GOOS=linux   GOARCH=amd64 GOAMD64=v3 EXT= ;;
    linux-arm64)   GOOS=linux   GOARCH=arm64 GOAMD64=    EXT= ;;
    darwin-amd64)  GOOS=darwin  GOARCH=amd64 GOAMD64=v3 EXT= ;;
    darwin-arm64)  GOOS=darwin  GOARCH=arm64 GOAMD64=    EXT= ;;
    *) fail "未知构建目标: $target" ;;
  esac

  out="$DIST_DIR/mihomo-enagent-$target$EXT"
  log "编译 $target"
  (
    cd "$CLONE_DIR"
    CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" GOAMD64="${GOAMD64:-}" \
      go build -tags with_gvisor -trimpath \
      -ldflags "-s -w -X github.com/metacubex/mihomo/constant.Version=enagent-$UPSTREAM_REF-$UPSTREAM_SHA -X github.com/metacubex/mihomo/constant.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      -o "$out" .
  )

  # 冒烟检查：确认链进去的是真实实现而不是 stub。
  # （纯字符串检查，不需要真机凭据，也不用执行二进制。）
  grep -qa "隧道就绪" "$out" || fail "$out 里没有 EnAgent 实现（可能编译成了 stub）"
  log "已产出 $out"
done

log "完成，产物在 $DIST_DIR"
ls -lh "$DIST_DIR"
