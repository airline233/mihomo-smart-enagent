<#
.SYNOPSIS
    本地构建 mihomo-smart + enagent：clone 上游 → 打补丁 → 注入模块 → 编译。

.DESCRIPTION
    仓库里不存放 mihomo 源码，所以每次构建都现拉上游。与 CI（build.yml）以及
    scripts/build-mihomo.sh 步骤完全一致，避免出现"CI 绿了但本地编不出来"。

    产物落在 <仓库>/dist/。

    本地验收提醒：编译通过只证明"能编译"，真机联通性需要校园网 + 真实 passkey，
    只能自己跑一遍（见 README）。

.PARAMETER UpstreamRef
    上游 ref（分支或 tag），默认 Alpha。

.PARAMETER Targets
    构建目标，默认 windows-amd64。
    可选：windows-amd64 / windows-arm64 / linux-amd64 / linux-arm64 / darwin-amd64 / darwin-arm64

.PARAMETER CacheRoot
    Go 缓存与上游 clone 的存放位置。
    默认 %LOCALAPPDATA%\mihomo-smart-enagent（刻意不放仓库里：上游源码树有上万文件，
    放进 OneDrive 目录会被反复同步）。

.EXAMPLE
    pwsh -File scripts/build-mihomo.ps1
    pwsh -File scripts/build-mihomo.ps1 -UpstreamRef v1.0.0 -Targets windows-amd64,linux-amd64
#>
[CmdletBinding()]
param(
    [string]$UpstreamRef = 'Alpha',
    [string]$Upstream = 'https://github.com/lux5am/mihomo-smart.git',
    [string[]]$Targets = @('windows-amd64'),
    [string]$CacheRoot = ''
)

$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not $CacheRoot) {
    $CacheRoot = if ($env:MIHOMO_ENAGENT_CACHE) {
        $env:MIHOMO_ENAGENT_CACHE
    } elseif ($env:LOCALAPPDATA) {
        Join-Path $env:LOCALAPPDATA 'mihomo-smart-enagent'
    } else {
        Join-Path $RepoRoot '.cache'
    }
}

$CloneDir = Join-Path $CacheRoot 'mihomo-smart'
$PatchFile = Join-Path $RepoRoot '_integration\patches\0001-register-enagent.patch'
$AdapterDir = Join-Path $RepoRoot '_integration\adapter\outbound'
$DistDir = Join-Path $RepoRoot 'dist'

# Go 缓存也放到 CacheRoot 下：既不污染 $HOME，也让重复构建更快。
# DSH 沙箱里默认 GOCACHE（%LOCALAPPDATA%\go-build）是不可写的，这时必须显式指定
# -CacheRoot（例如 -CacheRoot <仓库>\.cache）。
if (-not $env:GOPATH) { $env:GOPATH = Join-Path $CacheRoot 'gopath' }
if (-not $env:GOCACHE) { $env:GOCACHE = Join-Path $CacheRoot 'gobuild' }
if (-not $env:GOMODCACHE) { $env:GOMODCACHE = Join-Path $CacheRoot 'gomod' }
if (-not $env:GOTMPDIR) { $env:GOTMPDIR = Join-Path $CacheRoot 'tmp' }
foreach ($dir in @($env:GOPATH, $env:GOCACHE, $env:GOMODCACHE, $env:GOTMPDIR)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

# 某些 Windows 环境（含 DSH 沙箱）用 schannel 拉 git 会报 SEC_E_NO_CREDENTIALS，
# 强制走 OpenSSL 后端即可。在 Linux 上这是个无害的选项。
$GitCommon = @('-c', 'http.sslBackend=openssl')

function Write-Step([string]$Message) {
    Write-Host "==> $Message" -ForegroundColor Cyan
}

Write-Step "上游 $Upstream @ $UpstreamRef"
if (Test-Path (Join-Path $CloneDir '.git')) {
    # 复用 clone：先恢复成上游原样（clean 会删掉上次注入的 enagent/ 与 adapter 文件）
    git -C $CloneDir @GitCommon fetch --depth 1 origin $UpstreamRef
    if ($LASTEXITCODE -ne 0) { throw "git fetch 失败" }
    git -C $CloneDir checkout -q --force FETCH_HEAD
    git -C $CloneDir reset -q --hard FETCH_HEAD
    git -C $CloneDir clean -qfd
} else {
    New-Item -ItemType Directory -Force -Path $CacheRoot | Out-Null
    git @GitCommon clone --depth 1 --branch $UpstreamRef $Upstream $CloneDir
    if ($LASTEXITCODE -ne 0) { throw "git clone 失败" }
}
$UpstreamSha = (git -C $CloneDir rev-parse --short HEAD).Trim()
Write-Step "上游 HEAD = $UpstreamSha"

Write-Step '打注册补丁'
git -C $CloneDir apply -3 --verbose $PatchFile
if ($LASTEXITCODE -ne 0) {
    throw "补丁无法应用：上游可能挪动了锚点。请按 _integration/patches/README 重新导出补丁。"
}

Write-Step '注入 enagent 模块与 adapter'
# 顺序很重要：补丁会改 mihomo/go.mod，之后再把我们的模块放进去。
$cloneModule = Join-Path $CloneDir 'enagent'
New-Item -ItemType Directory -Force -Path $cloneModule | Out-Null
Copy-Item (Join-Path $RepoRoot 'go.mod'), (Join-Path $RepoRoot 'go.sum') $cloneModule -Force
foreach ($pkg in 'passkey', 'cas', 'spa', 'tunnel', 'stack', 'session') {
    Copy-Item (Join-Path $RepoRoot $pkg) (Join-Path $cloneModule $pkg) -Recurse -Force
}
Copy-Item (Join-Path $AdapterDir 'enagent*.go') (Join-Path $CloneDir 'adapter\outbound') -Force

New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

$targetMap = @{
    'windows-amd64' = @{ GOOS = 'windows'; GOARCH = 'amd64'; GOAMD64 = 'v3'; Ext = '.exe' }
    'windows-arm64' = @{ GOOS = 'windows'; GOARCH = 'arm64'; GOAMD64 = ''; Ext = '.exe' }
    'linux-amd64'   = @{ GOOS = 'linux'; GOARCH = 'amd64'; GOAMD64 = 'v3'; Ext = '' }
    'linux-arm64'   = @{ GOOS = 'linux'; GOARCH = 'arm64'; GOAMD64 = ''; Ext = '' }
    'darwin-amd64'  = @{ GOOS = 'darwin'; GOARCH = 'amd64'; GOAMD64 = 'v3'; Ext = '' }
    'darwin-arm64'  = @{ GOOS = 'darwin'; GOARCH = 'arm64'; GOAMD64 = ''; Ext = '' }
}

$buildTime = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$ldflags = "-s -w -X github.com/metacubex/mihomo/constant.Version=enagent-$UpstreamRef-$UpstreamSha " +
"-X github.com/metacubex/mihomo/constant.BuildTime=$buildTime"

foreach ($target in $Targets) {
    if (-not $targetMap.ContainsKey($target)) { throw "未知构建目标: $target" }
    $spec = $targetMap[$target]
    $out = Join-Path $DistDir "mihomo-enagent-$target$($spec.Ext)"

    Write-Step "编译 $target"
    $saved = @{}
    foreach ($name in 'GOOS', 'GOARCH', 'GOAMD64', 'CGO_ENABLED') {
        $saved[$name] = [Environment]::GetEnvironmentVariable($name)
    }
    try {
        $env:GOOS = $spec.GOOS
        $env:GOARCH = $spec.GOARCH
        $env:GOAMD64 = $spec.GOAMD64
        $env:CGO_ENABLED = '0'
        Push-Location $CloneDir
        try {
            go build -tags with_gvisor -trimpath -ldflags $ldflags -o $out .
            if ($LASTEXITCODE -ne 0) { throw "go build 失败（$target）" }
        } finally {
            Pop-Location
        }
    } finally {
        foreach ($name in 'GOOS', 'GOARCH', 'GOAMD64', 'CGO_ENABLED') {
            if ($null -eq $saved[$name]) {
                Remove-Item "Env:$name" -ErrorAction SilentlyContinue
            } else {
                Set-Item "Env:$name" $saved[$name]
            }
        }
    }

    # 冒烟检查：确认链进去的是真实实现而不是 stub。
    # （纯字符串检查，不需要真机凭据，也不用执行二进制。）
    $text = [System.IO.File]::ReadAllText($out, [System.Text.Encoding]::UTF8)
    if (-not $text.Contains('隧道就绪')) {
        throw "$out 里没有 EnAgent 实现（可能编译成了 stub）"
    }
    $sizeMb = [math]::Round((Get-Item $out).Length / 1MB, 1)
    Write-Step "已产出 $out（${sizeMb} MB）"
}

Write-Step "完成，产物在 $DistDir"
Get-ChildItem $DistDir | Select-Object Name, @{ n = 'MB'; e = { [math]::Round($_.Length / 1MB, 1) } }
