# cis-helper SDK 使用指南

## 1. 概述

`cis-helper` 是一个基于 Go 的 SDK，用于从 SPIRE agent 或本地来源加载工作负载身份，并将以下内容缓存在内存中：

- JWT-SVID
- JWT bundle
- X.509-SVID 证书链和私钥
- X.509 bundle

SDK 在 `NewHelper` 时完成首次加载，只有当 JWT 和 X.509 相关数据都成功加载并写入缓存后，才会返回可用的 `Helper` 实例。之后 SDK 会按固定周期刷新缓存，并且仅在整批刷新成功后才替换旧缓存。

## 2. 核心能力

- 支持三种身份来源，并按固定优先级选择：内存 > 磁盘 > SPIRE agent
- 对外提供统一的 JWT / X.509 / TLS 获取接口
- 支持 mTLS 和单向 TLS
- 提供结构化日志和可插拔 metrics
- 支持按 trust domain 返回 bundle，或在未指定 trust domain 时返回全部 bundle

## 3. 配置模型

`NewHelper` 的配置结构分为三部分：

- 通用运行配置：刷新周期、请求超时、trust domain、TLS、日志、metrics
- `Source`：身份来源配置
- `JWT`：JWT-SVID 请求配置

### 3.1 Config

```go
type Config struct {
    RefreshInterval time.Duration
    RequestTimeout  time.Duration
    TrustDomain     string
    Source          SourceConfig
    JWT             JWTConfig
    TLSMode         TLSMode
    TLSAuthorizer   PeerAuthorizer
    Logger          *slog.Logger
    Metrics         MetricsRecorder
}
```

字段说明：

- `RefreshInterval`：后台刷新周期，默认 `20s`
- `RequestTimeout`：单次加载或刷新超时，默认 `10s`
- `TrustDomain`：可选。设置后 `GetJWTBundle` 和 `GetX509Bundle` 仅返回该 trust domain；为空时返回全部缓存 bundle
- `TLSMode`：`mtls` 或 `one_way_tls`
- `TLSAuthorizer`：仅在 `mtls` 模式下生效，用于在 SPIFFE 证书校验后做额外授权
- `Logger`：自定义日志器
- `Metrics`：自定义 metrics 记录器

### 3.2 SourceConfig

```go
type SourceConfig struct {
    AgentAddress string
    Memory       *MemorySource
    Disk         *DiskSource
}
```

字段说明：

- `AgentAddress`：SPIRE Workload API 地址，默认 `unix:///run/spire/sockets/agent.sock`
- `Memory`：最高优先级本地内存来源
- `Disk`：第二优先级本地磁盘来源

来源优先级：

1. `Source.Memory`
2. `Source.Disk`
3. `Source.AgentAddress` 对应的 SPIRE agent

注意：

- 如果更高优先级来源被配置，SDK 不会自动回退到更低优先级
- 如果已选中的来源不完整或格式错误，`NewHelper` 会直接返回错误

### 3.3 JWTConfig

```go
type JWTConfig struct {
    Audiences []string
    SPIFFEID  string
}
```

字段说明：

- `Audiences`：对齐 Workload API `JWTSVIDRequest.audience`
  用途：
  - 决定 SDK 启动时首次向 SPIRE agent 请求哪个 audience 的 JWT-SVID
  - 决定后续 `GetJWTSVID()` 返回的是哪一组 JWT-SVID
  - 当来源是本地内存或磁盘时，SDK 也会使用这组 audience 解析和校验本地 JWT token
- `SPIFFEID`：对齐 Workload API `JWTSVIDRequest.spiffe_id`
  用途：
  - 当需要为指定 SPIFFE ID 请求 JWT-SVID 时使用
  - 如果不设置，则由 SPIRE agent 按默认工作负载身份返回 JWT-SVID
  - 当来源是本地内存或磁盘时，它也可用于辅助推导 trust domain

默认值：

- `Audiences` 为空时，默认使用 `["spire-server"]`

## 4. 身份来源格式

### 4.1 内存来源

```go
type MemorySource struct {
    Data   *MemoryIdentityData
    Loader func() (*MemoryIdentityData, error)
}

type MemoryIdentityData struct {
    JWTSVIDToken  string
    JWTBundleJSON []byte
    X509SVIDPEM   []byte
    X509KeyPEM    []byte
    X509BundlePEM []byte
}
```

格式要求：

- `Data`：静态内存快照
- `Loader`：动态内存加载函数。SDK 每次刷新都会重新调用它

`MemoryIdentityData` 字段要求：

- `JWTSVIDToken`：原始 JWT token 字符串
- `JWTBundleJSON`：原始 JWT bundle JSON
- `X509SVIDPEM`：X.509-SVID 证书链 PEM
- `X509KeyPEM`：私钥 PEM
- `X509BundlePEM`：X.509 bundle PEM

刷新说明：

- 如果你使用 `Data`，那么刷新机制仍然生效，但每次读到的都是同一份静态内存内容
- 如果你希望 SDK 随着上层内存变化而刷新到最新值，应该使用 `Loader`

### 4.2 磁盘来源

```go
type DiskSource struct {
    JWTSVIDTokenPath  string
    JWTBundleJSONPath string
    X509SVIDPEMPath   string
    X509KeyPEMPath    string
    X509BundlePEMPath string
}
```

格式要求：

- `JWTSVIDTokenPath`：JWT token 文件
- `JWTBundleJSONPath`：JWT bundle JSON 文件
- `X509SVIDPEMPath`：X.509-SVID 证书链 PEM 文件
- `X509KeyPEMPath`：私钥 PEM 文件
- `X509BundlePEMPath`：X.509 bundle PEM 文件

## 5. 常见使用方式

### 5.1 从 SPIRE agent 加载

```go
helper, err := cishelper.NewHelper(ctx, cishelper.Config{
    RefreshInterval: 20 * time.Second,
    TrustDomain:     "example.org",
    Source: cishelper.SourceConfig{
        AgentAddress: "unix:///run/spire/sockets/agent.sock",
    },
    JWT: cishelper.JWTConfig{
        Audiences: []string{"demo-service"},
    },
    TLSMode: cishelper.TLSModeMTLS,
})
```

### 5.2 从磁盘加载

```go
helper, err := cishelper.NewHelper(ctx, cishelper.Config{
    TrustDomain: "example.org",
    Source: cishelper.SourceConfig{
        Disk: &cishelper.DiskSource{
            JWTSVIDTokenPath:  "./out/jwt-svid.token",
            JWTBundleJSONPath: "./out/example.org-jwt-bundle.json",
            X509SVIDPEMPath:   "./out/svid-cert.pem",
            X509KeyPEMPath:    "./out/svid-key.pem",
            X509BundlePEMPath: "./out/example.org-bundle.pem",
        },
    },
    JWT: cishelper.JWTConfig{
        Audiences: []string{"demo-service"},
    },
})
```

### 5.3 从内存加载

```go
helper, err := cishelper.NewHelper(ctx, cishelper.Config{
    TrustDomain: "example.org",
    Source: cishelper.SourceConfig{
        Memory: &cishelper.MemorySource{
            Data: &cishelper.MemoryIdentityData{
                JWTSVIDToken:  jwtToken,
                JWTBundleJSON: jwtBundleJSON,
                X509SVIDPEM:   x509CertPEM,
                X509KeyPEM:    x509KeyPEM,
                X509BundlePEM: x509BundlePEM,
            },
        },
    },
    JWT: cishelper.JWTConfig{
        Audiences: []string{"demo-service"},
    },
})
```

### 5.4 从动态内存加载

```go
helper, err := cishelper.NewHelper(ctx, cishelper.Config{
    TrustDomain: "example.org",
    Source: cishelper.SourceConfig{
        Memory: &cishelper.MemorySource{
            Loader: func() (*cishelper.MemoryIdentityData, error) {
                return currentIdentitySnapshot(), nil
            },
        },
    },
    JWT: cishelper.JWTConfig{
        Audiences: []string{"demo-service"},
    },
})
```

这种模式下，只要 `currentIdentitySnapshot()` 返回的是最新内存数据，SDK 后台刷新就能更新缓存。

## 6. 对外接口

### 6.1 GetJWTSVID

```go
jwtSVID, err := helper.GetJWTSVID()
```

返回按 `Config.JWT` 配置生成并缓存的 JWT-SVID。

### 6.2 GetJWTBundle

```go
jwtBundles, err := helper.GetJWTBundle()
```

- 如果配置了 `TrustDomain`，返回对应 trust domain 的 JWT bundle
- 如果未配置 `TrustDomain`，返回全部已缓存 JWT bundle

### 6.3 GetX509SVID

```go
x509SVID, err := helper.GetX509SVID()
```

返回：

- 叶子证书
- 可发送给对端的证书链，包含 leaf 和 intermediate，不包含 root
- 私钥

### 6.4 GetX509Bundle

```go
x509Bundles, err := helper.GetX509Bundle()
```

行为和 `GetJWTBundle` 类似。

### 6.5 GetTlsConfig

```go
tlsConfig, err := helper.GetTlsConfig()
```

用途：

- `mtls`：构建可同时用于客户端和服务端的 mTLS `tls.Config`
- `one_way_tls`：构建可同时用于客户端和服务端的单向 TLS `tls.Config`

说明：

- `GetTlsConfig` 会使用本地缓存的 X.509-SVID 证书链和 X.509 bundle
- 返回的 `tls.Config` 同时包含动态证书回调和动态对端校验逻辑
- 当后台刷新成功后，后续 TLS 握手会自动使用刷新后的证书和 bundle
- 在 mTLS 模式下，SDK 会把 leaf + intermediate 一并作为握手证书发送给对端
- 在 mTLS 模式下，服务端校验客户端证书、客户端校验服务端证书，都会使用当前缓存中的最新 bundle
- 如果对端仅信任 root，只要本地缓存里包含中间证书链，握手仍可成功

### 6.6 Close

```go
err := helper.Close()
```

作用：

- 停止后台刷新 goroutine
- 关闭底层来源相关资源

## 7. 刷新机制

SDK 刷新遵循以下规则：

1. `NewHelper` 时先完成一次全量加载
2. 后台定时任务按 `RefreshInterval` 触发刷新
3. 每次刷新都会重新加载 JWT-SVID、JWT bundle、X.509-SVID、X.509 bundle
4. 只有当这批数据全部成功获取后，才替换旧缓存
5. 如果刷新失败，旧缓存保持可用

## 8. Demo 使用说明

仓库内有三个示例：

- `cmd/fetch-svid`
- `cmd/https-server`
- `cmd/https-client`

### 8.1 fetch-svid

支持以下来源模式：

- `agent`
- `disk`
- `memory`
- `memory_over_disk`

环境变量：

- `CIS_HELPER_SOURCE_MODE`
- `CIS_HELPER_INPUT_DIR`
- `CIS_HELPER_OUTPUT_DIR`
- `CIS_HELPER_TRUST_DOMAIN`
- `CIS_HELPER_JWT_AUDIENCE`
- `CIS_HELPER_JWT_AUDIENCES`
- `CIS_HELPER_AGENT_UDS`

示例：

```sh
CIS_HELPER_SOURCE_MODE=agent go run ./cmd/fetch-svid
```

```sh
CIS_HELPER_SOURCE_MODE=disk CIS_HELPER_INPUT_DIR=./out go run ./cmd/fetch-svid
```

```sh
CIS_HELPER_SOURCE_MODE=memory CIS_HELPER_INPUT_DIR=./out go run ./cmd/fetch-svid
```

```sh
CIS_HELPER_SOURCE_MODE=memory_over_disk CIS_HELPER_INPUT_DIR=./out go run ./cmd/fetch-svid
```

输出目录内容：

- `svid-cert.pem`
- `svid-key.pem`
- `<trust-domain>-bundle.pem`
- `jwt-svid.token`
- `<trust-domain>-jwt-bundle.json`

### 8.2 https-server

`https-server` 直接复用 `helper.GetTlsConfig()` 返回的动态 `tls.Config`。
当 SDK 后台刷新成功后，服务端后续握手会自动使用刷新后的证书和对端校验逻辑。

额外支持：

- `CIS_HELPER_HTTPS_SERVER_IP`
- `CIS_HELPER_HTTPS_SERVER_PORT`
- `CIS_HELPER_PPROF_IP`
- `CIS_HELPER_PPROF_PORT`

`pprof` 地址：

```text
http://127.0.0.1:6060/debug/pprof/
```

### 8.3 https-client

`https-client` 同样直接复用 `helper.GetTlsConfig()` 返回的动态 `tls.Config`。
当 SDK 后台刷新成功后，客户端后续握手会自动使用刷新后的证书和服务端校验逻辑。

额外支持：

- `CIS_HELPER_HTTPS_CLIENT_IP`
- `CIS_HELPER_HTTPS_CLIENT_PORT`

## 9. 推荐接入建议

- 如果你已经有落盘产物，优先使用 `DiskSource`
- 如果你的上层系统已经把身份材料管理在内存中，优先使用 `MemorySource`
- 如果你希望完全对齐 SPIRE agent 的动态获取方式，使用 `Source.AgentAddress`
- 如果需要 bundle 精确返回，建议显式配置 `TrustDomain`
- 如果需要稳定获取 JWT-SVID，建议显式配置 `JWT.Audiences`

## 10. 验证

建议使用以下命令做回归验证：

```sh
go test ./...
```
