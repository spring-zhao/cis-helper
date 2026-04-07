// Package cishelper provides a Go SDK for fetching SPIFFE workload identities
// from a SPIRE agent, caching them in memory, and exposing helper APIs for JWT,
// X.509, and TLS client configuration use cases.
package cishelper

import (
	"context"
	"crypto/tls"
	"log/slog"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"

	"git.corp.kuaishou.com/corpsec/nhi/cis-helper/internal/api"
	"git.corp.kuaishou.com/corpsec/nhi/cis-helper/internal/observability"
	"git.corp.kuaishou.com/corpsec/nhi/cis-helper/internal/service"
)

// Config configures helper initialization, identity loading, refresh behavior,
// and TLS generation.
//
// Source selection is grouped under Source. JWT-SVID request semantics are
// grouped under JWT.
//
// Defaults:
// - RefreshInterval: 20s
// - RequestTimeout: 10s
// - Source.AgentAddress: unix:///run/spire/sockets/agent.sock
// - JWT.Audiences: ["spire-server"]
// - TLSMode: mtls
//
// NewHelper only returns successfully after the initial JWT and X.509 data are
// fully loaded into cache.
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

// Metric is the public metric payload forwarded to the user-provided
// MetricsRecorder.
type Metric struct {
	Name     string
	Result   string
	Version  string
	Duration time.Duration
	Labels   map[string]string
}

// MetricsRecorder receives SDK metrics emitted by helper operations and refresh
// tasks.
type MetricsRecorder interface {
	Record(Metric)
}

// NopMetrics is a no-op MetricsRecorder implementation.
type NopMetrics struct{}

func (NopMetrics) Record(Metric) {}

// X509SVID is the public X.509 identity view returned by GetX509SVID.
type X509SVID = api.X509SVID

// SourceConfig groups all identity source configuration.
//
// Priority is fixed:
// 1. Memory
// 2. Disk
// 3. AgentAddress
//
// If a higher-priority source is configured, the SDK does not fall back to a
// lower-priority source when that source is invalid; NewHelper returns an
// error instead.
type SourceConfig = api.SourceConfig

// JWTConfig groups the parameters used to construct the Workload API
// JWTSVIDRequest represented by GetJWTSVID.
//
// Audiences maps to JWTSVIDRequest.audience. It determines which cached
// JWT-SVID the SDK loads, refreshes, and returns. When local sources are used,
// the same audience list is also used to parse the local JWT-SVID token.
//
// SPIFFEID maps to JWTSVIDRequest.spiffe_id. When set, the SDK requests a
// JWT-SVID for the specified SPIFFE ID instead of relying on the default
// workload identity.
type JWTConfig = api.JWTConfig

// MemorySource configures the highest-priority in-memory identity source.
//
// Use Data for a fixed in-memory snapshot.
// Use Loader when the underlying in-memory identity data can change over time
// and refresh should observe the latest values.
//
// During refresh:
// - Data behaves as a static snapshot
// - Loader is invoked on every refresh cycle
type MemorySource = api.MemorySource

// MemoryIdentityData is the in-memory identity payload used by MemorySource.
//
// Format rules:
// - JWTSVIDToken: raw JWT token string
// - JWTBundleJSON: raw JWT bundle JSON
// - X509SVIDPEM: X.509-SVID certificate chain PEM
// - X509KeyPEM: private key PEM
// - X509BundlePEM: X.509 bundle PEM
type MemoryIdentityData = api.MemoryIdentityData

// DiskSource configures the second-priority on-disk identity source.
//
// The files are re-read on each refresh, so updates on disk can be observed by
// the SDK without recreating the helper.
type DiskSource = api.DiskSource

// JWTBundleSet is the public JWT bundle view returned by GetJWTBundle.
type JWTBundleSet = api.JWTBundleSet

// X509BundleSet is the public X.509 bundle view returned by GetX509Bundle.
type X509BundleSet = api.X509BundleSet

// TLSMode controls how GetTlsConfig verifies the remote peer.
type TLSMode = api.TLSMode

const (
	TLSModeMTLS   = api.TLSModeMTLS
	TLSModeOneWay = api.TLSModeOneWay
)

// PeerAuthorizer runs after SPIFFE certificate validation in mtls mode and can
// apply application-specific authorization rules to the peer.
type PeerAuthorizer = api.PeerAuthorizer

// AuthorizeAnyPeer accepts any peer after SPIFFE verification.
func AuthorizeAnyPeer() PeerAuthorizer {
	return api.AuthorizeAnyPeer()
}

const (
	CodeInvalidConfig       = api.CodeInvalidConfig
	CodeConnectAgent        = api.CodeConnectAgent
	CodeInitialRefresh      = api.CodeInitialRefresh
	CodeRefresh             = api.CodeRefresh
	CodeClosed              = api.CodeClosed
	CodeJWTSVIDNotCached    = api.CodeJWTSVIDNotCached
	CodeX509SVIDNotCached   = api.CodeX509SVIDNotCached
	CodeJWTBundlesNotCached = api.CodeJWTBundlesNotCached
	CodeX509BundleNotCached = api.CodeX509BundleNotCached
	CodeJWTTokenInvalid     = api.CodeJWTTokenInvalid
)

// Error is the public SDK error type. Callers can inspect Code to classify
// failures.
type Error = api.Error

// Helper is the public SDK handle returned by NewHelper.
type Helper struct {
	impl *service.Helper
}

// NewHelper creates a helper, performs the initial fetch against the SPIRE
// agent, and starts the background refresh loop.
func NewHelper(ctx context.Context, cfg Config) (*Helper, error) {
	impl, err := service.New(ctx, api.Config{
		RefreshInterval: cfg.RefreshInterval,
		RequestTimeout:  cfg.RequestTimeout,
		TrustDomain:     cfg.TrustDomain,
		Source:          cloneSourceConfig(cfg.Source),
		JWT:             cloneJWTConfig(cfg.JWT),
		TLSMode:         api.TLSMode(cfg.TLSMode),
		TLSAuthorizer:   api.PeerAuthorizer(cfg.TLSAuthorizer),
		Logger:          cfg.Logger,
		Metrics:         metricsAdapter{sink: cfg.Metrics},
	}, version)
	if err != nil {
		return nil, err
	}
	return &Helper{impl: impl}, nil
}

// GetJWTSVID returns the cached JWT-SVID selected by Config.JWT.
func (h *Helper) GetJWTSVID() (*jwtsvid.SVID, error) {
	return h.impl.GetJWTSVID()
}

// GetJWTBundle returns cached JWT bundles. When Config.TrustDomain is set, the
// result is scoped to that trust domain; otherwise all cached bundles are
// returned.
func (h *Helper) GetJWTBundle() (*JWTBundleSet, error) {
	return h.impl.GetJWTBundle()
}

// GetX509SVID returns the cached X.509-SVID leaf certificate, presented chain,
// and private key.
func (h *Helper) GetX509SVID() (*X509SVID, error) {
	return h.impl.GetX509SVID()
}

// GetX509Bundle returns cached X.509 bundles. When Config.TrustDomain is set,
// the result is scoped to that trust domain; otherwise all cached bundles are
// returned.
func (h *Helper) GetX509Bundle() (*X509BundleSet, error) {
	return h.impl.GetX509Bundle()
}

// GetTlsConfig builds a client tls.Config backed by cached X.509 material.
func (h *Helper) GetTlsConfig() (*tls.Config, error) {
	return h.impl.GetTLSConfig()
}

// VerifyToken validates a JWT token against cached JWT bundles. When
// trustedLabel is non-empty, the label extracted from the token subject path
// must match it exactly.
func (h *Helper) VerifyToken(token string, trustedLabel string) error {
	return h.impl.VerifyToken(token, trustedLabel)
}

// Close stops background refresh and releases SDK resources.
func (h *Helper) Close() error {
	return h.impl.Close()
}

type metricsAdapter struct {
	sink MetricsRecorder
}

func (a metricsAdapter) Record(metric observability.Metric) {
	if a.sink == nil {
		return
	}
	a.sink.Record(Metric{
		Name:     metric.Name,
		Result:   metric.Result,
		Version:  metric.Version,
		Duration: metric.Duration,
		Labels:   cloneLabels(metric.Labels),
	})
}

func cloneLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		out[k] = v
	}
	return out
}

func cloneMemorySource(src *MemorySource) *api.MemorySource {
	if src == nil {
		return nil
	}
	return &api.MemorySource{
		Data:   cloneMemoryIdentityData(src.Data),
		Loader: src.Loader,
	}
}

func cloneSourceConfig(src SourceConfig) api.SourceConfig {
	return api.SourceConfig{
		AgentAddress: src.AgentAddress,
		Memory:       cloneMemorySource(src.Memory),
		Disk:         cloneDiskSource(src.Disk),
	}
}

func cloneJWTConfig(src JWTConfig) api.JWTConfig {
	return api.JWTConfig{
		Audiences: append([]string(nil), src.Audiences...),
		SPIFFEID:  src.SPIFFEID,
	}
}

func cloneMemoryIdentityData(data *MemoryIdentityData) *api.MemoryIdentityData {
	if data == nil {
		return nil
	}
	return &api.MemoryIdentityData{
		JWTSVIDToken:  data.JWTSVIDToken,
		JWTBundleJSON: append([]byte(nil), data.JWTBundleJSON...),
		X509SVIDPEM:   append([]byte(nil), data.X509SVIDPEM...),
		X509KeyPEM:    append([]byte(nil), data.X509KeyPEM...),
		X509BundlePEM: append([]byte(nil), data.X509BundlePEM...),
	}
}

func cloneDiskSource(src *DiskSource) *api.DiskSource {
	if src == nil {
		return nil
	}
	return &api.DiskSource{
		JWTSVIDTokenPath:  src.JWTSVIDTokenPath,
		JWTBundleJSONPath: src.JWTBundleJSONPath,
		X509SVIDPEMPath:   src.X509SVIDPEMPath,
		X509KeyPEMPath:    src.X509KeyPEMPath,
		X509BundlePEMPath: src.X509BundlePEMPath,
	}
}
