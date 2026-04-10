package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	spiffetlsconfig "github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com:spring-zhao/cis-helper/internal/api"
	"github.com:spring-zhao/cis-helper/internal/cache"
	"github.com:spring-zhao/cis-helper/internal/localsource"
	"github.com:spring-zhao/cis-helper/internal/observability"
	"github.com:spring-zhao/cis-helper/internal/runtime"
	"github.com:spring-zhao/cis-helper/internal/workloadclient"
)

type identityFetcher interface {
	FetchJWTSVID(context.Context, jwtsvid.Params) (*jwtsvid.SVID, error)
	FetchJWTBundles(context.Context) (*jwtbundle.Set, error)
	FetchX509SVID(context.Context) (*x509svid.SVID, error)
	FetchX509Bundles(context.Context) (*x509bundle.Set, error)
	Close() error
}

type Helper struct {
	cfg     api.Config
	logger  Logger
	metrics observability.Recorder
	fetcher identityFetcher
	source  string

	mu      sync.RWMutex
	closed  bool
	state   *cache.State
	closeCh chan struct{}
	doneCh  chan struct{}
}

type Logger interface {
	Info(string, ...any)
	Error(string, ...any)
}

func New(ctx context.Context, cfg api.Config, version string) (*Helper, error) {
	cfg = withDefaults(cfg)
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	logger := observability.WithLoggerDefaults(cfg.Logger, "cis-helper", version)
	metrics := observability.NewRecorder(version, cfg.Metrics)

	fetcher, sourceName, err := newIdentityFetcher(ctx, cfg, logger, metrics)
	if err != nil {
		return nil, err
	}

	h := &Helper{
		cfg:     cfg,
		logger:  logger,
		metrics: metrics,
		fetcher: fetcher,
		source:  sourceName,
		state: &cache.State{
			JWTSVIDs:    make(map[string]*jwtsvid.SVID),
			JWTRequests: make(map[string]jwtsvid.Params),
		},
		closeCh: make(chan struct{}),
		doneCh:  make(chan struct{}),
	}

	initialJWTParams, err := toJWTSVIDParams(cfg)
	if err != nil {
		_ = fetcher.Close()
		return nil, err
	}
	h.registerJWTRequests([]jwtsvid.Params{initialJWTParams})

	if err := h.refreshAndSwap(ctx); err != nil {
		_ = fetcher.Close()
		return nil, api.WrapError(api.CodeInitialRefresh, "initial identity refresh failed", err)
	}

	go h.refreshLoop()

	logger.Info("helper initialized", "source", sourceName, "agent_address", cfg.Source.AgentAddress, "trust_domain", cfg.TrustDomain, "refresh_interval", cfg.RefreshInterval, "tls_mode", string(cfg.TLSMode))
	metrics.Event("helper_initialized", "success", map[string]string{"source": sourceName})
	return h, nil
}

func newIdentityFetcher(ctx context.Context, cfg api.Config, logger Logger, metrics observability.Recorder) (identityFetcher, string, error) {
	switch {
	case cfg.Source.Memory != nil:
		fetcher, err := localsource.NewMemory(cfg)
		if err != nil {
			metrics.Error("new_helper", api.CodeInvalidConfig, err)
			logger.Error("configure memory source failed", "code", api.CodeInvalidConfig, "error", err)
			return nil, "", err
		}
		return fetcher, "memory", nil
	case cfg.Source.Disk != nil:
		fetcher, err := localsource.NewDisk(cfg)
		if err != nil {
			metrics.Error("new_helper", api.CodeInvalidConfig, err)
			logger.Error("configure disk source failed", "code", api.CodeInvalidConfig, "error", err)
			return nil, "", err
		}
		return fetcher, "disk", nil
	default:
		clientCtx, cancel := context.WithTimeout(ctx, cfg.RequestTimeout)
		defer cancel()

		client, err := workloadclient.New(clientCtx, cfg.Source.AgentAddress)
		if err != nil {
			metrics.Error("new_helper", api.CodeConnectAgent, err)
			logger.Error("connect spire agent failed", "code", api.CodeConnectAgent, "agent_address", cfg.Source.AgentAddress, "error", err)
			return nil, "", api.WrapError(api.CodeConnectAgent, "connect spire agent failed", err)
		}
		return client, "spire_agent", nil
	}
}

func (h *Helper) GetJWTSVID() (*jwtsvid.SVID, error) {
	start := time.Now()
	params, err := toJWTSVIDParams(h.cfg)
	if err != nil {
		h.finishAPICall("get_jwt_svid", start, err)
		return nil, err
	}

	key := jwtRequestKey(params)
	h.logger.Info("GetJWTSVID called", "jwt_request_key", key)

	h.mu.RLock()
	if h.closed {
		h.mu.RUnlock()
		err = api.WrapError(api.CodeClosed, "helper already closed", nil)
		h.finishAPICall("get_jwt_svid", start, err)
		return nil, err
	}
	cached := h.state.JWTSVIDs[key]
	h.mu.RUnlock()

	if cached != nil && cached.Expiry.After(time.Now()) {
		h.finishAPICall("get_jwt_svid", start, nil)
		return cached, nil
	}

	err = api.WrapError(api.CodeJWTSVIDNotCached, fmt.Sprintf("JWT-SVID for request %s not found in cache or has expired", key), nil)
	h.finishAPICall("get_jwt_svid", start, err)
	return nil, err
}

func (h *Helper) GetJWTBundle() (*api.JWTBundleSet, error) {
	start := time.Now()
	h.logger.Info("GetJWTBundle called", "trust_domain", h.cfg.TrustDomain)

	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.closed {
		err := api.WrapError(api.CodeClosed, "helper already closed", nil)
		h.finishAPICall("get_jwt_bundle", start, err)
		return nil, err
	}
	if h.state.JWTBundles == nil {
		err := api.WrapError(api.CodeJWTBundlesNotCached, "JWT bundles are not cached", nil)
		h.finishAPICall("get_jwt_bundle", start, err)
		return nil, err
	}

	out := &api.JWTBundleSet{Bundles: map[string][]byte{}}
	if h.cfg.TrustDomain != "" {
		trustDomain, err := spiffeid.TrustDomainFromString(h.cfg.TrustDomain)
		if err != nil {
			err = api.WrapError(api.CodeInvalidConfig, "trust domain is invalid", err)
			h.finishAPICall("get_jwt_bundle", start, err)
			return nil, err
		}
		bundle, err := h.state.JWTBundles.GetJWTBundleForTrustDomain(trustDomain)
		if err != nil {
			err = api.WrapError(api.CodeJWTBundlesNotCached, "JWT bundle for trust domain is not cached", err)
			h.finishAPICall("get_jwt_bundle", start, err)
			return nil, err
		}
		raw, err := bundle.Marshal()
		if err != nil {
			err = api.WrapError(api.CodeJWTBundlesNotCached, "marshal JWT bundle failed", err)
			h.finishAPICall("get_jwt_bundle", start, err)
			return nil, err
		}
		out.Bundles[trustDomain.String()] = raw
	} else {
		for _, bundle := range h.state.JWTBundles.Bundles() {
			raw, err := bundle.Marshal()
			if err != nil {
				err = api.WrapError(api.CodeJWTBundlesNotCached, "marshal JWT bundle failed", err)
				h.finishAPICall("get_jwt_bundle", start, err)
				return nil, err
			}
			out.Bundles[bundle.TrustDomain().String()] = raw
		}
	}

	h.finishAPICall("get_jwt_bundle", start, nil)
	return out, nil
}

func (h *Helper) VerifyToken(token string, trustedLabel string) error {
	start := time.Now()
	h.logger.Info("VerifyToken called", "trusted_label", trustedLabel)

	h.mu.RLock()
	closed := h.closed
	jwtBundles := h.state.JWTBundles
	h.mu.RUnlock()

	if closed {
		err := api.WrapError(api.CodeClosed, "helper already closed", nil)
		h.finishAPICall("verify_token", start, err)
		return err
	}
	if jwtBundles == nil {
		err := api.WrapError(api.CodeJWTBundlesNotCached, "JWT bundles are not cached", nil)
		h.finishAPICall("verify_token", start, err)
		return err
	}
	if strings.TrimSpace(token) == "" {
		err := api.WrapError(api.CodeJWTTokenInvalid, "token must not be empty", nil)
		h.finishAPICall("verify_token", start, err)
		return err
	}

	svid, err := jwtsvid.ParseAndValidate(token, jwtBundles, nil)
	if err != nil {
		err = api.WrapError(api.CodeJWTTokenInvalid, "token validation failed", err)
		h.finishAPICall("verify_token", start, err)
		return err
	}

	if trustedLabel != "" {
		subjectLabel, err := trustedLabelFromSPIFFEID(svid.ID)
		if err != nil {
			err = api.WrapError(api.CodeJWTTokenInvalid, "token subject label is invalid", err)
			h.finishAPICall("verify_token", start, err)
			return err
		}
		if subjectLabel != trustedLabel {
			err = api.WrapError(api.CodeJWTTokenInvalid, fmt.Sprintf("token subject label %q does not match trusted label %q", subjectLabel, trustedLabel), nil)
			h.finishAPICall("verify_token", start, err)
			return err
		}
	}

	h.finishAPICall("verify_token", start, nil)
	return nil
}

func (h *Helper) GetX509SVID() (*api.X509SVID, error) {
	start := time.Now()
	h.logger.Info("GetX509SVID called")

	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.closed {
		err := api.WrapError(api.CodeClosed, "helper already closed", nil)
		h.finishAPICall("get_x509_svid", start, err)
		return nil, err
	}
	if h.state.X509SVID == nil {
		err := api.WrapError(api.CodeX509SVIDNotCached, "X509-SVID is not cached", nil)
		h.finishAPICall("get_x509_svid", start, err)
		return nil, err
	}
	if len(h.state.X509SVID.Certificates) == 0 {
		err := api.WrapError(api.CodeX509SVIDNotCached, "X509-SVID certificate chain is empty", nil)
		h.finishAPICall("get_x509_svid", start, err)
		return nil, err
	}

	chain := sanitizePresentedChain(h.state.X509SVID.Certificates)
	leaf := chain[0]
	h.finishAPICall("get_x509_svid", start, nil)
	return &api.X509SVID{
		ID:         h.state.X509SVID.ID.String(),
		Cert:       leaf,
		Chain:      append([]*x509.Certificate(nil), chain...),
		PrivateKey: h.state.X509SVID.PrivateKey,
		Hint:       h.state.X509SVID.Hint,
	}, nil
}

func (h *Helper) GetX509Bundle() (*api.X509BundleSet, error) {
	start := time.Now()
	h.logger.Info("GetX509Bundle called", "trust_domain", h.cfg.TrustDomain)

	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.closed {
		err := api.WrapError(api.CodeClosed, "helper already closed", nil)
		h.finishAPICall("get_x509_bundle", start, err)
		return nil, err
	}
	if h.state.X509Bundles == nil {
		err := api.WrapError(api.CodeX509BundleNotCached, "X509 bundle is not cached", nil)
		h.finishAPICall("get_x509_bundle", start, err)
		return nil, err
	}

	out := &api.X509BundleSet{Bundles: map[string][]*x509.Certificate{}}
	if h.cfg.TrustDomain != "" {
		trustDomain, err := spiffeid.TrustDomainFromString(h.cfg.TrustDomain)
		if err != nil {
			err = api.WrapError(api.CodeInvalidConfig, "trust domain is invalid", err)
			h.finishAPICall("get_x509_bundle", start, err)
			return nil, err
		}
		bundle, err := h.state.X509Bundles.GetX509BundleForTrustDomain(trustDomain)
		if err != nil {
			err = api.WrapError(api.CodeX509BundleNotCached, "X509 bundle for trust domain is not cached", err)
			h.finishAPICall("get_x509_bundle", start, err)
			return nil, err
		}
		out.Bundles[trustDomain.String()] = bundle.X509Authorities()
	} else {
		for _, bundle := range h.state.X509Bundles.Bundles() {
			out.Bundles[bundle.TrustDomain().String()] = bundle.X509Authorities()
		}
	}

	h.finishAPICall("get_x509_bundle", start, nil)
	return out, nil
}

func (h *Helper) GetTLSConfig() (*tls.Config, error) {
	start := time.Now()
	h.logger.Info("GetTlsConfig called", "tls_mode", string(h.cfg.TLSMode))

	h.mu.RLock()
	closed := h.closed
	x509SVID := h.state.X509SVID
	x509Bundles := h.state.X509Bundles
	h.mu.RUnlock()

	if closed {
		err := api.WrapError(api.CodeClosed, "helper already closed", nil)
		h.finishAPICall("get_tls_config", start, err)
		return nil, err
	}
	if x509SVID == nil {
		err := api.WrapError(api.CodeX509SVIDNotCached, "X509-SVID is not cached", nil)
		h.finishAPICall("get_tls_config", start, err)
		return nil, err
	}
	if h.cfg.TLSMode == api.TLSModeMTLS && x509Bundles == nil {
		err := api.WrapError(api.CodeX509BundleNotCached, "X509 bundle is not cached", nil)
		h.finishAPICall("get_tls_config", start, err)
		return nil, err
	}

	x509Source := helperX509Source{helper: h}
	bundleSource := helperX509BundleSource{helper: h}

	tlsCfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: spiffetlsconfig.GetCertificate(x509Source),
	}

	if h.cfg.TLSMode == api.TLSModeOneWay {
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.GetClientCertificate = spiffetlsconfig.GetClientCertificate(x509Source)
	} else {
		tlsCfg.ClientAuth = tls.RequireAnyClientCert
		tlsCfg.GetClientCertificate = spiffetlsconfig.GetClientCertificate(x509Source)
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.VerifyPeerCertificate = spiffetlsconfig.VerifyPeerCertificate(
			bundleSource,
			func(id spiffeid.ID, verifiedChains [][]*x509.Certificate) error {
				return h.cfg.TLSAuthorizer(id.String(), verifiedChains)
			},
		)
	}

	h.finishAPICall("get_tls_config", start, nil)
	return tlsCfg, nil
}

func (h *Helper) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	close(h.closeCh)
	h.mu.Unlock()

	<-h.doneCh

	err := h.fetcher.Close()
	if err != nil {
		h.logger.Error("close workload api client failed", "error", err)
		h.metrics.Error("close_helper", api.CodeClosed, err)
		return api.WrapError(api.CodeClosed, "close workload api client failed", err)
	}

	h.logger.Info("helper closed")
	h.metrics.Event("helper_closed", "success", nil)
	return nil
}

func (h *Helper) registerJWTRequests(paramsList []jwtsvid.Params) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, params := range paramsList {
		h.state.JWTRequests[jwtRequestKey(params)] = params
	}
}

func (h *Helper) finishAPICall(operation string, start time.Time, err error) {
	result := "success"
	labels := map[string]string{"operation": operation}
	if err != nil {
		result = "error"
		var coded *api.Error
		if errors.As(err, &coded) {
			labels["code"] = coded.Code
		}
		h.logger.Error("helper api call failed", "operation", operation, "duration", time.Since(start), "error", err)
		h.metrics.Error(operation, runtime.ErrorCode(err, api.CodeRefresh), err)
	} else {
		h.logger.Info("helper api call succeeded", "operation", operation, "duration", time.Since(start))
	}
	h.metrics.Duration(operation, result, time.Since(start), labels)
}

type helperX509Source struct{ helper *Helper }

func (s helperX509Source) GetX509SVID() (*x509svid.SVID, error) {
	s.helper.mu.RLock()
	defer s.helper.mu.RUnlock()
	if s.helper.closed {
		return nil, api.WrapError(api.CodeClosed, "helper already closed", nil)
	}
	if s.helper.state.X509SVID == nil {
		return nil, api.WrapError(api.CodeX509SVIDNotCached, "X509-SVID is not cached", nil)
	}
	if len(s.helper.state.X509SVID.Certificates) == 0 {
		return nil, api.WrapError(api.CodeX509SVIDNotCached, "X509-SVID certificate chain is empty", nil)
	}
	clone := *s.helper.state.X509SVID
	clone.Certificates = sanitizePresentedChain(s.helper.state.X509SVID.Certificates)
	return &clone, nil
}

type helperX509BundleSource struct{ helper *Helper }

func (s helperX509BundleSource) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	s.helper.mu.RLock()
	defer s.helper.mu.RUnlock()
	if s.helper.closed {
		return nil, api.WrapError(api.CodeClosed, "helper already closed", nil)
	}
	if s.helper.state.X509Bundles == nil {
		return nil, api.WrapError(api.CodeX509BundleNotCached, "X509 bundle is not cached", nil)
	}
	return s.helper.state.X509Bundles.GetX509BundleForTrustDomain(trustDomain)
}

func sanitizePresentedChain(certs []*x509.Certificate) []*x509.Certificate {
	if len(certs) == 0 {
		return nil
	}
	chain := append([]*x509.Certificate(nil), certs...)
	for len(chain) > 1 && isSelfSignedRoot(chain[len(chain)-1]) {
		chain = chain[:len(chain)-1]
	}
	return chain
}

func isSelfSignedRoot(cert *x509.Certificate) bool {
	if cert == nil || !cert.IsCA {
		return false
	}
	return bytes.Equal(cert.RawSubject, cert.RawIssuer)
}

func trustedLabelFromSPIFFEID(id spiffeid.ID) (string, error) {
	path := strings.TrimPrefix(id.Path(), "/")
	segments := strings.Split(path, "/")
	if len(segments) != 4 {
		return "", fmt.Errorf("unexpected subject path %q", id.Path())
	}
	if !strings.HasPrefix(segments[2], "k_") {
		return "", fmt.Errorf("unexpected ksn segment %q", segments[2])
	}
	ksn := strings.TrimPrefix(segments[2], "k_")
	if ksn == "" {
		return "", fmt.Errorf("ksn segment is empty")
	}
	if segments[3] == "" {
		return "", fmt.Errorf("instance id segment is empty")
	}
	return ksn + "/" + segments[3], nil
}
