package service

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	gojwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"git.corp.kuaishou.com/corpsec/nhi/cis-helper/internal/api"
	"git.corp.kuaishou.com/corpsec/nhi/cis-helper/internal/cache"
	"git.corp.kuaishou.com/corpsec/nhi/cis-helper/internal/observability"
)

func TestRefreshFailureKeepsOldCache(t *testing.T) {
	cfg := api.Config{JWT: api.JWTConfig{Audiences: []string{"service-a"}}}
	params, err := toJWTSVIDParams(cfg)
	if err != nil {
		t.Fatalf("toJWTSVIDParams failed: %v", err)
	}
	fetcher := &fakeFetcher{
		x509:       &x509svid.SVID{},
		x509Bundle: x509bundle.NewSet(),
		jwtBundles: jwtbundle.NewSet(jwtbundle.New(spiffeid.RequireTrustDomainFromString("example.org"))),
		jwtSVIDs: map[string]*jwtsvid.SVID{
			jwtRequestKey(params): {Audience: []string{"service-a"}, Expiry: time.Now().Add(time.Minute)},
		},
	}

	helper := newTestHelper(fetcher, cfg)

	before, err := helper.GetJWTSVID()
	if err != nil {
		t.Fatalf("GetJWTSVID before refresh failed: %v", err)
	}

	fetcher.jwtErr = errors.New("boom")

	if err := helper.refreshAndSwap(context.Background()); err == nil {
		t.Fatal("expected refresh failure")
	}

	after, err := helper.GetJWTSVID()
	if err != nil {
		t.Fatalf("GetJWTSVID after refresh failed: %v", err)
	}

	if before != after {
		t.Fatal("expected cached JWT-SVID to remain unchanged after failed refresh")
	}
}

func TestGetJWTSVIDReturnsConfiguredCachedValue(t *testing.T) {
	cfg := api.Config{JWT: api.JWTConfig{Audiences: []string{"service-a"}}}
	params, _ := toJWTSVIDParams(cfg)

	fetcher := &fakeFetcher{
		x509:       &x509svid.SVID{},
		x509Bundle: x509bundle.NewSet(),
		jwtBundles: jwtbundle.NewSet(jwtbundle.New(spiffeid.RequireTrustDomainFromString("example.org"))),
		jwtSVIDs: map[string]*jwtsvid.SVID{
			jwtRequestKey(params): {Audience: []string{"service-a"}, Expiry: time.Now().Add(time.Minute)},
		},
	}

	helper := newTestHelper(fetcher, cfg)

	got, err := helper.GetJWTSVID()
	if err != nil {
		t.Fatalf("GetJWTSVID failed: %v", err)
	}
	if got == nil || len(got.Audience) != 1 || got.Audience[0] != "service-a" {
		t.Fatalf("unexpected JWT-SVID: %#v", got)
	}
}

func TestValidateConfigAllowsEmptyTrustDomain(t *testing.T) {
	cfg := withDefaults(api.Config{})
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("expected config validation success, got %v", err)
	}
}

func TestNormalizeJWTRequestDefaultsAudience(t *testing.T) {
	audiences, err := normalizeJWTAudiences(nil)
	if err != nil {
		t.Fatalf("normalizeJWTAudiences failed: %v", err)
	}
	if len(audiences) != 1 || audiences[0] != defaultJWTAudience {
		t.Fatalf("expected default audience %q, got %#v", defaultJWTAudience, audiences)
	}
}

func TestGetX509SVIDReturnsFullCertificateChain(t *testing.T) {
	leaf := &x509.Certificate{Raw: []byte("leaf")}
	intermediate := &x509.Certificate{Raw: []byte("intermediate")}
	root := &x509.Certificate{
		Raw:      []byte("root"),
		IsCA:     true,
		Subject:  pkix.Name{CommonName: "root"},
		Issuer:   pkix.Name{CommonName: "root"},
		KeyUsage: x509.KeyUsageCertSign,
	}
	fetcher := &fakeFetcher{
		x509: &x509svid.SVID{
			Certificates: []*x509.Certificate{leaf, intermediate, root},
		},
		x509Bundle: x509bundle.NewSet(),
		jwtBundles: jwtbundle.NewSet(jwtbundle.New(spiffeid.RequireTrustDomainFromString("example.org"))),
		jwtSVIDs: map[string]*jwtsvid.SVID{
			jwtRequestKey(mustJWTParams(t, api.Config{JWT: api.JWTConfig{Audiences: []string{"service-a"}}})): {Audience: []string{"service-a"}, Expiry: time.Now().Add(time.Minute)},
		},
	}

	helper := newTestHelper(fetcher, api.Config{JWT: api.JWTConfig{Audiences: []string{"service-a"}}})
	got, err := helper.GetX509SVID()
	if err != nil {
		t.Fatalf("GetX509SVID failed: %v", err)
	}
	if got.Cert != leaf {
		t.Fatalf("expected leaf certificate to be returned as Cert")
	}
	if len(got.Chain) != 2 {
		t.Fatalf("expected leaf and intermediate only, got %d certs", len(got.Chain))
	}
	if got.Chain[0] != leaf || got.Chain[1] != intermediate {
		t.Fatalf("unexpected chain order: %#v", got.Chain)
	}
}

func TestHelperX509SourceStripsSelfSignedRootFromPresentedChain(t *testing.T) {
	leaf := &x509.Certificate{Raw: []byte("leaf")}
	intermediate := &x509.Certificate{Raw: []byte("intermediate")}
	root := &x509.Certificate{
		Raw:      []byte("root"),
		IsCA:     true,
		Subject:  pkix.Name{CommonName: "root"},
		Issuer:   pkix.Name{CommonName: "root"},
		KeyUsage: x509.KeyUsageCertSign,
	}
	helper := &Helper{
		state: &cache.State{
			X509SVID: &x509svid.SVID{
				Certificates: []*x509.Certificate{leaf, intermediate, root},
			},
		},
	}

	got, err := (helperX509Source{helper: helper}).GetX509SVID()
	if err != nil {
		t.Fatalf("GetX509SVID source failed: %v", err)
	}
	if len(got.Certificates) != 2 {
		t.Fatalf("expected root-stripped presented chain, got %d certs", len(got.Certificates))
	}
	if got.Certificates[0] != leaf || got.Certificates[1] != intermediate {
		t.Fatalf("unexpected presented chain order: %#v", got.Certificates)
	}
}

func TestGetTLSConfigIncludesDynamicServerAndClientHooksForMTLS(t *testing.T) {
	cfg := api.Config{
		TLSMode: api.TLSModeMTLS,
		TLSAuthorizer: func(string, [][]*x509.Certificate) error {
			return nil
		},
	}
	helper := &Helper{
		cfg:     cfg,
		logger:  observability.WithLoggerDefaults(nil, "cis-helper", "test"),
		metrics: observability.NewRecorder("test", nil),
		state: &cache.State{
			X509SVID:    &x509svid.SVID{Certificates: []*x509.Certificate{{Raw: []byte("leaf")}}},
			X509Bundles: x509bundle.NewSet(),
		},
	}

	got, err := helper.GetTLSConfig()
	if err != nil {
		t.Fatalf("GetTLSConfig failed: %v", err)
	}
	if got.GetCertificate == nil {
		t.Fatal("expected dynamic server certificate callback")
	}
	if got.GetClientCertificate == nil {
		t.Fatal("expected dynamic client certificate callback")
	}
	if got.VerifyPeerCertificate == nil {
		t.Fatal("expected dynamic peer verification callback")
	}
	if got.ClientAuth != tls.RequireAnyClientCert {
		t.Fatalf("expected ClientAuth=%v, got %v", tls.RequireAnyClientCert, got.ClientAuth)
	}
	if !got.InsecureSkipVerify {
		t.Fatal("expected InsecureSkipVerify for SPIFFE peer verification flow")
	}
}

func TestVerifyTokenAcceptsValidTokenWithoutTrustedLabel(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	token := makeSignedToken(t, "kid-1", "spiffe://example.org/p_test/r_demo/k_ksn001/instance-1", time.Now().Add(time.Minute))
	helper := newTokenTestHelper(td, map[string]crypto.PublicKey{"kid-1": token.publicKey})

	if err := helper.VerifyToken(token.serialized, ""); err != nil {
		t.Fatalf("VerifyToken failed: %v", err)
	}
}

func TestVerifyTokenRejectsTrustedLabelMismatch(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	token := makeSignedToken(t, "kid-1", "spiffe://example.org/p_test/r_demo/k_ksn001/instance-1", time.Now().Add(time.Minute))
	helper := newTokenTestHelper(td, map[string]crypto.PublicKey{"kid-1": token.publicKey})

	err := helper.VerifyToken(token.serialized, "ksn002/instance-1")
	if err == nil {
		t.Fatal("expected trusted label mismatch")
	}
}

func TestVerifyTokenRejectsExpiredToken(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	token := makeSignedToken(t, "kid-1", "spiffe://example.org/p_test/r_demo/k_ksn001/instance-1", time.Now().Add(-time.Minute))
	helper := newTokenTestHelper(td, map[string]crypto.PublicKey{"kid-1": token.publicKey})

	err := helper.VerifyToken(token.serialized, "ksn001/instance-1")
	if err == nil {
		t.Fatal("expected expired token error")
	}
}

func TestVerifyTokenRejectsSignatureMismatch(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	token := makeSignedToken(t, "kid-1", "spiffe://example.org/p_test/r_demo/k_ksn001/instance-1", time.Now().Add(time.Minute))
	other := makeSignedToken(t, "kid-1", "spiffe://example.org/p_test/r_demo/k_ksn001/instance-1", time.Now().Add(time.Minute))
	helper := newTokenTestHelper(td, map[string]crypto.PublicKey{"kid-1": other.publicKey})

	err := helper.VerifyToken(token.serialized, "ksn001/instance-1")
	if err == nil {
		t.Fatal("expected signature mismatch error")
	}
}

func TestRefreshKeepsConfiguredJWTCacheSizeStable(t *testing.T) {
	cfg := api.Config{JWT: api.JWTConfig{Audiences: []string{"service-a"}}}
	params := mustJWTParams(t, cfg)
	fetcher := &fakeFetcher{
		x509:       &x509svid.SVID{},
		x509Bundle: x509bundle.NewSet(),
		jwtBundles: jwtbundle.NewSet(jwtbundle.New(spiffeid.RequireTrustDomainFromString("example.org"))),
		jwtSVIDs: map[string]*jwtsvid.SVID{
			jwtRequestKey(params): {Audience: []string{"service-a"}, Expiry: time.Now().Add(time.Minute)},
		},
	}

	helper := newTestHelper(fetcher, cfg)
	for i := 0; i < 3; i++ {
		if err := helper.refreshAndSwap(context.Background()); err != nil {
			t.Fatalf("refreshAndSwap failed at iteration %d: %v", i, err)
		}
	}

	if len(helper.state.JWTRequests) != 1 {
		t.Fatalf("expected 1 JWT request after repeated refreshes, got %d", len(helper.state.JWTRequests))
	}
	if len(helper.state.JWTSVIDs) != 1 {
		t.Fatalf("expected 1 cached JWT-SVID after repeated refreshes, got %d", len(helper.state.JWTSVIDs))
	}
}

func TestCloseStopsRefreshLoop(t *testing.T) {
	cfg := withDefaults(api.Config{
		RefreshInterval: 5 * time.Second,
		RequestTimeout:  time.Second,
		TrustDomain:     "example.org",
		Source:          api.SourceConfig{AgentAddress: defaultAgentSocketPath},
		JWT:             api.JWTConfig{Audiences: []string{"service-a"}},
	})
	params := mustJWTParams(t, cfg)
	fetcher := &fakeFetcher{
		x509:       &x509svid.SVID{},
		x509Bundle: x509bundle.NewSet(),
		jwtBundles: jwtbundle.NewSet(jwtbundle.New(spiffeid.RequireTrustDomainFromString("example.org"))),
		jwtSVIDs: map[string]*jwtsvid.SVID{
			jwtRequestKey(params): {Audience: []string{"service-a"}, Expiry: time.Now().Add(time.Minute)},
		},
	}
	helper := &Helper{
		cfg:     cfg,
		logger:  observability.WithLoggerDefaults(cfg.Logger, "cis-helper", "test"),
		metrics: observability.NewRecorder("test", cfg.Metrics),
		fetcher: fetcher,
		state: &cache.State{
			JWTSVIDs: map[string]*jwtsvid.SVID{
				jwtRequestKey(params): fetcher.jwtSVIDs[jwtRequestKey(params)],
			},
			JWTBundles:  fetcher.jwtBundles,
			X509Bundles: fetcher.x509Bundle,
			X509SVID:    fetcher.x509,
			JWTRequests: map[string]jwtsvid.Params{jwtRequestKey(params): params},
		},
		closeCh: make(chan struct{}),
		doneCh:  make(chan struct{}),
	}

	go helper.refreshLoop()

	done := make(chan error, 1)
	go func() {
		done <- helper.Close()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not stop refresh loop in time")
	}
}

func TestNewIdentityFetcherPrefersMemorySource(t *testing.T) {
	cfg := api.Config{
		Source: api.SourceConfig{
			Memory: &api.MemorySource{
				Data: &api.MemoryIdentityData{
					JWTSVIDToken:  "memory-jwt",
					JWTBundleJSON: []byte("memory-bundle"),
					X509SVIDPEM:   []byte("memory-cert"),
					X509KeyPEM:    []byte("memory-key"),
					X509BundlePEM: []byte("memory-x509-bundle"),
				},
			},
			Disk: &api.DiskSource{
				JWTSVIDTokenPath:  "/tmp/jwt.token",
				JWTBundleJSONPath: "/tmp/jwt-bundle.json",
				X509SVIDPEMPath:   "/tmp/svid.pem",
				X509KeyPEMPath:    "/tmp/key.pem",
				X509BundlePEMPath: "/tmp/bundle.pem",
			},
		},
	}

	fetcher, sourceName, err := newIdentityFetcher(context.Background(), cfg, observability.WithLoggerDefaults(nil, "cis-helper", "test"), observability.NewRecorder("test", nil))
	if err != nil {
		t.Fatalf("newIdentityFetcher failed: %v", err)
	}
	if sourceName != "memory" {
		t.Fatalf("expected memory source, got %q", sourceName)
	}
	if fetcher == nil {
		t.Fatal("expected non-nil fetcher")
	}
}

func TestNewIdentityFetcherPrefersDiskSourceWhenMemoryAbsent(t *testing.T) {
	cfg := api.Config{
		Source: api.SourceConfig{
			Disk: &api.DiskSource{
				JWTSVIDTokenPath:  "/tmp/jwt.token",
				JWTBundleJSONPath: "/tmp/jwt-bundle.json",
				X509SVIDPEMPath:   "/tmp/svid.pem",
				X509KeyPEMPath:    "/tmp/key.pem",
				X509BundlePEMPath: "/tmp/bundle.pem",
			},
		},
	}

	fetcher, sourceName, err := newIdentityFetcher(context.Background(), cfg, observability.WithLoggerDefaults(nil, "cis-helper", "test"), observability.NewRecorder("test", nil))
	if err != nil {
		t.Fatalf("newIdentityFetcher failed: %v", err)
	}
	if sourceName != "disk" {
		t.Fatalf("expected disk source, got %q", sourceName)
	}
	if fetcher == nil {
		t.Fatal("expected non-nil fetcher")
	}
}

func TestNewIdentityFetcherDoesNotFallBackWhenMemorySourceIsInvalid(t *testing.T) {
	cfg := api.Config{
		Source: api.SourceConfig{
			Memory: &api.MemorySource{
				Data: &api.MemoryIdentityData{
					JWTSVIDToken: "memory-jwt",
				},
			},
			Disk: &api.DiskSource{
				JWTSVIDTokenPath:  "/tmp/jwt.token",
				JWTBundleJSONPath: "/tmp/jwt-bundle.json",
				X509SVIDPEMPath:   "/tmp/svid.pem",
				X509KeyPEMPath:    "/tmp/key.pem",
				X509BundlePEMPath: "/tmp/bundle.pem",
			},
		},
	}

	_, _, err := newIdentityFetcher(context.Background(), cfg, observability.WithLoggerDefaults(nil, "cis-helper", "test"), observability.NewRecorder("test", nil))
	if err == nil {
		t.Fatal("expected invalid memory source error")
	}
}

func newTestHelper(fetcher *fakeFetcher, cfg api.Config) *Helper {
	cfg = withDefaults(api.Config{
		RefreshInterval: time.Minute,
		RequestTimeout:  time.Second,
		TrustDomain:     "example.org",
		Source:          api.SourceConfig{AgentAddress: defaultAgentSocketPath},
		JWT: api.JWTConfig{
			Audiences: append([]string(nil), cfg.JWT.Audiences...),
			SPIFFEID:  cfg.JWT.SPIFFEID,
		},
	})
	initialParams, _ := toJWTSVIDParams(cfg)

	return &Helper{
		cfg:     cfg,
		logger:  observability.WithLoggerDefaults(cfg.Logger, "cis-helper", "test"),
		metrics: observability.NewRecorder("test", cfg.Metrics),
		fetcher: fetcher,
		state: &cache.State{
			JWTSVIDs: map[string]*jwtsvid.SVID{
				jwtRequestKey(initialParams): fetcher.jwtSVIDs[jwtRequestKey(initialParams)],
			},
			JWTBundles:  fetcher.jwtBundles,
			X509Bundles: fetcher.x509Bundle,
			X509SVID:    fetcher.x509,
			JWTRequests: map[string]jwtsvid.Params{jwtRequestKey(initialParams): initialParams},
		},
		closeCh: make(chan struct{}),
		doneCh:  make(chan struct{}),
	}
}

func mustJWTParams(t *testing.T, cfg api.Config) jwtsvid.Params {
	t.Helper()
	params, err := toJWTSVIDParams(cfg)
	if err != nil {
		t.Fatalf("toJWTSVIDParams failed: %v", err)
	}
	return params
}

type fakeFetcher struct {
	x509       *x509svid.SVID
	x509Err    error
	x509Bundle *x509bundle.Set
	x509BErr   error
	jwtBundles *jwtbundle.Set
	bundlesErr error
	jwtSVIDs   map[string]*jwtsvid.SVID
	jwtErr     error
}

type signedTokenFixture struct {
	serialized string
	publicKey  crypto.PublicKey
}

func newTokenTestHelper(td spiffeid.TrustDomain, authorities map[string]crypto.PublicKey) *Helper {
	bundle := jwtbundle.NewSet(jwtbundle.FromJWTAuthorities(td, authorities))
	return &Helper{
		cfg:     withDefaults(api.Config{TrustDomain: td.String()}),
		logger:  observability.WithLoggerDefaults(nil, "cis-helper", "test"),
		metrics: observability.NewRecorder("test", nil),
		state: &cache.State{
			JWTBundles: bundle,
		},
	}
}

func makeSignedToken(t *testing.T, keyID string, subject string, expiry time.Time) signedTokenFixture {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key failed: %v", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key: jose.JSONWebKey{
			Key:   privateKey,
			KeyID: keyID,
		},
	}, nil)
	if err != nil {
		t.Fatalf("new signer failed: %v", err)
	}
	serialized, err := gojwt.Signed(signer).Claims(gojwt.Claims{
		Subject:  subject,
		Expiry:   gojwt.NewNumericDate(expiry),
		IssuedAt: gojwt.NewNumericDate(time.Now().Add(-time.Minute)),
	}).Serialize()
	if err != nil {
		t.Fatalf("serialize token failed: %v", err)
	}
	return signedTokenFixture{
		serialized: serialized,
		publicKey:  &privateKey.PublicKey,
	}
}

func (f *fakeFetcher) FetchJWTSVID(_ context.Context, params jwtsvid.Params) (*jwtsvid.SVID, error) {
	if f.jwtErr != nil {
		return nil, f.jwtErr
	}
	return f.jwtSVIDs[jwtRequestKey(params)], nil
}

func (f *fakeFetcher) FetchJWTBundles(context.Context) (*jwtbundle.Set, error) {
	if f.bundlesErr != nil {
		return nil, f.bundlesErr
	}
	return f.jwtBundles, nil
}

func (f *fakeFetcher) FetchX509SVID(context.Context) (*x509svid.SVID, error) {
	if f.x509Err != nil {
		return nil, f.x509Err
	}
	return f.x509, nil
}

func (f *fakeFetcher) FetchX509Bundles(context.Context) (*x509bundle.Set, error) {
	if f.x509BErr != nil {
		return nil, f.x509BErr
	}
	return f.x509Bundle, nil
}

func (f *fakeFetcher) Close() error { return nil }
