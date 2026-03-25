package localsource

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"git.corp.kuaishou.com/corpsec/nhi/cis-helper/internal/api"
)

type MemoryFetcher struct {
	cfg api.Config
	src *api.MemorySource
}

type DiskFetcher struct {
	cfg api.Config
	src *api.DiskSource
}

func NewMemory(cfg api.Config) (*MemoryFetcher, error) {
	if cfg.Source.Memory == nil {
		return nil, fmt.Errorf("memory source is not configured")
	}
	if err := validateMemorySource(*cfg.Source.Memory); err != nil {
		return nil, err
	}
	return &MemoryFetcher{cfg: cfg, src: cfg.Source.Memory}, nil
}

func NewDisk(cfg api.Config) (*DiskFetcher, error) {
	if cfg.Source.Disk == nil {
		return nil, fmt.Errorf("disk source is not configured")
	}
	if err := validateDiskSource(*cfg.Source.Disk); err != nil {
		return nil, err
	}
	return &DiskFetcher{cfg: cfg, src: cfg.Source.Disk}, nil
}

func (f *MemoryFetcher) FetchJWTSVID(_ context.Context, params jwtsvid.Params) (*jwtsvid.SVID, error) {
	data, err := f.loadIdentityData()
	if err != nil {
		return nil, err
	}
	return parseJWTSVIDToken([]byte(data.JWTSVIDToken), params)
}

func (f *MemoryFetcher) FetchJWTBundles(context.Context) (*jwtbundle.Set, error) {
	data, err := f.loadIdentityData()
	if err != nil {
		return nil, err
	}
	td, err := localTrustDomain(f.cfg, data.X509SVIDPEM, data.X509KeyPEM, []byte(data.JWTSVIDToken))
	if err != nil {
		return nil, err
	}
	return parseJWTBundleJSON(data.JWTBundleJSON, td)
}

func (f *MemoryFetcher) FetchX509SVID(context.Context) (*x509svid.SVID, error) {
	data, err := f.loadIdentityData()
	if err != nil {
		return nil, err
	}
	return x509svid.Parse(data.X509SVIDPEM, data.X509KeyPEM)
}

func (f *MemoryFetcher) FetchX509Bundles(context.Context) (*x509bundle.Set, error) {
	data, err := f.loadIdentityData()
	if err != nil {
		return nil, err
	}
	td, err := localTrustDomain(f.cfg, data.X509SVIDPEM, data.X509KeyPEM, []byte(data.JWTSVIDToken))
	if err != nil {
		return nil, err
	}
	return parseX509BundlePEM(data.X509BundlePEM, td)
}

func (f *MemoryFetcher) Close() error { return nil }

func (f *DiskFetcher) FetchJWTSVID(_ context.Context, params jwtsvid.Params) (*jwtsvid.SVID, error) {
	tokenBytes, err := os.ReadFile(f.src.JWTSVIDTokenPath)
	if err != nil {
		return nil, err
	}
	return parseJWTSVIDToken(tokenBytes, params)
}

func (f *DiskFetcher) FetchJWTBundles(context.Context) (*jwtbundle.Set, error) {
	td, err := localTrustDomainFromDisk(f.cfg, f.src)
	if err != nil {
		return nil, err
	}
	jsonBytes, err := os.ReadFile(f.src.JWTBundleJSONPath)
	if err != nil {
		return nil, err
	}
	return parseJWTBundleJSON(jsonBytes, td)
}

func (f *DiskFetcher) FetchX509SVID(context.Context) (*x509svid.SVID, error) {
	return x509svid.Load(f.src.X509SVIDPEMPath, f.src.X509KeyPEMPath)
}

func (f *DiskFetcher) FetchX509Bundles(context.Context) (*x509bundle.Set, error) {
	td, err := localTrustDomainFromDisk(f.cfg, f.src)
	if err != nil {
		return nil, err
	}
	pemBytes, err := os.ReadFile(f.src.X509BundlePEMPath)
	if err != nil {
		return nil, err
	}
	return parseX509BundlePEM(pemBytes, td)
}

func (f *DiskFetcher) Close() error { return nil }

func (f *MemoryFetcher) loadIdentityData() (*api.MemoryIdentityData, error) {
	switch {
	case f.src == nil:
		return nil, api.WrapError(api.CodeInvalidConfig, "memory source is not configured", nil)
	case f.src.Loader != nil:
		data, err := f.src.Loader()
		if err != nil {
			return nil, err
		}
		if data == nil {
			return nil, api.WrapError(api.CodeInvalidConfig, "memory source loader returned nil data", nil)
		}
		if err := validateMemoryIdentityData(*data); err != nil {
			return nil, err
		}
		return cloneMemoryIdentityData(data), nil
	case f.src.Data != nil:
		if err := validateMemoryIdentityData(*f.src.Data); err != nil {
			return nil, err
		}
		return cloneMemoryIdentityData(f.src.Data), nil
	default:
		return nil, api.WrapError(api.CodeInvalidConfig, "memory source must provide Data or Loader", nil)
	}
}

func validateMemorySource(src api.MemorySource) error {
	if src.Loader != nil {
		return nil
	}
	if src.Data == nil {
		return api.WrapError(api.CodeInvalidConfig, "memory source must provide Data or Loader", nil)
	}
	return validateMemoryIdentityData(*src.Data)
}

func validateDiskSource(src api.DiskSource) error {
	switch {
	case src.JWTSVIDTokenPath == "":
		return api.WrapError(api.CodeInvalidConfig, "disk source JWT-SVID token path must not be empty", nil)
	case src.JWTBundleJSONPath == "":
		return api.WrapError(api.CodeInvalidConfig, "disk source JWT bundle JSON path must not be empty", nil)
	case src.X509SVIDPEMPath == "":
		return api.WrapError(api.CodeInvalidConfig, "disk source X509-SVID PEM path must not be empty", nil)
	case src.X509KeyPEMPath == "":
		return api.WrapError(api.CodeInvalidConfig, "disk source X509 key PEM path must not be empty", nil)
	case src.X509BundlePEMPath == "":
		return api.WrapError(api.CodeInvalidConfig, "disk source X509 bundle PEM path must not be empty", nil)
	default:
		return nil
	}
}

func validateMemoryIdentityData(data api.MemoryIdentityData) error {
	switch {
	case data.JWTSVIDToken == "":
		return api.WrapError(api.CodeInvalidConfig, "memory source JWT-SVID token must not be empty", nil)
	case len(data.JWTBundleJSON) == 0:
		return api.WrapError(api.CodeInvalidConfig, "memory source JWT bundle JSON must not be empty", nil)
	case len(data.X509SVIDPEM) == 0:
		return api.WrapError(api.CodeInvalidConfig, "memory source X509-SVID PEM must not be empty", nil)
	case len(data.X509KeyPEM) == 0:
		return api.WrapError(api.CodeInvalidConfig, "memory source X509 key PEM must not be empty", nil)
	case len(data.X509BundlePEM) == 0:
		return api.WrapError(api.CodeInvalidConfig, "memory source X509 bundle PEM must not be empty", nil)
	default:
		return nil
	}
}

func localTrustDomainFromDisk(cfg api.Config, src *api.DiskSource) (spiffeid.TrustDomain, error) {
	certPEM, err := os.ReadFile(src.X509SVIDPEMPath)
	if err != nil {
		return spiffeid.TrustDomain{}, err
	}
	keyPEM, err := os.ReadFile(src.X509KeyPEMPath)
	if err != nil {
		return spiffeid.TrustDomain{}, err
	}
	jwtToken, err := os.ReadFile(src.JWTSVIDTokenPath)
	if err != nil {
		return spiffeid.TrustDomain{}, err
	}
	return localTrustDomain(cfg, certPEM, keyPEM, jwtToken)
}

func localTrustDomain(cfg api.Config, x509CertPEM, x509KeyPEM, jwtPEM []byte) (spiffeid.TrustDomain, error) {
	if cfg.TrustDomain != "" {
		td, err := spiffeid.TrustDomainFromString(cfg.TrustDomain)
		if err != nil {
			return spiffeid.TrustDomain{}, api.WrapError(api.CodeInvalidConfig, "trust domain is invalid", err)
		}
		return td, nil
	}

	if len(x509CertPEM) > 0 && len(x509KeyPEM) > 0 {
		svid, err := x509svid.Parse(x509CertPEM, x509KeyPEM)
		if err == nil {
			return svid.ID.TrustDomain(), nil
		}
	}

	if len(jwtPEM) > 0 {
		audiences := []string{"spire-server"}
		if len(cfg.JWT.Audiences) > 0 {
			audiences = append([]string(nil), cfg.JWT.Audiences...)
		}
		svid, jwtErr := jwtsvid.ParseInsecure(string(bytes.TrimSpace(jwtPEM)), audiences)
		if jwtErr == nil {
			return svid.ID.TrustDomain(), nil
		}
	}

	if cfg.JWT.SPIFFEID != "" {
		id, err := spiffeid.FromString(cfg.JWT.SPIFFEID)
		if err != nil {
			return spiffeid.TrustDomain{}, api.WrapError(api.CodeInvalidConfig, "jwt SPIFFE ID must be a valid SPIFFE ID", err)
		}
		return id.TrustDomain(), nil
	}

	return spiffeid.TrustDomain{}, api.WrapError(api.CodeInvalidConfig, "trust domain is required when using local sources and cannot be derived from local identities", nil)
}

func parseJWTSVIDToken(tokenBytes []byte, params jwtsvid.Params) (*jwtsvid.SVID, error) {
	audiences := append([]string{params.Audience}, params.ExtraAudiences...)
	return jwtsvid.ParseInsecure(string(bytes.TrimSpace(tokenBytes)), audiences)
}

func parseJWTBundleJSON(jsonBytes []byte, trustDomain spiffeid.TrustDomain) (*jwtbundle.Set, error) {
	bundle, err := jwtbundle.Parse(trustDomain, bytes.TrimSpace(jsonBytes))
	if err != nil {
		return nil, err
	}
	return jwtbundle.NewSet(bundle), nil
}

func parseX509BundlePEM(pemBytes []byte, trustDomain spiffeid.TrustDomain) (*x509bundle.Set, error) {
	bundle, err := x509bundle.Parse(trustDomain, pemBytes)
	if err != nil {
		return nil, err
	}
	return x509bundle.NewSet(bundle), nil
}

func cloneMemoryIdentityData(data *api.MemoryIdentityData) *api.MemoryIdentityData {
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
