package api

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"log/slog"
	"time"

	"github.com:spring-zhao/cis-helper/internal/observability"
)

type Config struct {
	RefreshInterval time.Duration
	RequestTimeout  time.Duration
	TrustDomain     string
	Source          SourceConfig
	JWT             JWTConfig
	TLSMode         TLSMode
	TLSAuthorizer   PeerAuthorizer
	Logger          *slog.Logger
	Metrics         observability.MetricsRecorder
}

type SourceConfig struct {
	AgentAddress string
	Memory       *MemorySource
	Disk         *DiskSource
}

type JWTConfig struct {
	Audiences []string
	SPIFFEID  string
}

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

type DiskSource struct {
	JWTSVIDTokenPath  string
	JWTBundleJSONPath string
	X509SVIDPEMPath   string
	X509KeyPEMPath    string
	X509BundlePEMPath string
}

type X509SVID struct {
	ID         string
	Cert       *x509.Certificate
	Chain      []*x509.Certificate
	PrivateKey crypto.Signer
	Hint       string
}

type JWTBundleSet struct {
	Bundles map[string][]byte
}

type X509BundleSet struct {
	Bundles map[string][]*x509.Certificate
}

type TLSMode string

const (
	TLSModeMTLS   TLSMode = "mtls"
	TLSModeOneWay TLSMode = "one_way_tls"
)

type PeerAuthorizer func(peerID string, verifiedChains [][]*x509.Certificate) error

func AuthorizeAnyPeer() PeerAuthorizer {
	return func(string, [][]*x509.Certificate) error { return nil }
}

const (
	CodeInvalidConfig       = "CIS_INVALID_CONFIG"
	CodeConnectAgent        = "CIS_CONNECT_AGENT_FAILED"
	CodeInitialRefresh      = "CIS_INITIAL_REFRESH_FAILED"
	CodeRefresh             = "CIS_REFRESH_FAILED"
	CodeClosed              = "CIS_HELPER_CLOSED"
	CodeJWTSVIDNotCached    = "CIS_JWT_SVID_NOT_CACHED"
	CodeX509SVIDNotCached   = "CIS_X509_SVID_NOT_CACHED"
	CodeJWTBundlesNotCached = "CIS_JWT_BUNDLES_NOT_CACHED"
	CodeX509BundleNotCached = "CIS_X509_BUNDLE_NOT_CACHED"
	CodeJWTTokenInvalid     = "CIS_JWT_TOKEN_INVALID"
)

type Error struct {
	Code    string
	Message string
	Cause   error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Cause == nil {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Cause)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func (e *Error) GetCode() string {
	if e == nil {
		return ""
	}
	return e.Code
}

func WrapError(code, message string, err error) error {
	return &Error{Code: code, Message: message, Cause: err}
}
