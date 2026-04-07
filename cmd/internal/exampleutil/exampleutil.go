package exampleutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	cishelper "git.corp.kuaishou.com/corpsec/nhi/cis-helper"
)

const (
	DefaultHost      = "127.0.0.1"
	DefaultPort      = 9443
	DefaultPProfPort = 6060
)

func NewHelperFromEnv(ctx context.Context) (*cishelper.Helper, cishelper.TLSMode, error) {
	agentAddr := os.Getenv("CIS_HELPER_AGENT_UDS")
	trustDomain := os.Getenv("CIS_HELPER_TRUST_DOMAIN")
	jwtAudiences := jwtAudiencesFromEnv()
	tlsMode := cishelper.TLSMode(envOrDefault("CIS_HELPER_TLS_MODE", string(cishelper.TLSModeMTLS)))
	sourceMode := strings.ToLower(envOrDefault("CIS_HELPER_SOURCE_MODE", "agent"))

	cfg := cishelper.Config{
		RefreshInterval: 20 * time.Second,
		TrustDomain:     trustDomain,
		Source: cishelper.SourceConfig{
			AgentAddress: agentAddr,
		},
		JWT: cishelper.JWTConfig{
			Audiences: jwtAudiences,
		},
		TLSMode: tlsMode,
	}

	switch sourceMode {
	case "agent":
	case "disk":
		diskSource, resolvedTrustDomain, err := DiskSourceFromEnv(trustDomain)
		if err != nil {
			return nil, "", err
		}
		cfg.Source.Disk = diskSource
		if cfg.TrustDomain == "" {
			cfg.TrustDomain = resolvedTrustDomain
		}
	case "memory":
		memorySource, resolvedTrustDomain, err := MemorySourceFromEnv(trustDomain)
		if err != nil {
			return nil, "", err
		}
		cfg.Source.Memory = memorySource
		if cfg.TrustDomain == "" {
			cfg.TrustDomain = resolvedTrustDomain
		}
	case "memory_over_disk":
		diskSource, resolvedTrustDomain, err := DiskSourceFromEnv(trustDomain)
		if err != nil {
			return nil, "", err
		}
		memorySource, _, err := MemorySourceFromEnv(resolvedTrustDomain)
		if err != nil {
			return nil, "", err
		}
		cfg.Source.Disk = diskSource
		cfg.Source.Memory = memorySource
		if cfg.TrustDomain == "" {
			cfg.TrustDomain = resolvedTrustDomain
		}
	default:
		return nil, "", fmt.Errorf("unsupported CIS_HELPER_SOURCE_MODE %q", sourceMode)
	}

	helper, err := cishelper.NewHelper(ctx, cfg)
	if err != nil {
		return nil, "", err
	}
	return helper, tlsMode, nil
}

func OutputDirFromEnv() string {
	return os.Getenv("CIS_HELPER_OUTPUT_DIR")
}

func TokenToVerifyFromEnv() string {
	return strings.TrimSpace(os.Getenv("CIS_HELPER_VERIFY_TOKEN"))
}

func TrustedTokenLabelFromEnv() string {
	return strings.TrimSpace(os.Getenv("CIS_HELPER_TRUSTED_TOKEN_LABEL"))
}

func FetchIdentityAndWriteOutput(helper *cishelper.Helper) error {
	x509SVID, err := helper.GetX509SVID()
	if err != nil {
		return err
	}

	x509Bundle, err := helper.GetX509Bundle()
	if err != nil {
		return err
	}

	jwtBundle, err := helper.GetJWTBundle()
	if err != nil {
		return err
	}

	jwtSVID, err := helper.GetJWTSVID()
	if err != nil {
		return err
	}

	if _, err := helper.GetTlsConfig(); err != nil {
		return err
	}

	return WriteOutputFiles(OutputDirFromEnv(), x509SVID, x509Bundle, jwtSVID.Marshal(), jwtBundle)
}

func WriteOutputFiles(outputDir string, x509SVID *cishelper.X509SVID, x509Bundle *cishelper.X509BundleSet, jwtToken string, jwtBundle *cishelper.JWTBundleSet) error {
	if outputDir == "" {
		return nil
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outputDir, "svid-cert.pem"), pemEncodeCertChain(x509SVID), 0o644); err != nil {
		return err
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(x509SVID.PrivateKey)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outputDir, "svid-key.pem"), pemBlock("PRIVATE KEY", keyBytes), 0o600); err != nil {
		return err
	}
	for trustDomain, certs := range x509Bundle.Bundles {
		path := filepath.Join(outputDir, trustDomain+"-bundle.pem")
		if err := os.WriteFile(path, pemEncodeCerts(certs), 0o644); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(outputDir, "jwt-svid.token"), []byte(jwtToken), 0o644); err != nil {
		return err
	}
	for trustDomain, raw := range jwtBundle.Bundles {
		path := filepath.Join(outputDir, trustDomain+"-jwt-bundle.json")
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func SourceModeFromEnv() string {
	return strings.ToLower(envOrDefault("CIS_HELPER_SOURCE_MODE", "agent"))
}

func InputDirFromEnv() string {
	return os.Getenv("CIS_HELPER_INPUT_DIR")
}

func DiskSourceFromEnv(trustDomain string) (*cishelper.DiskSource, string, error) {
	inputDir := InputDirFromEnv()
	if inputDir == "" {
		return nil, "", fmt.Errorf("CIS_HELPER_INPUT_DIR is required for disk source mode")
	}
	resolvedTrustDomain, err := resolveTrustDomainForLocalSource(inputDir, trustDomain)
	if err != nil {
		return nil, "", err
	}
	return &cishelper.DiskSource{
		JWTSVIDTokenPath:  filepath.Join(inputDir, "jwt-svid.token"),
		JWTBundleJSONPath: filepath.Join(inputDir, resolvedTrustDomain+"-jwt-bundle.json"),
		X509SVIDPEMPath:   filepath.Join(inputDir, "svid-cert.pem"),
		X509KeyPEMPath:    filepath.Join(inputDir, "svid-key.pem"),
		X509BundlePEMPath: filepath.Join(inputDir, resolvedTrustDomain+"-bundle.pem"),
	}, resolvedTrustDomain, nil
}

func MemorySourceFromEnv(trustDomain string) (*cishelper.MemorySource, string, error) {
	diskSource, resolvedTrustDomain, err := DiskSourceFromEnv(trustDomain)
	if err != nil {
		return nil, "", err
	}
	return &cishelper.MemorySource{
		Loader: func() (*cishelper.MemoryIdentityData, error) {
			jwtToken, err := os.ReadFile(diskSource.JWTSVIDTokenPath)
			if err != nil {
				return nil, err
			}
			jwtBundle, err := os.ReadFile(diskSource.JWTBundleJSONPath)
			if err != nil {
				return nil, err
			}
			x509SVID, err := os.ReadFile(diskSource.X509SVIDPEMPath)
			if err != nil {
				return nil, err
			}
			x509Key, err := os.ReadFile(diskSource.X509KeyPEMPath)
			if err != nil {
				return nil, err
			}
			x509Bundle, err := os.ReadFile(diskSource.X509BundlePEMPath)
			if err != nil {
				return nil, err
			}
			return &cishelper.MemoryIdentityData{
				JWTSVIDToken:  strings.TrimSpace(string(jwtToken)),
				JWTBundleJSON: jwtBundle,
				X509SVIDPEM:   x509SVID,
				X509KeyPEM:    x509Key,
				X509BundlePEM: x509Bundle,
			}, nil
		},
	}, resolvedTrustDomain, nil
}

func ServerAddressFromEnv() string {
	return fmt.Sprintf("%s:%d", envOrDefault("CIS_HELPER_HTTPS_SERVER_IP", DefaultHost), envPort("CIS_HELPER_HTTPS_SERVER_PORT", DefaultPort))
}

func ClientTargetAddressFromEnv() string {
	return fmt.Sprintf("%s:%d", envOrDefault("CIS_HELPER_HTTPS_CLIENT_IP", DefaultHost), envPort("CIS_HELPER_HTTPS_CLIENT_PORT", DefaultPort))
}

func PProfAddressFromEnv() string {
	return fmt.Sprintf("%s:%d", envOrDefault("CIS_HELPER_PPROF_IP", DefaultHost), envPort("CIS_HELPER_PPROF_PORT", DefaultPProfPort))
}

func BuildServerTLSConfig(ctx context.Context, helper *cishelper.Helper) (*tls.Config, error) {
	_ = ctx

	serverTLS, err := helper.GetTlsConfig()
	if err != nil {
		return nil, err
	}
	serverTLS.NextProtos = []string{"h2", "http/1.1"}
	return serverTLS, nil
}

func envOrDefault(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func envPort(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	port, err := strconv.Atoi(value)
	if err != nil || port <= 0 || port > 65535 {
		return fallback
	}
	return port
}

func jwtAudiencesFromEnv() []string {
	if value := os.Getenv("CIS_HELPER_JWT_AUDIENCES"); value != "" {
		parts := strings.Split(value, ",")
		out := make([]string, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	if value := strings.TrimSpace(os.Getenv("CIS_HELPER_JWT_AUDIENCE")); value != "" {
		return []string{value}
	}
	return nil
}

func pemEncodeCert(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func pemEncodeCertChain(x509SVID *cishelper.X509SVID) []byte {
	if len(x509SVID.Chain) == 0 {
		return pemEncodeCert(x509SVID.Cert)
	}
	return pemEncodeCerts(x509SVID.Chain)
}

func pemEncodeCerts(certs []*x509.Certificate) []byte {
	var out []byte
	for _, cert := range certs {
		out = append(out, pemEncodeCert(cert)...)
	}
	return out
}

func pemBlock(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

func certChainDER(x509SVID *cishelper.X509SVID) [][]byte {
	if len(x509SVID.Chain) == 0 {
		return [][]byte{x509SVID.Cert.Raw}
	}
	out := make([][]byte, 0, len(x509SVID.Chain))
	for _, cert := range x509SVID.Chain {
		out = append(out, cert.Raw)
	}
	return out
}

func resolveTrustDomainForLocalSource(inputDir, trustDomain string) (string, error) {
	if trustDomain != "" {
		return trustDomain, nil
	}
	matches, err := filepath.Glob(filepath.Join(inputDir, "*-jwt-bundle.json"))
	if err != nil {
		return "", err
	}
	filtered := existingFiles(matches)
	if len(filtered) != 1 {
		return "", fmt.Errorf("cannot infer trust domain from %s: expected exactly 1 *-jwt-bundle.json file, got %d", inputDir, len(filtered))
	}
	base := filepath.Base(filtered[0])
	return strings.TrimSuffix(base, "-jwt-bundle.json"), nil
}

func existingFiles(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			out = append(out, path)
		}
	}
	return out
}
