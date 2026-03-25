package service

import (
	"encoding/json"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"

	"git.corp.kuaishou.com/corpsec/nhi/cis-helper/internal/api"
)

const (
	defaultRefreshInterval = 20 * time.Second
	defaultRequestTimeout  = 10 * time.Second
	defaultAgentSocketPath = "unix:///run/spire/sockets/agent.sock"
	defaultJWTAudience     = "spire-server"
)

type jwtRequestFingerprint struct {
	Audiences []string `json:"audiences"`
	SpiffeID  string   `json:"spiffe_id,omitempty"`
}

func withDefaults(c api.Config) api.Config {
	if c.RefreshInterval <= 0 {
		c.RefreshInterval = defaultRefreshInterval
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = defaultRequestTimeout
	}
	if c.Source.AgentAddress == "" {
		c.Source.AgentAddress = defaultAgentSocketPath
	}
	if c.TLSMode == "" {
		c.TLSMode = api.TLSModeMTLS
	}
	if c.TLSAuthorizer == nil {
		c.TLSAuthorizer = api.AuthorizeAnyPeer()
	}
	return c
}

func validateConfig(c api.Config) error {
	if c.RefreshInterval <= 0 {
		return api.WrapError(api.CodeInvalidConfig, "refresh interval must be greater than 0", nil)
	}
	if c.RequestTimeout <= 0 {
		return api.WrapError(api.CodeInvalidConfig, "request timeout must be greater than 0", nil)
	}
	if c.Source.AgentAddress == "" {
		return api.WrapError(api.CodeInvalidConfig, "agent address must not be empty", nil)
	}
	if c.TrustDomain != "" {
		if _, err := spiffeid.TrustDomainFromString(c.TrustDomain); err != nil {
			return api.WrapError(api.CodeInvalidConfig, "trust domain is invalid", err)
		}
	}
	if c.TLSMode != api.TLSModeMTLS && c.TLSMode != api.TLSModeOneWay {
		return api.WrapError(api.CodeInvalidConfig, "tls mode must be mtls or one_way_tls", nil)
	}
	if _, err := normalizeJWTAudiences(c.JWT.Audiences); err != nil {
		return err
	}
	if err := validateJWTSPIFFEID(c.JWT.SPIFFEID); err != nil {
		return err
	}
	return nil
}

func normalizeJWTAudiences(audiences []string) ([]string, error) {
	if len(audiences) == 0 {
		return []string{defaultJWTAudience}, nil
	}
	out := make([]string, 0, len(audiences))
	for _, audience := range audiences {
		if audience == "" {
			continue
		}
		out = append(out, audience)
	}
	if len(out) == 0 {
		return []string{defaultJWTAudience}, nil
	}
	return out, nil
}

func validateJWTSPIFFEID(spiffeID string) error {
	if spiffeID == "" {
		return nil
	}
	if _, err := spiffeid.FromString(spiffeID); err != nil {
		return api.WrapError(api.CodeInvalidConfig, "jwt SPIFFE ID must be a valid SPIFFE ID", err)
	}
	return nil
}

func toJWTSVIDParams(cfg api.Config) (jwtsvid.Params, error) {
	audiences, err := normalizeJWTAudiences(cfg.JWT.Audiences)
	if err != nil {
		return jwtsvid.Params{}, err
	}
	if err := validateJWTSPIFFEID(cfg.JWT.SPIFFEID); err != nil {
		return jwtsvid.Params{}, err
	}

	params := jwtsvid.Params{
		Audience: audiences[0],
	}
	if len(audiences) > 1 {
		params.ExtraAudiences = append([]string(nil), audiences[1:]...)
	}
	if cfg.JWT.SPIFFEID != "" {
		subject, err := spiffeid.FromString(cfg.JWT.SPIFFEID)
		if err != nil {
			return jwtsvid.Params{}, api.WrapError(api.CodeInvalidConfig, "jwt SPIFFE ID must be a valid SPIFFE ID", err)
		}
		params.Subject = subject
	}
	return params, nil
}

func jwtRequestKey(params jwtsvid.Params) string {
	payload := jwtRequestFingerprint{
		Audiences: append([]string{params.Audience}, params.ExtraAudiences...),
		SpiffeID:  params.Subject.String(),
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return params.Audience
	}
	return string(buf)
}
