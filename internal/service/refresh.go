package service

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"

	"github.com:spring-zhao/cis-helper/internal/api"
	"github.com:spring-zhao/cis-helper/internal/cache"
)

func (h *Helper) refreshLoop() {
	defer close(h.doneCh)

	ticker := time.NewTicker(h.cfg.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-h.closeCh:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), h.cfg.RequestTimeout)
			err := h.refreshAndSwap(ctx)
			cancel()
			if err != nil {
				h.logger.Error("background refresh failed", "code", api.CodeRefresh, "error", err)
			}
		}
	}
}

func (h *Helper) refreshAndSwap(ctx context.Context) error {
	start := time.Now()

	state, err := h.collectState(ctx)
	if err != nil {
		h.metrics.Duration("refresh", "error", time.Since(start), nil)
		h.metrics.Error("refresh", api.CodeRefresh, err)
		h.logger.Error("refresh identities failed", "code", api.CodeRefresh, "error", err)
		return api.WrapError(api.CodeRefresh, "refresh identities failed", err)
	}

	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return api.WrapError(api.CodeClosed, "helper already closed", nil)
	}
	h.state = state
	h.mu.Unlock()

	jwtBundleCount := 0
	if state.JWTBundles != nil {
		jwtBundleCount = len(state.JWTBundles.Bundles())
	}
	h.logger.Info("refresh identities succeeded", "jwt_svid_count", len(state.JWTSVIDs), "jwt_bundle_count", jwtBundleCount)
	h.metrics.Duration("refresh", "success", time.Since(start), map[string]string{
		"jwt_bundle_count": strconv.Itoa(jwtBundleCount),
	})
	return nil
}

func (h *Helper) collectState(ctx context.Context) (*cache.State, error) {
	h.mu.RLock()
	requests := make([]jwtsvid.Params, 0, len(h.state.JWTRequests))
	for _, params := range h.state.JWTRequests {
		requests = append(requests, params)
	}
	h.mu.RUnlock()

	x509SVID, err := h.fetcher.FetchX509SVID(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch X509-SVID: %w", err)
	}
	x509Bundles, err := h.fetcher.FetchX509Bundles(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch X509 bundles: %w", err)
	}
	jwtBundles, err := h.fetcher.FetchJWTBundles(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch JWT bundles: %w", err)
	}

	jwtSVIDs := make(map[string]*jwtsvid.SVID, len(requests))
	requestMap := make(map[string]jwtsvid.Params, len(requests))
	for _, params := range requests {
		svid, err := h.fetcher.FetchJWTSVID(ctx, params)
		if err != nil {
			return nil, fmt.Errorf("fetch JWT-SVID for audience %q: %w", params.Audience, err)
		}
		key := jwtRequestKey(params)
		jwtSVIDs[key] = svid
		requestMap[key] = params
	}

	return &cache.State{
		X509SVID:    x509SVID,
		X509Bundles: x509Bundles,
		JWTBundles:  jwtBundles,
		JWTSVIDs:    jwtSVIDs,
		JWTRequests: requestMap,
	}, nil
}
