package workloadclient

import (
	"context"
	"errors"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type Client struct {
	conn   *grpc.ClientConn
	client workload.SpiffeWorkloadAPIClient
}

func New(ctx context.Context, agentAddress string) (*Client, error) {
	target, err := workloadapi.TargetFromAddress(agentAddress)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.DialContext(ctx, target, grpc.WithTransportCredentials(insecure.NewCredentials())) //nolint:staticcheck
	if err != nil {
		return nil, err
	}

	return &Client{
		conn:   conn,
		client: workload.NewSpiffeWorkloadAPIClient(conn),
	}, nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) FetchX509SVID(ctx context.Context) (*x509svid.SVID, error) {
	stream, err := c.client.FetchX509SVID(withWorkloadHeader(ctx), &workload.X509SVIDRequest{})
	if err != nil {
		return nil, err
	}
	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}

	svids, err := parseX509SVIDs(resp, true)
	if err != nil {
		return nil, err
	}
	return svids[0], nil
}

func (c *Client) FetchX509Bundles(ctx context.Context) (*x509bundle.Set, error) {
	stream, err := c.client.FetchX509Bundles(withWorkloadHeader(ctx), &workload.X509BundlesRequest{})
	if err != nil {
		return nil, err
	}
	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	return parseX509BundlesResponse(resp)
}

func (c *Client) FetchJWTSVID(ctx context.Context, params jwtsvid.Params) (*jwtsvid.SVID, error) {
	audience := append([]string{params.Audience}, params.ExtraAudiences...)
	resp, err := c.client.FetchJWTSVID(withWorkloadHeader(ctx), &workload.JWTSVIDRequest{
		Audience: audience,
		SpiffeId: params.Subject.String(),
	})
	if err != nil {
		return nil, err
	}

	svids, err := parseJWTSVIDs(resp, audience, true)
	if err != nil {
		return nil, err
	}
	return svids[0], nil
}

func (c *Client) FetchJWTBundles(ctx context.Context) (*jwtbundle.Set, error) {
	stream, err := c.client.FetchJWTBundles(withWorkloadHeader(ctx), &workload.JWTBundlesRequest{})
	if err != nil {
		return nil, err
	}
	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	return parseJWTBundlesResponse(resp)
}

func withWorkloadHeader(ctx context.Context) context.Context {
	return metadata.NewOutgoingContext(ctx, metadata.Pairs("workload.spiffe.io", "true"))
}

func parseX509SVIDs(resp *workload.X509SVIDResponse, firstOnly bool) ([]*x509svid.SVID, error) {
	n := len(resp.Svids)
	if n == 0 {
		return nil, errors.New("no X509-SVIDs in response")
	}
	if firstOnly {
		n = 1
	}

	hints := make(map[string]struct{}, n)
	svids := make([]*x509svid.SVID, 0, n)
	for i := 0; i < n; i++ {
		protoSVID := resp.Svids[i]
		if _, ok := hints[protoSVID.Hint]; ok && protoSVID.Hint != "" {
			continue
		}
		hints[protoSVID.Hint] = struct{}{}

		svid, err := x509svid.ParseRaw(protoSVID.X509Svid, protoSVID.X509SvidKey)
		if err != nil {
			return nil, err
		}
		svid.Hint = protoSVID.Hint
		svids = append(svids, svid)
	}

	return svids, nil
}

func parseX509BundlesResponse(resp *workload.X509BundlesResponse) (*x509bundle.Set, error) {
	bundles := make([]*x509bundle.Bundle, 0, len(resp.Bundles))
	for tdID, rawBundle := range resp.Bundles {
		td, err := spiffeid.TrustDomainFromString(tdID)
		if err != nil {
			return nil, err
		}
		bundle, err := x509bundle.ParseRaw(td, rawBundle)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, bundle)
	}
	return x509bundle.NewSet(bundles...), nil
}

func parseJWTSVIDs(resp *workload.JWTSVIDResponse, audience []string, firstOnly bool) ([]*jwtsvid.SVID, error) {
	n := len(resp.Svids)
	if n == 0 {
		return nil, errors.New("no JWT-SVIDs in response")
	}
	if firstOnly {
		n = 1
	}

	hints := make(map[string]struct{}, n)
	svids := make([]*jwtsvid.SVID, 0, n)
	for i := 0; i < n; i++ {
		protoSVID := resp.Svids[i]
		if _, ok := hints[protoSVID.Hint]; ok && protoSVID.Hint != "" {
			continue
		}
		hints[protoSVID.Hint] = struct{}{}

		svid, err := jwtsvid.ParseInsecure(protoSVID.Svid, audience)
		if err != nil {
			return nil, err
		}
		svid.Hint = protoSVID.Hint
		svids = append(svids, svid)
	}
	return svids, nil
}

func parseJWTBundlesResponse(resp *workload.JWTBundlesResponse) (*jwtbundle.Set, error) {
	bundles := make([]*jwtbundle.Bundle, 0, len(resp.Bundles))
	for tdID, rawBundle := range resp.Bundles {
		td, err := spiffeid.TrustDomainFromString(tdID)
		if err != nil {
			return nil, err
		}
		bundle, err := jwtbundle.Parse(td, rawBundle)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, bundle)
	}
	return jwtbundle.NewSet(bundles...), nil
}
