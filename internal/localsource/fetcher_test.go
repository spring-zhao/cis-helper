package localsource

import (
	"testing"

	"git.corp.kuaishou.com/corpsec/nhi/cis-helper/internal/api"
)

func TestMemoryFetcherLoadIdentityDataUsesLatestLoaderValue(t *testing.T) {
	current := &api.MemoryIdentityData{
		JWTSVIDToken:  "token-a",
		JWTBundleJSON: []byte(`{"keys":[]}`),
		X509SVIDPEM:   []byte("cert-a"),
		X509KeyPEM:    []byte("key-a"),
		X509BundlePEM: []byte("bundle-a"),
	}
	fetcher := &MemoryFetcher{
		src: &api.MemorySource{
			Loader: func() (*api.MemoryIdentityData, error) {
				return current, nil
			},
		},
	}

	first, err := fetcher.loadIdentityData()
	if err != nil {
		t.Fatalf("loadIdentityData failed: %v", err)
	}

	current = &api.MemoryIdentityData{
		JWTSVIDToken:  "token-b",
		JWTBundleJSON: []byte(`{"keys":[{"kid":"b"}]}`),
		X509SVIDPEM:   []byte("cert-b"),
		X509KeyPEM:    []byte("key-b"),
		X509BundlePEM: []byte("bundle-b"),
	}

	second, err := fetcher.loadIdentityData()
	if err != nil {
		t.Fatalf("loadIdentityData second call failed: %v", err)
	}

	if first.JWTSVIDToken != "token-a" {
		t.Fatalf("expected first token to be token-a, got %q", first.JWTSVIDToken)
	}
	if second.JWTSVIDToken != "token-b" {
		t.Fatalf("expected second token to be token-b, got %q", second.JWTSVIDToken)
	}
}
