package cache

import (
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

type State struct {
	X509SVID    *x509svid.SVID
	X509Bundles *x509bundle.Set
	JWTBundles  *jwtbundle.Set
	JWTSVIDs    map[string]*jwtsvid.SVID
	JWTRequests map[string]jwtsvid.Params
}
