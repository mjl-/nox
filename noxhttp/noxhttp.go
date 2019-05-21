// Package noxhttp provides a http.RoundTripper for making HTTP requests over nox
// connections.
package noxhttp

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/mjl-/nox"
)

// RegisterDefaultTransport registers a NoxRoundTripper with URL scheme "httpn" on
// http.DefaultTransporter. This enables calls like:
//
//	http.Get("httpn://localhost:1047+fs+known")
func RegisterDefaultTransport() {
	Register("httpn", http.DefaultTransport.(*http.Transport))
}

// Register registers a NoxRoundTripper for an URL scheme (like "http" or "httpn")
// with transport.
func Register(scheme string, transport *http.Transport) {
	rt := NewNoxRoundTripper(scheme)
	transport.RegisterProtocol(scheme, rt)
}

// NewNoxRoundTripper creates a new NoxRoundTripper for scheme.
func NewNoxRoundTripper(scheme string) *NoxRoundTripper {
	return &NoxRoundTripper{scheme}
}

// NoxRoundTripper is a http.RoundTripper that makes nox connections.
type NoxRoundTripper struct {
	scheme string
}

// RoundTrip performs a HTTP connection over nox.
func (rt *NoxRoundTripper) RoundTrip(req *http.Request) (resp *http.Response, rerr error) {
	if req.URL.Scheme != rt.scheme {
		return nil, fmt.Errorf("bad scheme, got %q, expected %q", req.URL.Scheme, rt.scheme)
	}

	noxConfig := &nox.Config{}
	u := *req.URL
	u.Scheme = "http"
	err := nox.ParseAddress(u.Host, noxConfig)
	if err != nil {
		return nil, err
	}
	u.Host = noxConfig.Address
	req.URL = &u

	dialNox := func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{}
		conn, err := d.DialContext(ctx, network, u.Host)
		if err != nil {
			return nil, err
		}
		return nox.Client(conn, noxConfig)
	}

	tt := &http.Transport{
		DialContext: dialNox,
	}
	return tt.RoundTrip(req)
}
