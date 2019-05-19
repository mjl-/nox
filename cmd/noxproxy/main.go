/*
Noxproxy is an HTTP proxy allowing incoming plain requests and making outgoing requests over nox.

HTTPS is not supported, simply configure your http client to only use the proxy
for plain HTTP.

Nox addresses are created by using "fs" to the incoming address for the local
specifier. And "known" for remote. You can override these values with the -local
and -remote flags.

Address to use nox for can be whitelisted or blacklisted. If a whitelist is
active, only outgoing connection for matching addresses are made with nox. If a
blacklist is active, all outgoing connections except those matching the
blacklist are made with nox.

Example:

	$ nox init
	$ noxproxy -verbose -remote tofu -whitelist localhost:1047

	$ http_proxy=http://localhost:8000 curl -v localhost:1047
*/
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"

	"github.com/mjl-/nox"
	"github.com/mjl-/nox/noxhttp"
)

func check(err error, action string) {
	if err != nil {
		log.Fatalf("%s: %s\n", action, err)
	}
}

var address = flag.String("address", "localhost:8000", "address to serve http proxy on")
var local = flag.String("local", "fs", "specifier for local private key to use for dialing nox addresses")
var remote = flag.String("remote", "known", "specifier for trusting remote to use for dialing nox addresses")
var verbose = flag.Bool("verbose", false, "print requested URLs to stderr")
var whitelist = flag.String("whitelist", "", "comma-separated dial addresses to use with nox; if empty, all addresses are dialed with nox")
var blacklist = flag.String("blacklist", "", "comma-separated dial addresses not to use with nox; if empty, no addresses are dialed with plain http")

func main() {
	log.SetFlags(0)
	flag.Usage = func() {
		log.Println("usage: noxproxy [flags]")
		flag.PrintDefaults()
	}
	flag.Parse()
	if len(flag.Args()) != 0 {
		flag.Usage()
		os.Exit(2)
	}

	if *whitelist != "" && *blacklist != "" {
		log.Fatalln("cannot have both whitelist and blacklist")
	}

	_, err := nox.NearestNoxDir()
	check(err, "finding nearest nox directory")

	var config nox.Config
	err = nox.ParseAddress(*address, &config)
	check(err, "parsing listen address")

	pr := newPickRoundTripper(*whitelist, *blacklist)

	proxy := &httputil.ReverseProxy{
		Director:  pr.director,
		Transport: pr,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			transportName := "nox"
			if pr.usePlain(r) {
				transportName = "plain http"
			}
			msg := fmt.Sprintf("%s request failed: %s: %s", transportName, r.URL, err)
			log.Println(msg)
			http.Error(w, "http status 502 - noxproxy: "+msg, http.StatusBadGateway)
		},
	}
	http.Handle("/", proxy)

	log.Printf("serving http proxy on %s, local static public key %s", config.Address, config.LocalStaticPublic())
	log.Fatalln(http.ListenAndServe(config.Address, nil))
}

type pickRoundTripper struct {
	whitelist    map[string]struct{}
	blacklist    map[string]struct{}
	noxTransport *http.Transport
}

func newPickRoundTripper(wl string, bl string) *pickRoundTripper {
	pr := &pickRoundTripper{
		map[string]struct{}{},
		map[string]struct{}{},
		&http.Transport{},
	}
	noxhttp.Register("http", pr.noxTransport)

	if wl != "" {
		for _, addr := range strings.Split(wl, ",") {
			pr.whitelist[addr] = struct{}{}
		}
	}
	if bl != "" {
		for _, addr := range strings.Split(bl, ",") {
			pr.blacklist[addr] = struct{}{}
		}
	}
	return pr
}

func (pr *pickRoundTripper) director(req *http.Request) {
	transportName := "plain"
	if *verbose {
		defer func() {
			log.Printf("%s %s\n", transportName, req.URL)
		}()
	}
	if req.URL.Scheme != "http" || pr.usePlain(req) {
		return
	}
	transportName = "nox"
	if !strings.Contains(req.URL.Host, ":") {
		req.URL.Host += ":80"
	}
	req.URL.Host += "+" + *local + "+" + *remote
}

func (pr *pickRoundTripper) usePlain(req *http.Request) bool {
	if len(pr.blacklist) > 0 {
		if _, ok := pr.blacklist[req.URL.Host]; ok {
			return true
		}
	}
	if len(pr.whitelist) > 0 {
		if _, ok := pr.whitelist[req.URL.Host]; !ok {
			return true
		}
	}
	return false
}

func (pr *pickRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if !strings.Contains(req.URL.Host, "+") {
		return http.DefaultTransport.RoundTrip(req)
	}
	return pr.noxTransport.RoundTrip(req)
}
