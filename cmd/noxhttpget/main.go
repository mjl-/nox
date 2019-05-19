// Noxhttpget shows how to use subpackage noxhttp to create a http client that communicates over nox.
//
// Usage:
//
//	noxhttpget http://localhost:1047+fs+known/
//	noxhttpget httpn://localhost:1047+fs+known/
package main

import (
	"io"
	"log"
	"net/http"
	"os"

	"github.com/mjl-/nox/noxhttp"
)

func check(err error, action string) {
	if err != nil {
		log.Fatalf("%s: %s\n", action, err)
	}
}

func main() {
	log.SetFlags(0)
	if len(os.Args) != 2 {
		log.Fatalln("usage: noxhttpget url")
	}

	transport := &http.Transport{}
	noxhttp.Register("http", transport)
	noxhttp.Register("httpn", transport)

	client := &http.Client{Transport: transport}
	resp, err := client.Get(os.Args[1])
	check(err, "http get")
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Fatalf("http response status %v, expected 200", resp.StatusCode)
	}
	_, err = io.Copy(os.Stdout, resp.Body)
	check(err, "copy")
}
