package nox

import (
	"encoding/base64"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

func TestKnownhosts(t *testing.T) {
	tcheck := func(got, exp error, action string) {
		t.Helper()
		check(t, got, exp, action)
	}

	dir, err := os.Getwd()
	tcheck(err, nil, "getwd")

	err = os.Chdir("testdata/dotnox")
	tcheck(err, nil, "chdir to dotnox")
	defer func() {
		err := os.Chdir(dir)
		if err != nil {
			log.Printf("restoring workdir after test: %s", err)
		}
	}()

	origKnownHosts, err := ioutil.ReadFile(".nox/known_hosts")
	tcheck(err, nil, "reading current test known_hosts file")
	defer func() {
		err = ioutil.WriteFile(".nox/known_hosts", origKnownHosts, 0600)
		if err != nil {
			log.Printf("restoring known_hosts after test: %s", err)
		}
	}()

	parsePubKey := func(s string) PublicKey {
		buf, err := base64.RawURLEncoding.DecodeString(s)
		tcheck(err, nil, "parsing public key")
		return PublicKey(buf)
	}

	pubKey1 := parsePubKey("Wd6ylojy2ZSPos2L1mQFWFLlOKDtTJ2-3IS-TaHNh3c")
	pubKey2 := parsePubKey("OM2rHhpaiLiuCJ8BJ44G6xhwEkzZ2Gix5fdgXqomYjI")
	pubKeyUnknown := parsePubKey("M0fS5ygb7LRqn6b7IHZQWB3zbf_St3sWAaHKpNedQlM")

	err = CheckKnownhosts("localhost:1047", pubKey1, nil)
	tcheck(err, nil, "verifying with known hosts")

	err = CheckKnownhosts("localhost:1048", pubKey1, nil)
	tcheck(err, ErrRemoteUntrusted, "verifying with known hosts")

	err = CheckKnownhosts("localhost:1048", pubKey2, nil)
	tcheck(err, nil, "verifying with known hosts")

	err = CheckKnownhosts("localhost:1047", pubKeyUnknown, nil)
	tcheck(err, ErrRemoteUntrusted, "verifying with known hosts")

	// Already have other keys for this address.
	err = CheckTrustOnFirstUse("localhost:1047", pubKeyUnknown, nil)
	tcheck(err, ErrRemoteUntrusted, "verifying with known hosts")

	// No entry in known_hosts for public key.
	err = CheckKnownhosts("localhost:1049", pubKeyUnknown, nil)
	tcheck(err, ErrRemoteUntrusted, "verifying with known hosts")

	// Get pubKeyUnknown added for new address.
	err = CheckTrustOnFirstUse("localhost:1049", pubKeyUnknown, nil)
	tcheck(err, nil, "verifying with tofu (adding)")

	// Should still work, just with verification.
	err = CheckTrustOnFirstUse("localhost:1049", pubKeyUnknown, nil)
	tcheck(err, nil, "verifying with tofu (existing)")

	// pubKeyUnknown should now be trusted.
	err = CheckKnownhosts("localhost:1049", pubKeyUnknown, nil)
	tcheck(err, nil, "verifying with known hosts")
}
