package nox

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

type knownHost struct {
	Version    string
	Address    string
	PublicKey  PublicKey
	Linenumber int
}

func readKnownHosts() (string, map[string][]knownHost, error) {
	dir, err := NearestNoxDir()
	if err != nil {
		return "", nil, err
	}

	filename := dir + "/known_hosts"
	f, err := os.Open(filename)
	if err != nil {
		return "", nil, prefixError(ErrNoKnownHosts, "opening known hosts file: %s", err)
	}
	defer f.Close()

	knownHosts := map[string][]knownHost{}

	b := bufio.NewReader(f)
	linenumber := 0
	for {
		line, err := b.ReadString('\n')
		if err != nil && err != io.EOF {
			return filename, nil, err
		}
		if line == "" && err == io.EOF {
			break
		}
		linenumber++
		if strings.HasSuffix(line, "\n") {
			line = line[:len(line)-1]
		}
		t := strings.Split(line, " ")
		if len(t) != 3 {
			return filename, nil, prefixError(errBadKnownHosts, "%s:%d: malformed line, expect three space-separated words", filename, linenumber)
		}
		version, address, pubKeyStr := t[0], t[1], t[2]
		if version != Nox0 {
			continue
		}

		pubKey, err := base64.RawURLEncoding.DecodeString(pubKeyStr)
		if err != nil {
			return filename, nil, prefixError(errBadKnownHosts, "%s:%d: malformed public key %q: %s", filename, linenumber, pubKeyStr, err)
		}
		if len(pubKey) != 32 {
			return filename, nil, prefixError(errBadKnownHosts, "%s:%d: invalid public key, got length %d, must be 32", filename, linenumber, len(pubKey))
		}
		kh := knownHost{
			Version:    version,
			Address:    address,
			PublicKey:  PublicKey(pubKey),
			Linenumber: linenumber,
		}
		knownHosts[address] = append(knownHosts[address], kh)
	}
	return filename, knownHosts, nil
}

func addKnownHost(address string, pubKey PublicKey) error {
	f, err := findNearestFile(".nox/known_hosts")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()

	os.MkdirAll(path.Dir(name), 0700)
	f, err = os.OpenFile(name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "%s %s %s\n", Nox0, address, pubKey)
	if err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// CheckKnownhosts looks up address in the "known_hosts" file in the nearest ".nox"
// directory. If it is present and the public key matches, CheckKnownhosts returns
// nil.
//
// CheckKnownhosts implements the remote specifier "known" in nox addresses.
func CheckKnownhosts(address string, pubKey PublicKey, conn *Conn) error {
	filename, knownHosts, err := readKnownHosts()
	if err != nil {
		return err
	}
	l, ok := knownHosts[address]
	if !ok {
		return prefixError(ErrRemoteUntrusted, "unknown host %q with public key %s", address, pubKey)
	}
	for _, kh := range l {
		if bytes.Equal(kh.PublicKey, pubKey) {
			return nil
		}
	}
	if len(l) == 1 {
		return prefixError(ErrRemoteUntrusted, "%s:%d: key mismatch for %q, got %s, expected %s, potential MITM", filename, l[0].Linenumber, address, pubKey, l[0].PublicKey)
	}
	return prefixError(ErrRemoteUntrusted, "%s: none of the multiple keys for %q match", filename, address)
}

// CheckTrustOnFirstUse is like CheckKnownhosts. If a public key is associated with
// the address in the "known_hosts" file, the check passes. If the address is not
// in the "known_hosts" file, CheckTrustOnFirstUse adds the remote public key to
// the file. Future connections to the same address require the same public key
// from remote.
//
// It is an error if the "known_hosts" file does not exist yet.
//
// CheckTrustOnFirstUse implements the remote specifier "tofu" in nox addresses.
func CheckTrustOnFirstUse(address string, pubKey PublicKey, conn *Conn) error {
	filename, knownHosts, err := readKnownHosts()
	if err != nil {
		return err
	}
	l, ok := knownHosts[address]
	if !ok {
		err := addKnownHost(address, pubKey)
		if err != nil {
			return fmt.Errorf("adding %s with public key %s to known hosts file: %s", address, pubKey, err)
		}
		return nil
	}
	for _, kh := range l {
		if bytes.Equal(kh.PublicKey, pubKey) {
			return nil
		}
	}
	if len(l) == 1 {
		return prefixError(ErrRemoteUntrusted, "%s:%d: key mismatch for %q, got %s, expected %s, potential MITM", filename, l[0].Linenumber, address, pubKey, l[0].PublicKey)
	}
	return prefixError(ErrRemoteUntrusted, "%s: none of the multiple keys for %q match", filename, address)
}
