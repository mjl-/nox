package nox

import (
	"encoding/base64"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/xerrors"
)

var newlyGenerated struct {
	sync.Mutex
	key *noise.DHKey
}

// ParseAddress parses a regular "host:port" address, or a nox  address of the form
// "host:port+local+remote". Config is updated with information from "local"
// and "remote". The leftover regular address is stored in config.Address.
//
// "Local" specifies the local static private key, and must be one of:
//
//	- a literal base64-raw-url-encoded key.
//	  Keep in mind this address may be printed or logged, revealing it unintentionally.
//	- "fs", read the key from the file "private_key" from the nearest ".nox"
//	  directory. The default for regular addresses.
//	- "new", a new private key is created and used for the lifetime of the program.
//	- "" (empty string), nothing is done, in which case the "config" parameter must
//	  contain a private key.
//
// "Remote" specifies the remote static public keys, and must be a comma-separated
// list of:
//
//	- a literal base64-raw-url-encoded key.
//	- "known", read the file "known_hosts" for known public keys from the nearest
//	  ".nox" directory. The default for regular addresses.
//	- "tofu", for trust on first use, like "known", but adds a line to the known
//	  hosts file for a previously unseen address, returning an error if no known hosts
//	  file was found.
//	- "any", for trusting any remote public key, this is unsafe and should only be
//	  used for testing or merely fetching the remote's public key.
//
// Example addresses:
//
//	localhost:1047
//	localhost:1047+fs+known
//	localhost:1047+fs+tofu
//	localhost:1047+EzckHRK9zMVib3vIHYc17LztyyabLGaV5F7Z-ye5yRQ+S1KCaHr7wHI4f06GY4uPstZnPC6UIDzwkYq48B3lhG8
//	localhost:1047+new+any
func ParseAddress(address string, config *Config) (rerr error) {
	// NOTE: we don't include the address in error messages: it might contain a private key.

	if address == config.Address {
		return nil
	}
	if config.Address != "" {
		return prefixError(ErrBadConfig, "an address was already parsed into the config")
	}

	t := strings.Split(address, "+")
	if len(t) > 3 {
		return prefixError(ErrBadAddress, "found more than 3 plus-separated tokens in address")
	}

	config.Address = t[0]

	if len(t) < 3 && config.CheckPublicKey == nil {
		config.CheckPublicKey = CheckKnownhosts
	}

	var err error
	if len(t) > 1 {
		err = loadPrivate(t[1], config)
	} else if config.LocalStaticPrivateKey == nil {
		err = loadPrivate("fs", config)
	}
	if err != nil {
		return err
	}

	if len(t) > 2 {
		err = loadPublic(t[2], config)
	} else if config.CheckPublicKey == nil {
		err = loadPublic("known", config)
	}
	return err
}

func parseKey(privBuf []byte) (*noise.DHKey, error) {
	var pubKey, privKey [32]byte
	if len(privBuf) != len(privKey) {
		return nil, prefixError(ErrBadKey, "got %d bytes expected %d bytes", len(privBuf), len(privKey))
	}
	copy(privKey[:], privBuf)
	curve25519.ScalarBaseMult(&pubKey, &privKey)
	key := &noise.DHKey{Private: privKey[:], Public: pubKey[:]}
	return key, nil
}

func loadPrivate(spec string, config *Config) error {
	switch spec {
	case "new":
		if config.LocalStaticPrivateKey != nil {
			return prefixError(ErrBadConfig, "config already has a private key")
		}
		newlyGenerated.Lock()
		defer newlyGenerated.Unlock()
		if newlyGenerated.key == nil {
			key, err := noise.DH25519.GenerateKeypair(nil)
			if err != nil {
				return err
			}
			newlyGenerated.key = &key
		}
		config.LocalStaticPrivateKey = newlyGenerated.key
	case "fs":
		if config.LocalStaticPrivateKey != nil {
			return prefixError(ErrBadConfig, "config already has a private key")
		}
		key, err := readNearestPrivateKeyFile()
		if err != nil {
			return xerrors.Errorf("reading nearest private key in file system: %w", err)
		}
		config.LocalStaticPrivateKey = key
	case "":
		if config.LocalStaticPrivateKey == nil {
			return ErrNoPrivateKey
		}
	default:
		privKey, err := base64.RawURLEncoding.DecodeString(spec)
		if err != nil {
			return prefixError(ErrBadKey, "bad base64-raw-url for private key: %s", err)
		}
		config.LocalStaticPrivateKey, err = parseKey(privKey)
		if err != nil {
			return prefixError(ErrBadKey, "parsing private key: %s", err)
		}
	}
	return nil
}

func loadPublic(spec string, config *Config) error {
	for _, remote := range strings.Split(spec, ",") {
		switch remote {
		case "":
			// nothing to do
		case "known", "tofu", "any":
			if config.CheckPublicKey != nil {
				return prefixError(ErrBadConfig, "config already has a CheckPublicKey configured")
			}
			switch remote {
			case "known":
				config.CheckPublicKey = CheckKnownhosts
			case "tofu":
				config.isTofu = true
				config.CheckPublicKey = CheckTrustOnFirstUse
			case "any":
				config.CheckPublicKey = func(address string, pubKey PublicKey, conn *Conn) error {
					return nil
				}
			default:
				panic("missing case")
			}
		default:
			pubKey, err := base64.RawURLEncoding.DecodeString(remote)
			if err != nil {
				return prefixError(ErrBadKey, "bad base64-raw-url for public key: %s", err)
			}
			if len(pubKey) != 32 {
				return prefixError(ErrBadKey, "invalid remote public key %q: got %d bytes, expect 32", remote, len(pubKey))
			}
			config.remoteStaticPublicKeys = append(config.remoteStaticPublicKeys, pubKey)
		}
	}

	return nil
}

func readNearestPrivateKeyFile() (*noise.DHKey, error) {
	dir, err := NearestNoxDir()
	if err != nil {
		return nil, err
	}

	f, err := os.Open(dir + "/private_key")
	if err != nil {
		return nil, prefixError(ErrNoPrivateKey, "opening private key file: %s", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	perm := info.Mode() & os.ModePerm
	if perm&07 != 0 {
		return nil, prefixError(ErrNoPrivateKey, "refusing to read private key from world-accessible %s", f.Name())
	}

	// Read the private key from file in "buf" below, without making any copies. Clear
	// it when we are done. Afterwards, the only copy will be in the DHKey returned by
	// parseKey.
	buf := make([]byte, 64)
	defer func() {
		for i := range buf {
			buf[i] = 0
		}
	}()
	have := 0
	for {
		n, err := f.Read(buf[have:])
		have += n
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if have == len(buf) {
			return nil, prefixError(ErrBadKey, "too long for a private key")
		}
	}
	n, err := base64.RawURLEncoding.Decode(buf, buf[:have])
	if err != nil {
		return nil, prefixError(ErrBadKey, "decoding base64-raw-url private key: %s", err)
	}
	return parseKey(buf[:n])
}
