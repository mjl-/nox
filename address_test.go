package nox

import (
	"log"
	"os"
	"testing"
)

func TestAddress(t *testing.T) {
	tcheck := func(got, exp error, action string) {
		t.Helper()
		check(t, got, exp, action)
	}

	err := ParseAddress("localhost:1047", &Config{})
	tcheck(err, ErrNoNoxDir, "address with default fs but no .nox dir")

	err = ParseAddress("localhost:1047", &Config{Address: "localhost:1047"})
	tcheck(err, nil, "noop, address already parsed")

	err = ParseAddress("localhost:1047", &Config{Address: "localhost:1048"})
	tcheck(err, ErrBadConfig, "invalid attempt to parse address when one is set already")

	err = ParseAddress("localhost:1047+1+2+3", &Config{})
	tcheck(err, ErrBadAddress, "invalid address with 3 plus signs")

	err = ParseAddress("localhost:1047+new", &Config{})
	tcheck(err, nil, "generating new key")

	err = ParseAddress("localhost:1047++", &Config{})
	tcheck(err, ErrNoPrivateKey, "no private key after parsing")

	key := "Wd6ylojy2ZSPos2L1mQFWFLlOKDtTJ2-3IS-TaHNh3c"
	err = ParseAddress("localhost:1047+"+key+"+", &Config{})
	tcheck(err, nil, "literal private key")

	err = ParseAddress("localhost:1047+Wd6ylojy2ZSPos2L1m+", &Config{})
	tcheck(err, ErrBadKey, "short literal private key")

	err = ParseAddress("localhost:1047+Wd6ylojy2ZSPos2L1mQFWFLlOKDtTJ2-3IS-TaHNh3cWd6ylojy2ZSPos2L1mQFWFLlOKDtTJ2-3IS-TaHNh3c+", &Config{})
	tcheck(err, ErrBadKey, "long literal private key")

	err = ParseAddress("localhost:1047+fs+", &Config{})
	tcheck(err, ErrNoNoxDir, "fs without having a .nox directory")

	err = ParseAddress("localhost:1047+new+", &Config{})
	tcheck(err, nil, "generate a new key")

	dir, err := os.Getwd()
	tcheck(err, nil, "get current workdir")
	defer func() {
		err := os.Chdir(dir)
		if err != nil {
			log.Printf("chdir to %s: %s", dir, err)
		}
	}()

	err = os.Chdir("testdata/dotnox")
	tcheck(err, nil, "cd to dir with .nox dir")

	err = ParseAddress("localhost:1047+fs+", &Config{})
	tcheck(err, nil, "fs with a .nox directory")

	err = ParseAddress("localhost:1047+fs+"+key, &Config{})
	tcheck(err, nil, "parsing a remote public key")

	err = ParseAddress("localhost:1047+fs+"+key+","+key, &Config{})
	tcheck(err, nil, "parsing multiple remote public keys")

	err = ParseAddress("localhost:1047+fs+any", &Config{})
	tcheck(err, nil, "accepting any remote key")

	err = ParseAddress("localhost:1047+fs+known", &Config{})
	tcheck(err, nil, "accepting only known remote public keys")

	err = ParseAddress("localhost:1047+fs+tofu", &Config{})
	tcheck(err, nil, "store public key on first use")

	err = ParseAddress("localhost:1047+fs+invalid", &Config{})
	tcheck(err, ErrBadKey, "invalid keyword, will fail to parse")
}
