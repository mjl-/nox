nox - bidirectional streaming transport protocol, mutually authenticated and secured by the noise protocol variant Noise_XX_25519_ChaChaPoly_BLAKE2b, with simple framing.

For documentation, see https://godoc.org/github.com/mjl-/nox.
For an example client & server, see cmd/nox/.

The nox protocol is described in PROTOCOL.txt.
See https://noiseprotocol.org/ for the noise protocol families.
This code uses the noise Go library at https://github.com/flynn/noise.

Design inspiration for nox:
- Looking for a nearby .nox directory: hg & git.
- Trust-on-first use with known_hosts file: ssh.
- Go library interface: "net" and "crypto/tls" packages.
- Using noise, small base64 keys, simple setup: wireguard.
- X.509, for what not to want.

# TODO

- need an implementation in another language
- test with go-fuzz
- clear crypto state on close, https://github.com/golang/go/issues/21865
- audit the code
- add benchmark tests, can probably be made more efficient with less data copying
- more tests, counterparty with invalid protocol messages, use a transcript of successful communication.
