/*
Package nox implements the nox protocol, a bidirectional streaming transport
protocol, mutually authenticated and secured by the noise protocol variant
Noise_XX_25519_ChaChaPoly_BLAKE2b, with simple framing.

The nox protocol uses Curve25519 for static and ephemeral keys.A 32-byte public
key is generated from a 32-byte private key. The static public key serves as an
identity. In this package, keys are stored in base64-raw-url encoding, making
them easy to handle and embed in config files and even URLs.

In nox, both parties typically have trust configured out of bounds, like with
SSH and WireGuard. Nox does not use a PKI (public key infrastructure). No
certificate authorities are involved. Keys do not expire.  No X.509 certificates
are involved.

This package provides a programming interface similar to "net" and "crypto/tls"
for making secure connections. Dial and Listen parse extended nox addresses that
optionally contain public and private keys (described below), making integration
of nox in existing Go code extremely easy.

Errors returned by nox are typically wrapped with additional information. Use
errors.Is() or Unwrap to check for errors.

Security

Nox uses the Noise XX handshake. The ephemeral  key exchange provides forward
secrecy. The static key exchange provides mutual authentication. The static
public key is the identity of the remote party. The identity of the client
remains hidden. Server identities can be probed by any connection. BLAKE2b is
used to hash the handshake into keying material used for symmetric authenticated
encryption (AEAD) used in the transport phase. Nox uses ChaCha20 with Poly1305
as AEAD algorithm.

Nox addresses

Nox uses an address format that can include keys, or specify where the keys
should be read from:

	host:port+local+remote

Host and port are like in regular dial addresses. Local specifies the (source
of) the local private key, remote for the remote's public key.

Local can be a literal private key. Remote can be a comma-separate list of
literal public keys.

Alternatively, nox can read keys from the nearest ".nox" directory. If local
is "fs", the key is read from ".nox/private_key". If remote is "known", a list
of trusted public keys is read from ".nox/known_hosts". Nox uses uses
"+fs+known" as default policy for connections. Nox also recognizes "tofu" for
remote, trusting remote public keys on first use for the dialed address. See
ParseAddress for details.

Use cmd/nox to initialize a ".nox" directory and to create simple servers and
clients.
*/
package nox
