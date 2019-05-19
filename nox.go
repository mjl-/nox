package nox

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	mathrand "math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/xerrors"
)

const (
	// authSize authenticator bytes are appended to encrypted data by ChaCha20-Poly1305.
	authSize = 16

	// maxDataSize is the maximum size of the data message, including padding.
	maxDataSize = noise.MaxMsgLen - authSize

	minMsgSize       = 16
	maxRandomPadding = 16

	// Nox0 is the fist version identifier for the hello message in protocol negotiation.
	Nox0 = "nox0"
)

var (
	// Versions holds the nox protocol versions supported by this package.
	Versions = []string{Nox0}

	// ErrVersionMismatch is returned when no mutually supported nox version could be
	// negotiated.
	ErrVersionMismatch = errors.New("protocol version mismatch")

	// ErrNoPrivateKey indicates no private key was found, either in the config or
	// through the nox address.
	ErrNoPrivateKey = errors.New("no private key")

	// ErrBadKey indicates a key is not valid, either public or private. Possibly
	// invalid base64-raw-url-encoded data, or not 32 bytes.
	ErrBadKey = errors.New("bad key")

	// ErrBadAddress is returned when a nox address is malformed.
	ErrBadAddress = errors.New("malformed nox address")

	// ErrBadConfig is returned when a config and address cannot be turned into a
	// usable Config.
	ErrBadConfig = errors.New("invalid configuration/address combination")

	// ErrHandshakeAborted is returned when the client disconnects after seeing the
	// server's static key. This may indicate the client does not trust the server, or
	// that the client is probing the server for its static key.
	ErrHandshakeAborted = errors.New("handshake aborted by client")

	// ErrRemoteUntrusted is returned when the remote host did not have a trusted
	// static public key.
	ErrRemoteUntrusted = errors.New("remote untrusted")

	// ErrProtocol is returned for protocol-level errors, like malformed messages.
	ErrProtocol = errors.New("protocol error")

	// ErrNoHandshake is returned for operations before having completed the handshake.
	ErrNoHandshake = errors.New("handshake not completed yet")

	// ErrConnClosed is returned when calling functions on a closed connection.
	ErrConnClosed = errors.New("connection closed")

	// ErrNoNoxDir indicates no .nox directory was found.
	ErrNoNoxDir = errors.New("no .nox directory found")

	// ErrNoKnownHosts indicates no .nox/known_hosts file was found.
	ErrNoKnownHosts = errors.New("no .nox/known_hosts file was found")

	errHandshakeDone = errors.New("handshake already completed")
	errDataTooBig    = prefixError(ErrProtocol, "data too big")
	errNoConfig      = errors.New("nil config passed to function")
	errBadKnownHosts = errors.New("malformed .nox/known_hosts file")
	errServerTofu    = errors.New("trust-on-first-use not usable for server")
)

// PublicKey presents a 32-byte public curve25519 key, for either local or remote.
type PublicKey []byte

// String returns a base64-raw-url-encoded version of the public key.
func (k PublicKey) String() string {
	return base64.RawURLEncoding.EncodeToString(k)
}

// Config holds the authentication credentials for the secure nox connection.
type Config struct {
	// Rand is used as source of cryptographic randomness in Nox. If nil, Reader from
	// crypto/rand is used.
	Rand io.Reader

	// Address to dial or listen after parsing nox address. Set by ParseAddress, which
	// is also called by Dial and Listen.
	Address string

	// LocalStaticPrivateKey is the private key used in the Noise protocol.
	// Can be set by direct assignment, through a nox address containing a private key,
	// or through the "fs" keyword.
	LocalStaticPrivateKey *noise.DHKey

	// Filled from explicit public addresses in the nox address.
	remoteStaticPublicKeys []PublicKey

	// CheckPublicKey is called (if set) to verify a remote public key for an address.
	// For server connections, the address passed to CheckPublicKey is "*".
	// See CheckKnownhosts and CheckTrustOnFirstUse.
	CheckPublicKey func(address string, pubKey PublicKey, conn *Conn) error
	isTofu         bool
}

// Conn is a nox connection.
type Conn struct {
	conn        net.Conn
	noiseConfig noise.Config
	config      *Config

	handshake struct {
		sync.Mutex
		completed bool
		err       error
	}

	// Fields below only valid after completed handshake.

	state *noise.HandshakeState
	enc   *noise.CipherState
	dec   *noise.CipherState

	reader struct {
		sync.Mutex
		scratch [maxDataSize + authSize]byte // Either holds unread bytes, or used for scratch space while decrypting.
		buf     []byte                       // Slice into reader.scratch for readReady bytes to read.
		err     error                        // Set to io.EOF when remote sent zero-sized buffer.
	}

	writer struct {
		writing uint32 // Whether currently writing; Write, CloseWrite and Close interact with sync/atomic.

		sync.Mutex
		out  *bufio.Writer
		prng *mathrand.Rand
		err  error // Set to ErrConnClosed after CloseWrite().
	}
}

// LocalAddr returns the local network address of the underlying connection.
func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address of the underlying connection.
func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline calls the SetDeadline on the underlying connection.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline calls the SetReadDeadline on the underlying connection.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline calls the SetWriteDeadline on the underlying connection.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// LocalStaticPublic returns the local public static key.
//
// If no private key has been configured, LocalStaticPublic calls panic.
func (c *Config) LocalStaticPublic() PublicKey {
	if c.LocalStaticPrivateKey == nil {
		panic("LocalStaticPrivateKey not yet set")
	}
	return PublicKey(c.LocalStaticPrivateKey.Public)
}

// Dial connects to the remote and performs the nox handshake and checks if the
// remote is trusted.
//
// Dial calls ParseAddress on address, which can be a nox address.
func Dial(network, address string, config *Config) (*Conn, error) {
	if config == nil {
		return nil, errNoConfig
	}

	err := ParseAddress(address, config)
	if err != nil {
		return nil, xerrors.Errorf("parsing address: %w", err)
	}

	conn, err := net.Dial(network, config.Address)
	if err != nil {
		return nil, err
	}
	nc, err := newConn(conn, config, true, true)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return nc, nil
}

// Client turns an existing (non-nox) connection in a nox connection.
// On failure, the existing connection is not closed.
func Client(conn net.Conn, config *Config) (*Conn, error) {
	return newConn(conn, config, true, true)
}

// Server turns an existing (non-nox) connection in a nox connection.
// On failure, the existing connection is not closed.
func Server(conn net.Conn, config *Config) (*Conn, error) {
	return newConn(conn, config, false, true)
}

type listener struct {
	net.Listener
	config *Config
}

// Listen creates a new listener for incoming connections.
// Accept on the returned listener returns a *Conn with the handshake not yet
// completed. The first read or write performs the handshake, as does calling
// RemoteAddress.
//
// Listen calls ParseAddress on address, which can be a nox address.
func Listen(network, address string, config *Config) (net.Listener, error) {
	if config == nil {
		return nil, errNoConfig
	}
	err := ParseAddress(address, config)
	if err != nil {
		return nil, xerrors.Errorf("parsing address: %w", err)
	}

	l, err := net.Listen(network, config.Address)
	if err != nil {
		return nil, err
	}
	r := &listener{
		Listener: l,
		config:   config,
	}
	return r, nil
}

// Accept accepts an incoming connection.
// The returned connection has not completed a handshake. The handshake can be
// triggered explicitly by calling Handshake. The handshake will also be performed
// automatically on first Read or Write.
func (l *listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	nc, err := newConn(conn, l.config, false, false)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return nc, nil
}

// newConn turns an existing connection into a nox.Conn.
func newConn(conn net.Conn, config *Config, isInitiator bool, shake bool) (*Conn, error) {
	if config == nil {
		return nil, errNoConfig
	}
	if config.LocalStaticPrivateKey == nil {
		return nil, ErrNoPrivateKey
	}

	if !isInitiator && config.isTofu {
		return nil, errServerTofu
	}

	random := config.Rand
	if random == nil {
		random = rand.Reader
	}
	noiseConfig := noise.Config{
		Random:        random,
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b),
		Pattern:       noise.HandshakeXX,
		Initiator:     isInitiator,
		StaticKeypair: *config.LocalStaticPrivateKey,
	}
	c := &Conn{
		conn:        conn,
		noiseConfig: noiseConfig,
		config:      config,
		writer: struct {
			writing uint32
			sync.Mutex
			out  *bufio.Writer
			prng *mathrand.Rand
			err  error
		}{
			out:  bufio.NewWriter(conn),
			prng: mathrand.New(mathrand.NewSource(time.Now().UnixNano())),
		},
	}
	if shake {
		err := c.Handshake()
		if err != nil {
			return nil, xerrors.Errorf("handshake: %w", err)
		}
	}
	return c, nil
}

// RemoteStatic returns the remote's static public key.
// RemoteStatic ensures a handshake has been completed.
func (c *Conn) RemoteStatic() (PublicKey, error) {
	err := c.ensureHandshake()
	if err != nil {
		return nil, xerrors.Errorf("handshake: %w", err)
	}
	return PublicKey(c.state.PeerStatic()), nil
}

// ensureHandshake performs the handshake if it has not already been completed.
func (c *Conn) ensureHandshake() error {
	c.handshake.Lock()
	defer c.handshake.Unlock()
	if !c.handshake.completed && c.handshake.err == nil {
		return c.shakehands()
	}
	return c.handshake.err
}

// Handshake performs the protocol handshake: first version negotation, then noise
// handshake. Read, Write or RemoteAddress on a new connection ensures a handshake
// is done.
//
// Handshake returns an error if a handshake has already completed or failed.
func (c *Conn) Handshake() error {
	c.handshake.Lock()
	defer c.handshake.Unlock()
	if c.handshake.err != nil {
		return c.handshake.err
	}
	if c.handshake.completed {
		return errHandshakeDone
	}
	return c.shakehands()
}

// Must be called with lock held.
func (c *Conn) shakehands() (rerr error) {
	defer func() {
		if rerr != nil {
			c.handshake.err = rerr
		}
	}()
	lcheck, handle := errorHandler(func(xerr error) {
		rerr = xerr
	})
	defer handle()

	readHello := func() ([]byte, []string, error) {
		size := make([]byte, 2)
		_, err := io.ReadFull(c.conn, size)
		if err != nil {
			return nil, nil, err
		}
		length := int(size[0])<<8 | int(size[1])
		buf := make([]byte, 2+length)
		buf[0], buf[1] = size[0], size[1]
		_, err = io.ReadFull(c.conn, buf[2:])
		if err != nil {
			return nil, nil, err
		}
		versions := strings.Split(string(buf[2:]), ",")
		return buf, versions, nil
	}

	writeHello := func(versions []string) ([]byte, error) {
		vbuf := []byte(strings.Join(versions, ","))
		buf := make([]byte, 2+len(vbuf))
		buf[0] = uint8(len(vbuf) >> 8)
		buf[1] = uint8(len(vbuf))
		copy(buf[2:], vbuf)
		_, err := c.conn.Write(buf)
		return buf, err
	}

	matchVersion := func(versions []string) string {
		for _, v := range Versions {
			if versions[0] == v {
				return v
			}
		}
		return ""
	}

	var err error
	var helloInitiator, helloResponder []byte

	if c.noiseConfig.Initiator {
		helloInitiator, err = writeHello(Versions)
		lcheck(err, "writing hello")

		var versions []string
		helloResponder, versions, err = readHello()
		lcheck(err, "reading hello")

		version := matchVersion(versions)
		if version == "" {
			return prefixError(ErrVersionMismatch, "asked %q, received %q", string(helloInitiator[2:]), string(string(helloResponder[2:])))
		}
	} else {
		var versions []string
		helloInitiator, versions, err = readHello()
		lcheck(err, "reading hello")

		version := matchVersion(versions)
		helloResponder, err = writeHello([]string{Nox0})
		lcheck(err, "writing hello")

		if version == "" {
			return prefixError(ErrVersionMismatch, "client asked %q, we support none", string(helloInitiator[2:]))
		}
	}

	c.noiseConfig.Prologue = append(append([]byte{}, helloInitiator...), helloResponder...)
	c.state, err = noise.NewHandshakeState(c.noiseConfig)
	lcheck(err, "noise.NewHandshakeState")

	write := func() (*noise.CipherState, *noise.CipherState) {
		buf, i2r, r2i, err := c.state.WriteMessage(nil, nil)
		lcheck(err, "making noise handshake message")
		_, err = c.conn.Write(buf)
		lcheck(err, "writing noise handshake")
		return i2r, r2i
	}

	read := func(n int, checkHandshakeEOF bool) (*noise.CipherState, *noise.CipherState) {
		buf := make([]byte, n)
		_, err = io.ReadFull(c.conn, buf)
		if checkHandshakeEOF && err == io.EOF {
			lcheck(ErrHandshakeAborted, "reading client final handshake message")
		}
		lcheck(err, "reading message")
		_, i2r, r2i, err := c.state.ReadMessage(nil, buf)
		lcheck(err, "parsing noise handshake message")
		return i2r, r2i
	}

	if c.noiseConfig.Initiator {
		write()
		read(96, false)

		err := c.verifyRemote(PublicKey(c.state.PeerStatic()))
		if err != nil {
			return err
		}

		i2r, r2i := write()
		c.enc, c.dec = i2r, r2i
	} else {
		read(32, false)
		write()
		i2r, r2i := read(64, true)
		c.enc, c.dec = r2i, i2r

		err := c.verifyRemote(PublicKey(c.state.PeerStatic()))
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Conn) verifyRemote(pubKey PublicKey) error {
	for _, k := range c.config.remoteStaticPublicKeys {
		if bytes.Equal(k, pubKey) {
			c.handshake.completed = true
			return nil
		}
	}

	if c.config.CheckPublicKey != nil {
		remoteAddress := "*"
		if c.noiseConfig.Initiator {
			remoteAddress = c.config.Address
			if remoteAddress == "" {
				remoteAddress = c.RemoteAddr().String()
			}
		}
		err := c.config.CheckPublicKey(remoteAddress, pubKey, c)
		if err == nil {
			c.handshake.completed = true
			return nil
		}
		return &wrapErr{ErrRemoteUntrusted, err}
	}

	return prefixError(ErrRemoteUntrusted, "unknown remote static public key %s", pubKey)
}

// Read reads data from remote. Read returns io.EOF after an explicit close message
// from remote. Early hangups of the underlying connection result in an error other
// than io.EOF.
func (c *Conn) Read(buf []byte) (read int, rerr error) {
	lcheck, handle := errorHandler(func(xerr error) {
		rerr = xerr
		if c.reader.err == nil {
			c.reader.err = xerr
		}
	})
	defer handle()

	err := c.ensureHandshake()
	lcheck(err, "ensuring handshake")

	c.reader.Lock()
	defer c.reader.Unlock()

	if len(buf) == 0 {
		return 0, nil
	}

	if len(buf) > 0 && len(c.reader.buf) == 0 {
		var xsize [4 + authSize]byte
		_, err = io.ReadFull(c.conn, xsize[:])
		if err == io.EOF {
			// Closing the underlying connection is not an authenticated EOF.
			err = io.ErrUnexpectedEOF
		}
		lcheck(err, "reading size message")
		size, err := c.dec.Decrypt(nil, nil, xsize[:])
		lcheck(err, "decrypting size message")

		cn := int(size[0])<<8 | int(size[1])
		padn := int(size[2])<<8 | int(size[3])

		if cn+padn > maxDataSize {
			return 0, errDataTooBig
		}

		_, err = io.ReadFull(c.conn, c.reader.scratch[:cn+padn+authSize])
		if err == io.EOF {
			// Closing the underlying connection is not an authenticated EOF.
			err = io.ErrUnexpectedEOF
		}
		lcheck(err, "reading data message")

		c.reader.buf, err = c.dec.Decrypt(c.reader.scratch[:0], nil, c.reader.scratch[:cn+padn+authSize])
		lcheck(err, "decrypting data message")
		c.reader.buf = c.reader.buf[:cn]

		if cn == 0 {
			c.reader.err = io.EOF
			return 0, io.EOF
		}
	}

	n := len(c.reader.buf)
	if n > len(buf) {
		n = len(buf)
	}
	copy(buf, c.reader.buf[:n])
	c.reader.buf = c.reader.buf[n:]
	return n, nil
}

// Write writes data to remote.
func (c *Conn) Write(buf []byte) (written int, rerr error) {
	err := c.ensureHandshake()
	if err != nil {
		return 0, err
	}

	c.writer.Lock()
	defer c.writer.Unlock()

	// We do not send zero-sized writes to remote, because that would signal EOF.
	if len(buf) == 0 {
		return 0, nil
	}

	return c.write(buf)
}

// Must be called with writer lock held.
func (c *Conn) write(buf []byte) (written int, rerr error) {
	lcheck, handle := errorHandler(func(xerr error) {
		rerr = xerr
		if c.writer.err == nil {
			c.writer.err = xerr
		}
	})
	defer handle()

	atomic.StoreUint32(&c.writer.writing, 1)
	defer atomic.StoreUint32(&c.writer.writing, 0)

	write := func(out []byte) {
		xout := c.enc.Encrypt(nil, nil, out)
		_, err := c.writer.out.Write(xout)
		lcheck(err, "writing")
	}

	var size [4]byte
	for first := true; len(buf) > 0 || first; first = false {
		cn := len(buf)
		if cn > maxDataSize {
			cn = maxDataSize
		}
		padn := 0
		if cn < minMsgSize {
			padn = minMsgSize - cn
		}
		if cn+maxRandomPadding <= maxDataSize {
			padn += int(c.writer.prng.Int31n(maxRandomPadding))
		}

		size[0] = uint8(cn >> 8)
		size[1] = uint8(cn)
		size[2] = uint8(padn >> 8)
		size[3] = uint8(padn)
		write(size[:])

		out := make([]byte, cn+padn)
		copy(out, buf[:cn])
		write(out)

		written += cn
		buf = buf[cn:]
	}

	err := c.writer.out.Flush()
	lcheck(err, "writing")

	return written, nil
}

// CloseWrite sends a zero-sized write to remote to indicate the end of data to
// remote. Data can still be read from remote until an EOF from remote is read.
// CloseWrite does not close the underlying connection.
func (c *Conn) CloseWrite() error {
	c.handshake.Lock()
	hsErr, hsOK := c.handshake.err, c.handshake.completed
	c.handshake.Unlock()
	if hsErr != nil {
		return hsErr
	}
	if !hsOK {
		return ErrNoHandshake
	}

	c.writer.Lock()
	defer c.writer.Unlock()
	if c.writer.err != nil {
		return c.writer.err
	}
	_, err := c.write([]byte{})
	if err != nil {
		return xerrors.Errorf("writing eof message: %w", err)
	}

	c.writer.err = ErrConnClosed
	return nil
}

// Close closes the connection. If still connected, Close sends a message to signal
// EOF to remote, as in CloseWrite. Close then closes the underlying connection. If
// a write is in progress, Close immediately closes the underlying connection,
// assuming Close was called to abort.
func (c *Conn) Close() error {
	c.handshake.Lock()
	handshakeCompleted := c.handshake.completed
	handShakeErr := c.handshake.err
	c.handshake.Unlock()

	// If we have a working connection, and no write in progress, then we send an explicit EOF to remote.
	var err error
	writerClosed := false
	if handShakeErr == nil && handshakeCompleted && atomic.LoadUint32(&c.writer.writing) == 0 {
		c.writer.Lock()
		defer c.writer.Unlock()
		if c.writer.err == nil {
			_, err = c.write([]byte{})
		}
		c.writer.err = ErrConnClosed
		writerClosed = true
	}

	err2 := c.conn.Close()
	if err == nil {
		err = err2
	}

	c.reader.Lock()
	c.reader.err = ErrConnClosed
	c.reader.Unlock()

	if !writerClosed {
		c.writer.Lock()
		c.writer.err = ErrConnClosed
		c.writer.Unlock()
	}

	c.handshake.Lock()
	c.handshake.err = ErrConnClosed
	c.handshake.Unlock()

	c.reader.buf = nil
	buf := c.reader.scratch[:]
	for i := range buf {
		buf[i] = 0
	}

	return err
}
