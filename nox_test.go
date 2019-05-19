package nox

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/xerrors"
)

func check(t *testing.T, got, expect error, action string) {
	t.Helper()

	if got == expect {
		return
	}
	if expect == nil || expect == io.EOF || !xerrors.Is(got, expect) {
		t.Fatalf("%s: got %v, expected %v", action, got, expect)
	}
}

func configPair(t *testing.T) (*Config, noise.DHKey, *Config, noise.DHKey) {
	ckey, err := noise.DH25519.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("generating key: %s", err)
	}

	skey, err := noise.DH25519.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("generating key: %s", err)
	}

	cconfig := &Config{
		LocalStaticPrivateKey:  &ckey,
		remoteStaticPublicKeys: []PublicKey{skey.Public},
	}
	cconfig.LocalStaticPublic()

	sconfig := &Config{
		LocalStaticPrivateKey:  &skey,
		remoteStaticPublicKeys: []PublicKey{ckey.Public},
	}

	return cconfig, ckey, sconfig, skey
}

func TestNox(t *testing.T) {
	tcheck := func(got, exp error, action string) {
		t.Helper()
		check(t, got, exp, action)
	}

	cconfig, ckey, sconfig, skey := configPair(t)
	cr, sw := io.Pipe()
	sr, cw := io.Pipe()

	cconn, err := newConn(&testConn{cr, cw}, cconfig, true, false)
	tcheck(err, nil, "client connection")

	cconfig.LocalStaticPublic()

	sconn, err := newConn(&testConn{sr, sw}, sconfig, false, false)
	tcheck(err, nil, "server connection")

	errc := make(chan error)
	go func() {
		errc <- sconn.Handshake()
	}()

	err = cconn.Handshake()
	tcheck(err, nil, "client handshake")

	err = cconn.Handshake()
	tcheck(err, errHandshakeDone, "second handshake")

	tcheck(<-errc, nil, "server handshake")

	cspubkey, err := cconn.RemoteStatic()
	tcheck(err, nil, "RemoteStatic at client")
	if !bytes.Equal(cspubkey, skey.Public) {
		t.Fatalf("unexpected server key at client, got %s expected %s", cspubkey, PublicKey(skey.Public))
	}
	scpubkey, err := sconn.RemoteStatic()
	tcheck(err, nil, "RemoteStatic at server")
	if !bytes.Equal(scpubkey, ckey.Public) {
		t.Fatalf("unexpected client key at server, got %s expected %s", scpubkey, PublicKey(ckey.Public))
	}

	readwrite := func(t *testing.T, src, dst *Conn, count int) {
		srcbuf := make([]byte, count)
		for i := range srcbuf {
			srcbuf[i] = byte(i)
		}
		ioc := make(chan ioResult)
		go func() {
			dstbuf := make([]byte, count+1)
			n, err := io.ReadFull(sconn, dstbuf[:count])
			if n < 0 {
				n = 0
			}
			ioc <- ioResult{dstbuf[:n], err}
		}()
		n, err := cconn.Write(srcbuf[:count])
		if err != nil {
			t.Fatalf("client write")
		}
		if n != count {
			t.Fatalf("wrote %d bytes, expected 1", n)
		}
		ior := <-ioc
		if ior.err != nil {
			t.Fatalf("server read")
		}
		if !bytes.Equal(srcbuf[:count], ior.buf) {
			t.Fatalf("read/write data mismatch between client/server, client wrote %x, server read %x", srcbuf[:count], ior.buf)
		}
	}

	sizes := []int{
		2, authSize, maxDataSize, noise.MaxMsgLen, 2 * noise.MaxMsgLen,
	}
	for _, size := range sizes {
		t.Run(fmt.Sprintf("cs%d", size-1), func(t *testing.T) { readwrite(t, cconn, sconn, size-1) })
		t.Run(fmt.Sprintf("cs%d", size), func(t *testing.T) { readwrite(t, cconn, sconn, size) })
		t.Run(fmt.Sprintf("cs%d", size+1), func(t *testing.T) { readwrite(t, cconn, sconn, size+1) })

		t.Run(fmt.Sprintf("sc%d", size-1), func(t *testing.T) { readwrite(t, sconn, cconn, size-1) })
		t.Run(fmt.Sprintf("sc%d", size), func(t *testing.T) { readwrite(t, sconn, cconn, size) })
		t.Run(fmt.Sprintf("sc%d", size+1), func(t *testing.T) { readwrite(t, sconn, cconn, size+1) })
	}

	go func() {
		err := sconn.CloseWrite()
		if err == nil {
			_, err = sconn.Read(make([]byte, 1))
			if err == io.EOF {
				err = nil
			}
		}
		if err == nil {
			err = sconn.Close()
		}
		errc <- err
	}()
	_, err = cconn.Read(make([]byte, 1))
	tcheck(err, io.EOF, "read authenticated eof from remote")
	err = cconn.CloseWrite()
	tcheck(err, nil, "client CloseWrite")
	err = cconn.Close()
	tcheck(err, nil, "client Close")
	tcheck(<-errc, nil, "server close")
}

func TestNetwork(t *testing.T) {
	tcheck := func(got, exp error, action string) {
		t.Helper()
		check(t, got, exp, action)
	}

	cconfig1, _, sconfig, _ := configPair(t)
	cconfig2, ckey2, _, _ := configPair(t)

	// Make server trust client2, not not client2 server.
	sconfig.remoteStaticPublicKeys = append(sconfig.remoteStaticPublicKeys, PublicKey(ckey2.Public))

	addr := "127.0.0.1:0"
	l, err := Listen("tcp", addr, sconfig)
	if err != nil {
		t.Fatalf("listen: %s", err)
	}
	defer l.Close()

	accept := func(errc chan error) {
		conn, err := l.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer conn.Close()

		_, err = io.Copy(conn, conn)
		errc <- err
	}

	badRead := errors.New("bad read")

	dial := func(cconfig *Config, errc chan error) {
		t.Helper()

		conn, err := Dial("tcp", l.Addr().String(), cconfig)
		if err != nil {
			errc <- err
			return
		}

		hello := []byte("hello world")
		_, err = conn.Write(hello)
		if err != nil {
			errc <- err
			return
		}
		err = conn.CloseWrite()
		if err != nil {
			errc <- err
			return
		}

		buf := make([]byte, len(hello)+1)
		n, _ := io.ReadFull(conn, buf)
		if n != len(hello) {
			errc <- badRead
		} else {
			errc <- nil
		}
	}

	cerr := make(chan error, 1)
	serr := make(chan error, 1)

	go dial(cconfig1, cerr)
	go accept(serr)
	tcheck(<-cerr, nil, "dial")
	tcheck(<-serr, nil, "accept")

	cconfig2.Address = l.Addr().String()
	cconfig2.CheckPublicKey = nil
	go dial(cconfig2, cerr)
	go accept(serr)
	tcheck(<-cerr, ErrRemoteUntrusted, "dial with untrusted remote")
	tcheck(<-serr, ErrHandshakeAborted, "accept with client disconnecting for lack of trust")

	cconfig2.CheckPublicKey = CheckKnownhosts
	go dial(cconfig2, cerr)
	go accept(serr)
	err = <-cerr
	tcheck(err, ErrRemoteUntrusted, "dial failing because no trusted remote public keys could be found")
	tcheck(err, ErrNoNoxDir, "and it failed because no .nox dir could be found")
	tcheck(<-serr, ErrHandshakeAborted, "accept with client disconnecting for lack of trust")
}

type ioResult struct {
	buf []byte
	err error
}

type testConn struct {
	io.ReadCloser
	io.WriteCloser
}

type addr struct {
}

func (addr) Network() string {
	return "test"
}

func (addr) String() string {
	return "test"
}

func (c *testConn) Close() error {
	err1 := c.ReadCloser.Close()
	err2 := c.WriteCloser.Close()
	if err1 == nil {
		return err2
	}
	return nil
}

func (c *testConn) LocalAddr() net.Addr {
	return addr{}
}

func (c *testConn) RemoteAddr() net.Addr {
	return addr{}
}

func (c *testConn) SetDeadline(t time.Time) error {
	return errors.New("not supported")
}

func (c *testConn) SetReadDeadline(t time.Time) error {
	return errors.New("not supported")
}

func (c *testConn) SetWriteDeadline(t time.Time) error {
	return errors.New("not supported")
}

func TestNegotiation(t *testing.T) {
	tcheck := func(got, exp error, action string) {
		t.Helper()
		check(t, got, exp, action)
	}

	negotiate := func(send, expect []byte) {
		t.Helper()

		cr, sw := io.Pipe()
		sr, cw := io.Pipe()

		_, _, sconfig, _ := configPair(t)

		sconn, err := newConn(&testConn{sr, sw}, sconfig, false, false)
		tcheck(err, nil, "server connection")

		errc := make(chan error)
		go func() {
			errc <- sconn.Handshake()
		}()

		_, err = cw.Write(send)
		tcheck(err, nil, "writing hello of zero length")

		buf := make([]byte, 64)
		n, err := cr.Read(buf)
		tcheck(err, nil, "client reading handshake")

		tcheck(<-errc, ErrVersionMismatch, "no matching protocol")
		if !bytes.Equal(buf[:n], expect) {
			t.Fatalf("unexpected handshake response from server, got %x, expected %x", buf[:n], expect)
		}
	}

	negotiate([]byte("\x00\x00"), []byte("\x00\x04nox0"))
	negotiate([]byte("\x00\x01x"), []byte("\x00\x04nox0"))
	negotiate([]byte("\x00\x03a,b"), []byte("\x00\x04nox0"))
	negotiate([]byte("\x00\x07a,nox0,"), []byte("\x00\x04nox0"))
}
