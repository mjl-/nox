/*
Nox is a tool for making nox connections.

	$ nox
	usage: nox { init | privkey | pubkey | genkeys | listen | dial | remotestatic}

In the example below, we will create ".nox" directories with "nox init". Then
start a server with "nox listen" and make a connection with "nox dial".

Init

Make two directories, one for the client and one for the server, and run "nox
init":

	$ cd client
	client$ nox init
	init: created .nox/private_key
	init: created .nox/known_hosts

	$ cd server
	server$ nox init
	init: created .nox/private_key
	init: created .nox/known_hosts

Pubkey

We need to configure the server to accept the public key of the client. Add a
line to the server's ".nox/known_hosts" file. It requires three space-separated
fields: "nox0" (protocol version), "*" (any network address), public key:

	client$ nox pubkey < .nox/private_key
	byX6M3L2qCU4yAFotRhI1dKOffrU7drs4W7-iIY-1Qc

	server$ echo 'nox0 * byX6M3L2qCU4yAFotRhI1dKOffrU7drs4W7-iIY-1Qc' >>.nox/known_hosts

Listen

Start a server that just echoes back everything it reads:

	server$ nox listen localhost:1047 cat
	listen: listening on localhost:1047, local static public key dveY0PXJfUQn84FOdV3MCCCRz6Na7SccQH_Shcj-Qg4

Because of the default nox address policy "+fs+known", the server found
".nox/private_key". For incoming connections it will check the
".nox/known_hosts".

Dial

Connect to the server:

	client$ nox dial localhost:1047+fs+tofu
	dial: connected to localhost:1047, static public key local byX6M3L2qCU4yAFotRhI1dKOffrU7drs4W7-iIY-1Qc, remote dveY0PXJfUQn84FOdV3MCCCRz6Na7SccQH_Shcj-Qg4

Now type anything and you'll see it echoed back to you by the server.

The connection from client to server succeeded because of the "tofu" directive:
Trust on first use. The client added the public key to its ".nox/known_hosts"
file and will be verified in later connections:

	client$ cat .nox/known_hosts
	nox0 localhost:1047 dveY0PXJfUQn84FOdV3MCCCRz6Na7SccQH_Shcj-Qg4

Remotestatic

To find the remote static public key, you can perform a handshake, learn the
remote key and close the connection. Remotestatic does this and prints it in a
form suitable for adding to a "known_hosts" file:

	$ nox remotestatic localhost:1047
	nox0 localhost:1047 dveY0PXJfUQn84FOdV3MCCCRz6Na7SccQH_Shcj-Qg4

Privkey

Command privkey prints a new private key to stdout.

	$ nox privkey
	gIJoUNK0wVl1ASAZstVR2KAoIREkLduv29TMW0X_HGU

Genkeys

Command genkeys prints a keypair and example nox addresses. These can be used to
quickly set up a nox connection without the use for a ".nox" directory:

	$ nox genkeys
	[...]
	local to remote: localhost:1047+sF8XgswdnBscEhCL24m3dgiQw7HEH0ezt_tq3jbKOr4+YNrfnE9BMY0jZEq-KI8p-CkGlI0nQ-Q9I8Uf7-kRjw4
	remote to local: localhost:1047+Pv1yEwpRnbwNc9O-CCPseDN96Fb7DSKllpBs0DyhDxU+Q3gfkda4WVqhDAD7ypqLHVVknJSFxIUHAfIJBchFfi8

Start the listener:

	$ nox listen localhost:1047+sF8XgswdnBscEhCL24m3dgiQw7HEH0ezt_tq3jbKOr4+YNrfnE9BMY0jZEq-KI8p-CkGlI0nQ-Q9I8Uf7-kRjw4 cat
	listen: listening on localhost:1047, local static public key Q3gfkda4WVqhDAD7ypqLHVVknJSFxIUHAfIJBchFfi8

And connect:

	$ nox dial localhost:1047+Pv1yEwpRnbwNc9O-CCPseDN96Fb7DSKllpBs0DyhDxU+Q3gfkda4WVqhDAD7ypqLHVVknJSFxIUHAfIJBchFfi8
	dial: connected to localhost:1047, static public key local YNrfnE9BMY0jZEq-KI8p-CkGlI0nQ-Q9I8Uf7-kRjw4, remote Q3gfkda4WVqhDAD7ypqLHVVknJSFxIUHAfIJBchFfi8


*/
package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/flynn/noise"
	"github.com/mjl-/nox"
	"golang.org/x/crypto/curve25519"
)

func check(err error, action string) {
	if err != nil {
		log.Fatalf("%s: %s\n", action, err)
	}
}

func main() {
	log.SetFlags(0)

	usage := func() {
		log.Printf("usage: nox { init | privkey | pubkey | genkeys | listen | dial | remotestatic}\n")
		os.Exit(2)
	}
	if len(os.Args) < 2 {
		usage()
	}

	args := os.Args[1:]
	switch os.Args[1] {
	case "init":
		init0(args)
	case "privkey":
		privkey(args)
	case "pubkey":
		pubkey(args)
	case "genkeys":
		genkeys(args)
	case "listen":
		listen(args)
	case "dial":
		dial(args)
	case "remotestatic":
		remotestatic(args)
	default:
		usage()
	}
}

func init0(args []string) {
	log.SetPrefix("init: ")

	if len(args) != 1 {
		log.Fatalln("usage: nox init")
	}

	localKey, err := noise.DH25519.GenerateKeypair(rand.Reader)
	check(err, "generating private key")

	os.MkdirAll(".nox", 0750)

	f, err := os.OpenFile(".nox/private_key", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	check(err, "creating private key file")
	_, err = fmt.Fprintf(f, "%s\n", base64.RawURLEncoding.EncodeToString(localKey.Private))
	check(err, "writing private key file")
	err = f.Close()
	check(err, "closing private key file")
	log.Println("created .nox/private_key")

	f, err = os.OpenFile(".nox/known_hosts", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	check(err, "creating known hosts file")
	err = f.Close()
	check(err, "closing known hosts file")
	log.Println("created .nox/known_hosts")
}

func privkey(args []string) {
	log.SetPrefix("privkey: ")

	if len(args) != 1 {
		log.Fatalln("usage: nox privkey >.nox/private_key")
	}

	localKey, err := noise.DH25519.GenerateKeypair(rand.Reader)
	check(err, "generating private key")
	_, err = fmt.Printf("%s\n", base64.RawURLEncoding.EncodeToString(localKey.Private))
	check(err, "write")
}

func pubkey(args []string) {
	log.SetPrefix("pubkey: ")

	flagset := flag.NewFlagSet(args[0], flag.ExitOnError)
	flagset.Usage = func() {
		log.Println("usage: nox pubkey < .nox/private_key")
		flagset.PrintDefaults()
	}
	flagset.Parse(args[1:])
	args = flagset.Args()
	if len(args) != 0 {
		flagset.Usage()
		os.Exit(2)
	}

	buf, err := ioutil.ReadAll(base64.NewDecoder(base64.RawURLEncoding, os.Stdin))
	check(err, "reading private key")

	if len(buf) != 32 {
		log.Fatalf("bad private key, got %d bytes, expected 32\n", len(buf))
	}
	var privKey, pubKey [32]byte
	copy(privKey[:], buf)
	curve25519.ScalarBaseMult(&pubKey, &privKey)

	_, err = fmt.Printf("%s\n", nox.PublicKey(pubKey[:]))
	check(err, "write")
}

func genkeys(args []string) {
	log.SetPrefix("genkey: ")

	flagset := flag.NewFlagSet(args[0], flag.ExitOnError)
	var address = flagset.String("address", "localhost:1047", "nox address to serve on")
	flagset.Usage = func() {
		log.Println("usage: nox genkeys [flags] [config]")
		flagset.PrintDefaults()
	}
	flagset.Parse(args[1:])
	args = flagset.Args()
	if len(args) != 0 {
		flagset.Usage()
		os.Exit(2)
	}

	localKey, err := noise.DH25519.GenerateKeypair(rand.Reader)
	check(err, "generating local keypair")
	remoteKey, err := noise.DH25519.GenerateKeypair(rand.Reader)
	check(err, "generating remote keypair")

	fmt.Println("local public:", base64.RawURLEncoding.EncodeToString(localKey.Public))
	fmt.Println("local private:", base64.RawURLEncoding.EncodeToString(localKey.Private))
	fmt.Printf("local to remote: %s+%s+%s\n", *address, base64.RawURLEncoding.EncodeToString(localKey.Private), base64.RawURLEncoding.EncodeToString(remoteKey.Public))

	fmt.Println("")
	fmt.Println("remote public:", base64.RawURLEncoding.EncodeToString(remoteKey.Public))
	fmt.Println("remote private:", base64.RawURLEncoding.EncodeToString(remoteKey.Private))
	fmt.Printf("remote to local: %s+%s+%s\n", *address, base64.RawURLEncoding.EncodeToString(remoteKey.Private), base64.RawURLEncoding.EncodeToString(localKey.Public))
}

func listen(args []string) {
	log.SetPrefix("listen: ")

	flagset := flag.NewFlagSet(args[0], flag.ExitOnError)
	flagset.Usage = func() {
		log.Println("usage: nox listen [flags] ext-addr")
		flagset.PrintDefaults()
	}
	flagset.Parse(args[1:])
	args = flagset.Args()
	if len(args) < 1 {
		flagset.Usage()
		os.Exit(2)
	}

	config := &nox.Config{}
	l, err := nox.Listen("tcp", args[0], config)
	check(err, "listen")

	log.Printf("listening on %s, local static public key %s\n", config.Address, config.LocalStaticPublic())

	argv := args[1:]

	input := make(chan []byte)
	if len(argv) == 0 {
		go func() {
			for {
				buf := make([]byte, 128)
				n, err := os.Stdin.Read(buf)
				if err != nil && err != io.EOF {
					check(err, "read from stdin")
				}
				input <- buf[:n]
			}
		}()
	}

	for {
		conn, err := l.Accept()
		check(err, "accept")

		if len(argv) == 0 {
			stdConn(conn.(*nox.Conn), config, input)
		} else {
			go cmdConn(conn.(*nox.Conn), config, argv)
		}
	}
}

func stdConn(conn *nox.Conn, config *nox.Config, input chan []byte) {
	defer conn.Close()

	remoteStatic, err := conn.RemoteStatic()
	if err != nil {
		log.Printf("RemoteStatic: %s\n", err)
		return
	}

	log.Printf("remote static public key %s\n", remoteStatic)

	stop := make(chan struct{}, 1)
	go func() {
		_, err := io.Copy(os.Stdout, conn)
		if err != nil {
			log.Printf("copy from connection: %s", err)
		} else {
			log.Printf("eof from remote")
		}
		stop <- struct{}{}
	}()
	for {
		select {
		case buf := <-input:
			_, err = conn.Write(buf)
			if err != nil {
				log.Printf("write to connection: %s", err)
				return
			}
		case <-stop:
			conn.CloseWrite()
			return
		}
	}
}

func cmdConn(conn *nox.Conn, config *nox.Config, argv []string) {
	defer conn.Close()

	lcheck, handle := errorHandler(func(err error) {
		log.Printf("connection finished: %s\n", err)
	})
	defer handle()

	log.Printf("new connection from %s\n", conn.RemoteAddr())

	remoteStatic, err := conn.RemoteStatic()
	if err != nil {
		log.Printf("RemoteStatic: %s\n", err)
		return
	}

	log.Printf("remote static public key %s\n", remoteStatic)

	cmd := exec.Command(argv[0], argv[1:]...)
	stdin, err := cmd.StdinPipe()
	lcheck(err, "stdin")
	stdout, err := cmd.StdoutPipe()
	lcheck(err, "stdout")
	defer stdout.Close()
	cmd.Stderr = os.Stderr

	go func() {
		_, err := io.Copy(stdin, conn)
		if err != nil {
			log.Printf("copy from connection: %s\n", err)
		}
		stdin.Close()
	}()

	go func() {
		_, err := io.Copy(conn, stdout)
		if err != nil {
			log.Printf("copy to connection: %s\n", err)
		}
		conn.CloseWrite()
		conn.Close()
	}()

	err = cmd.Run()
	lcheck(err, "run")
}

func dial(args []string) {
	log.SetPrefix("dial: ")

	flagset := flag.NewFlagSet(args[0], flag.ExitOnError)
	flagset.Usage = func() {
		log.Println("usage: nox dial [flags] ext-addr")
		flagset.PrintDefaults()
	}
	flagset.Parse(args[1:])
	args = flagset.Args()
	if len(args) < 1 {
		flagset.Usage()
		os.Exit(2)
	}

	config := &nox.Config{}
	conn, err := nox.Dial("tcp", args[0], config)
	check(err, "dial")

	remoteStatic, err := conn.RemoteStatic()
	check(err, "RemoteStatic")
	log.Printf("connected to %s, static public key local %s, remote %s\n", config.Address, config.LocalStaticPublic(), remoteStatic)

	if len(args) == 1 {
		go func() {
			_, err := io.Copy(os.Stdout, conn)
			check(err, "copy")
		}()
		_, err = io.Copy(conn, os.Stdin)
		check(err, "copy")
		conn.CloseWrite()
		return
	}

	argv := args[1:]
	cmd := exec.Command(argv[0], argv[1:]...)
	stdin, err := cmd.StdinPipe()
	check(err, "stdin pipe")
	stdout, err := cmd.StdoutPipe()
	check(err, "stdout pipe")
	cmd.Stderr = os.Stderr

	go func() {
		_, err := io.Copy(stdin, conn)
		check(err, "copy from connection to command")
		stdin.Close()
	}()

	go func() {
		_, err := io.Copy(conn, stdout)
		check(err, "copy from command to connection")
		stdout.Close()
		conn.CloseWrite()
	}()

	err = cmd.Run()
	check(err, "run")
}

func remotestatic(args []string) {
	log.SetPrefix("remotestatic: ")

	flagset := flag.NewFlagSet(args[0], flag.ExitOnError)
	flagset.Usage = func() {
		log.Println("usage: nox remotestatic [flags] addr")
		flagset.PrintDefaults()
	}
	flagset.Parse(args[1:])
	args = flagset.Args()
	if len(args) != 1 {
		flagset.Usage()
		os.Exit(2)
	}

	addr := args[0]
	if len(strings.Split(addr, "+")) == 1 {
		addr += "+new+any"
	}

	config := &nox.Config{}
	conn, err := nox.Dial("tcp", addr, config)
	check(err, "dial")

	remoteStatic, err := conn.RemoteStatic()
	check(err, "RemoteStatic")
	_, err = fmt.Printf("%s %s %s\n", nox.Nox0, config.Address, remoteStatic)
	check(err, "print")
}
