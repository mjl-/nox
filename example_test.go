package nox_test

import (
	"io"
	"log"

	"github.com/mjl-/nox"
)

func ExampleDial() {
	// Connecting with the default "+fs+known" policy. Requires having a ".nox"
	// directory with "known_hosts" and "private_key" files.
	config := &nox.Config{}
	conn, err := nox.Dial("tcp", "localhost:1047", config)
	if err != nil {
		log.Fatalf("dial: %s", err)
	}
	// Handshake was completed, remote is trusted.

	conn.Close()
}

func ExampleDial_keys() {
	// Connecting with an address that includes private & public keys.
	address := "localhost:1047+9Raaywe4hLyJT7olZjwbjuGShPmqV0YD6aiX9r2uwps+nwpSVXwaGB5EpsRQvNyAzG1CYAGdJr5MrDhAvsdTyCs"
	config := &nox.Config{}
	conn, err := nox.Dial("tcp", address, config)
	if err != nil {
		log.Fatalf("dial: %s", err)
	}
	// Handshake was completed, remote is trusted.

	conn.Close()
}

func ExampleListen() {
	// Use defaults "+fs+known" to make server read ".nox/private_key" and ".nox/known_hosts".
	address := "localhost:1047"

	config := &nox.Config{}
	l, err := nox.Listen("tcp", address, config)
	if err != nil {
		log.Fatalf("listen: %s", err)
	}

	log.Printf("listening on %s, local static public key %s\n", config.Address, config.LocalStaticPublic())

	serve := func(conn *nox.Conn) {
		defer conn.Close()
		io.Copy(conn, conn)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatalf("accept: %s", err)
		}

		go serve(conn.(*nox.Conn))
	}
}
