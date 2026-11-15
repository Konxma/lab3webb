package main

import (
	"flag"
	"fmt"
	"log"

	"secure-alert-gateway/internal/pki"
)

func main() {
	dir := flag.String("dir", "certs", "new directory for certificates and private keys")
	flag.Parse()
	if err := pki.Generate(*dir); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Created Root CA, server and dispatcher-agent-01 certificates in %s\n", *dir)
}
