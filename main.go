package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) <= 1 {
		checkErr(errors.New("Missing host:port argument"))
	}

	host := os.Args[1]
	if !strings.Contains(":", host) {
		host = host + ":443"
	}
	conn, err := tls.Dial("tcp", host, &tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: verifyPeerCert,
	})
	checkErr(err)
	if conn != nil {
		conn.Close()
	}
}

func verifyPeerCert(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	for _, rawCert := range rawCerts {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return err
		}

		certPath := fmt.Sprintf("%s.crt", cert.Subject.CommonName)
		fmt.Println(fmt.Sprintf("Writing %s", certPath))

		file, err := os.Create(certPath)
		if err != nil {
			return err
		}
		defer file.Close()

		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.RawTBSCertificate,
		}
		err = pem.Encode(file, block)
		if err != nil {
			return err
		}
	}

	return nil
}

func checkErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n%s\n", err)
		os.Exit(1)
	}
}
