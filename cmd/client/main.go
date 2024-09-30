package main

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
)

//go:embed clientcert.pem
var embedClientCert []byte

//go:embed clientkey.pem
var embedClientKey []byte

//go:embed cert.pem
var embedServerCert []byte

func main() {
	addr := flag.String("addr", "localhost:4000", "HTTPS server address")
	//certFile := flag.String("certfile", "cert.pem", "trusted CA certificate")
	//clientCertFile := flag.String("clientcert", "clientcert.pem", "certificate PEM for client")
	//clientKeyFile := flag.String("clientkey", "clientkey.pem", "key PEM for client")

	flag.Parse()

	// Load our client certificate and key.
	clientCert, err := tls.X509KeyPair(embedClientCert, embedClientKey)
	if err != nil {
		log.Fatal(err)
	}

	// Trusted server certificate.
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(embedServerCert); !ok {
		log.Fatalf("unable to parse cert from %s", embedServerCert)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      certPool,
				Certificates: []tls.Certificate{clientCert},
				MinVersion:   tls.VersionTLS13,
			},
		},
	}

	r, err := client.Get("https://" + *addr)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Body.Close()

	html, err := io.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%v\n", r.Status)
	fmt.Printf(string(html))
}
