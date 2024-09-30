package main

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"flag"
	"fmt"
	"log"
	"net/http"
)

//go:embed clientcert.pem
var embedClientCert []byte

//go:embed cert.pem
var embedServerCert []byte

//go:embed key.pem
var embedServerKey []byte

func main() {
	addr := flag.String("addr", ":4000", "HTTPS network address")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			http.NotFound(w, req)
			return
		}
		fmt.Fprintf(w, "Proudly served with Go and HTTPS!")
	})

	// Load the embedded certificate and key
	cert, err := tls.X509KeyPair(embedServerCert, embedServerKey)
	if err != nil {
		log.Fatalf("failed to load X.509 key pair: %v", err)
	}

	// Trusted client certificate.
	clientCertPool := x509.NewCertPool()
	clientCertPool.AppendCertsFromPEM(embedClientCert)

	srv := &http.Server{
		Addr:    *addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS13,
			PreferServerCipherSuites: true,
			ClientCAs:                clientCertPool,
			ClientAuth:               tls.RequireAndVerifyClientCert,
			Certificates:             []tls.Certificate{cert},
		},
	}

	log.Printf("Starting server on %s", *addr)
	err = srv.ListenAndServeTLS("", "")
	log.Fatal(err)
}
