package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"os"
	"time"
)

func main() {
	forClient := flag.Bool("client", false, "Generate client certificates")
	flag.Parse()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)

	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Next, we'll create a certificate template:
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"My Corp"},
		},
		DNSNames:  []string{"build.lan"},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(3 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Each certificate needs a unique serial number; typically, certificate authorities will have these stored in some database but for our local needs a random 128-bit number will do. This is what the first few lines of the snippet are doing.

	// Next comes the x509.Certificate template. For more information on what the fields mean, see the crypto/x509 package docs, as well as RFC 5280. We'll just note that the certificate is valid for 3 hours, and is only valid for the localhost domain.

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, &privateKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	// The certificate is created from the template, and is signed with the private key we've generated earlier. Note that &template is passed in both for the template and parent parameters of CreateCertificate. The latter is what makes this certificate self-signed.

	// This is it, we have the private key for our server and its certificate (which contains the public key, among other information). All that's left now is to serialize them into files. First, the certificate:
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if pemCert == nil {
		log.Fatal("Failed to encode certificate to PEM")
	}

	certfile := "cert.pem"
	if *forClient {
		certfile = "clientcert.pem"
	}

	if err := os.WriteFile(certfile, pemCert, 0600); err != nil {
		log.Fatal(err)
	}
	log.Print("wrote ", certfile, "\n")

	// And then, the private key:
	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if pemKey == nil {
		log.Fatal("Failed to encode key to PEM")
	}

	keyfile := "key.pem"
	if *forClient {
		keyfile = "clientkey.pem"
	}
	if err := os.WriteFile(keyfile, pemKey, 0600); err != nil {
		log.Fatal(err)
	}

	log.Print("wrote ", keyfile, "\n")
}
