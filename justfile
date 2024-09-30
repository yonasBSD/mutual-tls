build:
  go build -v ./cmd/gen-certs
  ./gen-certs -client
  ./gen-certs
  mv client*pem cmd/client/
  cp cert.pem cmd/client/
  mv *pem ./cmd/server/
  cp cmd/client/clientcert.pem ./cmd/server/
  go build -v ./cmd/client
  go build -v ./cmd/server
