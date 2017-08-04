# Certman

[![Go project version](https://badge.fury.io/go/github.com%2Fdyson%2Fcertman.svg)](https://badge.fury.io/go/github.com%2Fdyson%2Fcertman)

[![license](https://img.shields.io/github/license/dyson/certman.svg)](https://github.com/dyson/certman/blob/master/LICENSE)

Go TLS certificate reloading for the standard library http server.

Certman watches for changes to your certificate and key files and reloads them on change allowing the server to stay online during certificate changes. Useful for Let's Encrypt but also just in general as there's no reason to bring your servers down just to update certificates and keys.

## Limitation

Certman handles only a single certificate and key pair and responds to all requests with this pair. It ignores if the client is sending a server name using SNI. I'm not sure if there's a generic enough way to implement this that handles all use cases and as it's a niche feature I haven't needed I've left it out (pull requests welcome!). Certman's codebase is small so either fork the repo or copy and paste it into your project and modify it to your needs.

## Installation
Using dep for dependency management (https://github.com/golang/dep):
```
dep ensure github.com/dyson/certman
```

Using go get:
```
$ go get github.com/dyson/certman
```
## Usage

Generate a cert and key:

```
$ openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -sha256 -keyout /tmp/server.key -out /tmp/server.crt
```
Basic server passing in a logger to log certman events:
```go
package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/dyson/certman"
)

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags)

	cm, err := certman.New("/tmp/server.crt", "/tmp/server.key")
	if err != nil {
		logger.Println(err)
	}
	cm.Logger(logger)
	if err := cm.Watch(); err != nil {
		logger.Println(err)
	}

	http.HandleFunc("/", handler)
	s := &http.Server{
		Addr: ":8080",
		TLSConfig: &tls.Config{
			GetCertificate: cm.GetCertificate,
		},
	}
	if err := s.ListenAndServeTLS("", ""); err != nil {
		logger.Println(err)
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello")
}
```
Visit https://localhost:8080.

Overwrite exising certificate and key using the openssl gen command above.

Visit https://localhost:8080 again. Notice how existing requests are continued to be served by the old certificate.

Visit https://localhost:8080 in another browser and see the new certificate is being served for new requests.

Running example:
```
$ go run main.go
2017/08/01 16:05:23 certman: certificate and key loaded
2017/08/01 16:05:23 certman: watching for cert and key change
# Regenerated certificate and key here
2017/08/01 16:06:30 certman: watch event: "/tmp/server.key": WRITE
2017/08/01 16:06:30 certman: can't load cert or key file: tls: private key does not match public key
2017/08/01 16:06:30 certman: watch event: "/tmp/server.key": WRITE
2017/08/01 16:06:30 certman: can't load cert or key file: tls: private key does not match public key
2017/08/01 16:06:32 certman: watch event: "/tmp/server.crt": WRITE
2017/08/01 16:06:32 certman: certificate and key loaded
# Certificate loaded once the certificate and key can both be read correctly and they match
```

## License
See LICENSE file.
