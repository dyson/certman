// Copyright 2017 Dyson Simmons. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package certman_test

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dyson/certman"
)

func TestValidPair(t *testing.T) {
	buf := new(bytes.Buffer)
	l := log.New(buf, "", 0)

	cm, err := certman.New("./testdata/server1.crt", "./testdata/server1.key")
	if err != nil {
		t.Fatalf("could not create certman: %v", err)
	}

	cm.Logger(l)
	if err := cm.Watch(); err != nil {
		t.Fatalf("could not watch files: %v", err)
	}

	logWant := "certificate and key loaded\n" +
		"watching for cert and key change\n"
	logGot := buf.String()

	if logGot != logWant {
		t.Log("log output expected:", logWant)
		t.Log("log output received:", logGot)
		t.Fatal("log from certman not as expected")
	}
}

func TestInvalidPair(t *testing.T) {
	buf := new(bytes.Buffer)
	l := log.New(buf, "", 0)

	cm, err := certman.New("./testdata/server1.crt", "./testdata/server2.key")
	if err != nil {
		t.Fatalf("could not create certman: %v", err)
	}

	cm.Logger(l)
	if err := cm.Watch(); err != nil {
		t.Fatalf("could not watch files: %v", err)
	}

	logWant := "can't load cert or key file: tls: private key does not match public key\n" +
		"watching for cert and key change\n"
	logGot := buf.String()

	if logGot != logWant {
		t.Log("log output expected:", logWant)
		t.Log("log output received:", logGot)
		t.Fatalf("test didn't in the way expected")
	}
}

func TestCertificateNotFound(t *testing.T) {
	buf := new(bytes.Buffer)
	l := log.New(buf, "", 0)

	cm, err := certman.New("./testdata/nothere.crt", "./testdata/server2.key")
	if err != nil {
		t.Fatalf("could not create certman: %v", err)
	}

	cm.Logger(l)
	if err := cm.Watch(); err != nil {
		if !strings.HasPrefix(err.Error(), "can't watch cert file:") {
			t.Fatalf("unexpected watch error: %v", err)
		}
	}
}

func TestKeyNotFound(t *testing.T) {
	buf := new(bytes.Buffer)
	l := log.New(buf, "", 0)
	cm, err := certman.New("./testdata/server1.crt", "./testdata/nothere.key")

	if err != nil {
		t.Fatalf("could not create certman: %v", err)
	}

	cm.Logger(l)
	if err := cm.Watch(); err != nil {
		if !strings.HasPrefix(err.Error(), "can't watch key file:") {
			t.Fatalf("unexpected watch error: %v", err)
		}
	}
}

func TestValidPairValidPair(t *testing.T) {
	buf := new(bytes.Buffer)
	l := log.New(buf, "", 0)

	copyPair("./testdata/server1.crt", "./testdata/server1.key")

	cm, err := certman.New("./testdata/server.crt", "./testdata/server.key")
	if err != nil {
		t.Fatalf("could not create certman: %v", err)
	}

	cm.Logger(l)
	if err := cm.Watch(); err != nil {
		t.Fatalf("could not watch files: %v", err)
	}

	logWant := "certificate and key loaded\n" +
		"watching for cert and key change\n"
	logGot := buf.String()

	if logGot != logWant {
		t.Log("log output expected:", logWant)
		t.Log("log output received:", logGot)
		t.Fatalf("log from certman not as expected")
	}

	buf.Reset()
	copyPair("./testdata/server2.crt", "./testdata/server2.key")

	time.Sleep(200 * time.Millisecond)

	logWant = "certificate and key loaded"
	logGot = strings.Split(buf.String(), "\n")[3]

	if logGot != logWant {
		t.Log("log output expected:", logWant)
		t.Log("log output received:", logGot)
		t.Fatalf("log from certman not as expected")
	}
}

func TestValidPairInvalidPair(t *testing.T) {
	buf := new(bytes.Buffer)
	l := log.New(buf, "", 0)

	copyPair("./testdata/server1.crt", "./testdata/server1.key")

	cm, err := certman.New("./testdata/server.crt", "./testdata/server.key")
	if err != nil {
		t.Fatalf("could not create certman: %v", err)
	}

	cm.Logger(l)
	if err := cm.Watch(); err != nil {
		t.Fatalf("could not watch files: %v", err)
	}

	logWant := "certificate and key loaded\n" +
		"watching for cert and key change\n"
	logGot := buf.String()

	if logGot != logWant {
		t.Log("log output expected:", logWant)
		t.Log("log output received:", logGot)
		t.Fatalf("log from certman not as expected")
	}

	buf.Reset()

	copyPair("./testdata/server1.crt", "./testdata/server2.key")

	time.Sleep(200 * time.Millisecond)

	logWant = "can't load cert or key file: tls: private key does not match public key"
	logGot = strings.Split(buf.String(), "\n")[3]

	if logGot != logWant {
		t.Log("log output expected:", logWant)
		t.Log("log output received:", logGot)
		t.Fatalf("log from certman not as expected")
	}
}

func TestStop(t *testing.T) {
	buf := new(bytes.Buffer)
	l := log.New(buf, "", 0)

	copyPair("./testdata/server1.crt", "./testdata/server1.key")

	cm, err := certman.New("./testdata/server.crt", "./testdata/server.key")
	if err != nil {
		t.Fatalf("could not create certman: %v", err)
	}

	cm.Logger(l)
	if err := cm.Watch(); err != nil {
		t.Fatalf("could not watch files: %v", err)
	}

	logWant := "certificate and key loaded\n" +
		"watching for cert and key change\n"
	logGot := buf.String()

	if logGot != logWant {
		t.Log("log output expected:", logWant)
		t.Log("log output received:", logGot)
		t.Fatalf("log from certman not as expected")
	}

	buf.Reset()
	cm.Stop()

	copyPair("./testdata/server2.crt", "./testdata/server2.key")
	time.Sleep(200 * time.Millisecond)

	logWant = "stopped watching\n"
	logGot = buf.String()

	if logGot != logWant {
		t.Log("log output expected:", logWant)
		t.Log("log output received:", logGot)
		t.Fatalf("log from certman not as expected")
	}
}

func TestGetCertificate(t *testing.T) {
	cm, err := certman.New("./testdata/server1.crt", "./testdata/server1.key")
	if err != nil {
		t.Fatalf("could not create certman: %v", err)
	}

	if err := cm.Watch(); err != nil {
		t.Fatalf("could not watch files: %v", err)
	}

	hello := &tls.ClientHelloInfo{}

	cmCert, err := cm.GetCertificate(hello)
	if err != nil {
		t.Fatalf("could not get certman certificate")
	}

	expectedCert, _ := tls.LoadX509KeyPair("./testdata/server1.crt", "./testdata/server1.key")
	if err != nil {
		t.Fatalf("could not load certificate and key files to test: %v", err)
	}

	if !reflect.DeepEqual(cmCert.Certificate, expectedCert.Certificate) {
		t.Fatalf("certman certificate doesn't match expected certificate")
	}

}

func copyPair(crt, key string) {
	// ignore error handling
	crtSource, _ := os.Open(crt)
	defer crtSource.Close()

	crtDest, _ := os.Create("./testdata/server.crt")
	defer crtDest.Close()

	io.Copy(crtDest, crtSource)

	keySource, _ := os.Open(key)
	defer keySource.Close()

	keyDest, _ := os.Create("./testdata/server.key")
	defer keyDest.Close()

	io.Copy(keyDest, keySource)
}
