// Copyright 2017 Dyson Simmons. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package certman provides live reloading of the certificate and key
// files used by the standard library http.Server. It defines a type,
// certMan, with methods watching and getting the files.
// Only valid certificate and key pairs are loaded and an optional
// logger can be passed to certman for logging providing it implements
// the logger interface.
package certman

import (
	"crypto/tls"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/pkg/errors"
)

// A CertMan represents a certificate manager able to watch certificate
// and key pairs for changes.
type CertMan struct {
	mu       sync.RWMutex
	certFile string
	keyFile  string
	keyPair  *tls.Certificate
	watcher  *fsnotify.Watcher
	watching chan bool
	log      logger
}

// logger is an interface that wraps the basic Printf method.
type logger interface {
	Printf(string, ...interface{})
}

type nopLogger struct{}

func (l *nopLogger) Printf(format string, v ...interface{}) {}

// New creates a new certMan. The certFile and the keyFile
// are both paths to the location of the files. Relative and
// absolute paths are accepted.
func New(certFile, keyFile string) (*CertMan, error) {
	var err error

	certFile, err = filepath.Abs(certFile)
	if err != nil {
		return nil, err
	}

	keyFile, err = filepath.Abs(keyFile)
	if err != nil {
		return nil, err
	}

	cm := &CertMan{
		mu:       sync.RWMutex{},
		certFile: certFile,
		keyFile:  keyFile,
		log:      &nopLogger{},
	}

	return cm, nil
}

// Logger sets the logger for certMan to use. It accepts
// a logger interface.
func (cm *CertMan) Logger(logger logger) {
	cm.log = logger
}

// Watch starts watching for changes to the certificate
// and key files. On any change the certificate and key
// are reloaded. If there is an issue the load will fail
// and the old (if any) certificates and keys will continue
// to be used.
func (cm *CertMan) Watch() error {
	var err error

	if cm.watcher, err = fsnotify.NewWatcher(); err != nil {
		return errors.Wrap(err, "can't create watcher")
	}

	certPath := path.Dir(cm.certFile)
	keyPath := path.Dir(cm.keyFile)

	if err = cm.watcher.Add(certPath); err != nil {
		return errors.Wrap(err, fmt.Sprintf("can't watch %s", certPath))
	}
	if keyPath != certPath {
		if err = cm.watcher.Add(keyPath); err != nil {
			return errors.Wrap(err, fmt.Sprintf("can't watch %s", keyPath))
		}
	}

	if err := cm.load(); err != nil {
		cm.log.Printf("can't load cert or key file: %v", err)
	}

	cm.log.Printf("watching for cert and key change")

	cm.watching = make(chan bool)

	go cm.run()

	return nil
}

func (cm *CertMan) load() error {
	keyPair, err := tls.LoadX509KeyPair(cm.certFile, cm.keyFile)
	if err == nil {
		cm.mu.Lock()
		defer cm.mu.Unlock()
		cm.keyPair = &keyPair
		cm.log.Printf("certificate and key loaded")
		return nil
	}

	cm.log.Printf("can't load cert or key file: %s", err)

	return err
}

func (cm *CertMan) run() {
	cm.log.Printf("running")

	ticker := time.NewTicker(1 * time.Second)
	files := []string{cm.certFile, cm.keyFile}
	reload := time.Time{}

loop:
	for {
		select {
		case <-cm.watching:
			cm.log.Printf("watching triggered; break loop")
			break loop
		case <-ticker.C:
			if !reload.IsZero() && time.Now().After(reload) {
				reload = time.Time{}
				cm.log.Printf("reloading")
				if err := cm.load(); err != nil {
					cm.log.Printf("can't load cert or key file: %v", err)
				}
			}
		case event := <-cm.watcher.Events:
			// cm.log.Printf("certman: watch event: %s (%s)", event.Name, event.Op.String())
			// cm.log.Printf("certman: watch event: %+v", event)
			for _, f := range files {
				if event.Name == f ||
					strings.HasSuffix(event.Name, "/..data") { // kubernetes secrets mount
					if reload.IsZero() {
						cm.log.Printf("%s was modified (%s), queue reload", f, event.Op.String())
					}
					// we wait a couple seconds in case the cert and key don't update atomically
					reload = time.Now().Add(1 * time.Second)
				}
			}
		case err := <-cm.watcher.Errors:
			cm.log.Printf("error watching files: %v", err)
		}
	}

	cm.log.Printf("stopped watching")

	cm.watcher.Close()
	ticker.Stop()
}

// GetCertificate returns the loaded certificate for use by
// the GetCertificate field in tls.Config.
func (cm *CertMan) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return cm.keyPair, nil
}

// GetClientCertificate returns the loaded certificate for use by
// the GetClientCertificate field in tls.Config.
func (cm *CertMan) GetClientCertificate(hello *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.keyPair, nil
}

// Stop tells certMan to stop watching for changes to the
// certificate and key files.
func (cm *CertMan) Stop() {
	cm.watching <- false
}
