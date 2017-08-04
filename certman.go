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
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/pkg/errors"
)

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
		return errors.Wrap(err, "certman: can't create watcher")
	}
	if err = cm.watcher.Add(cm.certFile); err != nil {
		return errors.Wrap(err, "certman: can't watch cert file")
	}
	if err = cm.watcher.Add(cm.keyFile); err != nil {
		return errors.Wrap(err, "certman: can't watch key file")
	}
	if err := cm.load(); err != nil {
		cm.log.Printf("certman: can't load cert or key file: %v", err)
	}
	cm.log.Printf("certman: watching for cert and key change")
	cm.watching = make(chan bool)
	go func() {
	loop:
		for {
			select {
			case <-cm.watching:
				break loop
			case event := <-cm.watcher.Events:
				cm.log.Printf("certman: watch event: %v", event)
				if err := cm.load(); err != nil {
					cm.log.Printf("certman: can't load cert or key file: %v", err)
				}
			case err := <-cm.watcher.Errors:
				cm.log.Printf("certman: error watching files: %v", err)
			}
		}
		cm.log.Printf("certman: stopped watching")
		cm.watcher.Close()
		close(cm.watching)
	}()
	return nil
}

func (cm *CertMan) load() error {
	keyPair, err := tls.LoadX509KeyPair(cm.certFile, cm.keyFile)
	if err == nil {
		cm.mu.Lock()
		cm.keyPair = &keyPair
		cm.mu.Unlock()
		cm.log.Printf("certman: certificate and key loaded")
	}
	return err
}

// GetCertificate returns the loaded certificate for use by
// the TLSConfig fields GetCertificate field in a http.Server.
func (cm *CertMan) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.keyPair, nil
}

// Stop tells certMan to stop watching for changes to the
// certificate and key files.
func (cm *CertMan) Stop() {
	cm.watching <- false
}
