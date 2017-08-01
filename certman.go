package certman

import (
	"crypto/tls"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/pkg/errors"
)

type certMan struct {
	mu       sync.RWMutex
	certFile string
	keyFile  string
	keyPair  *tls.Certificate
	watcher  *fsnotify.Watcher
	watching chan bool
	log      logger
}

type logger interface {
	Printf(string, ...interface{})
}

type nopLogger struct{}

func (l *nopLogger) Printf(format string, v ...interface{}) {}

func NewCertMan(certFile, keyFile string) (*certMan, error) {
	var err error
	certFile, err = filepath.Abs(certFile)
	if err != nil {
		return nil, err
	}
	keyFile, err = filepath.Abs(keyFile)
	if err != nil {
		return nil, err
	}
	cm := &certMan{
		mu:       sync.RWMutex{},
		certFile: certFile,
		keyFile:  keyFile,
		log:      &nopLogger{},
	}
	return cm, nil
}

func (cm *certMan) Logger(logger logger) {
	cm.log = logger
}

func (cm *certMan) Watch() error {
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

func (cm *certMan) load() error {
	keyPair, err := tls.LoadX509KeyPair(cm.certFile, cm.keyFile)
	if err == nil {
		cm.mu.Lock()
		cm.keyPair = &keyPair
		cm.mu.Unlock()
		cm.log.Printf("certman: certificate and key loaded")
	}
	return err
}

func (cm *certMan) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.keyPair, nil
}

func (cm *certMan) Stop() {
	cm.watching <- false
}
