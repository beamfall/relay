package config

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// CertificateReloader serves one last-known-good TLS certificate while safely
// replacing it after an explicit signal or certificate/key mtime change.
type CertificateReloader struct {
	certFile string
	keyFile  string
	logger   *slog.Logger

	certificate atomic.Pointer[tls.Certificate]
	mu          sync.Mutex
	certState   certificateFileState
	keyState    certificateFileState
}

type certificateFileState struct {
	modTime time.Time
	size    int64
}

// NewCertificateReloader loads the initial certificate before any listener can
// bind. Later reload failures leave this initial or most recently loaded pair
// available to GetCertificate.
func NewCertificateReloader(certFile, keyFile string, logger *slog.Logger) (*CertificateReloader, error) {
	if logger == nil {
		logger = slog.Default()
	}
	certificate, certState, keyState, _, err := loadCertificatePair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	reloader := &CertificateReloader{
		certFile:  certFile,
		keyFile:   keyFile,
		logger:    logger,
		certState: certState,
		keyState:  keyState,
	}
	reloader.certificate.Store(certificate)
	return reloader, nil
}

// GetCertificate returns the current immutable pair for each new TLS
// handshake. Existing carrier sessions continue with the pair they negotiated.
func (r *CertificateReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.certificate.Load(), nil
}

// Reload replaces the active pair even when file metadata is unchanged. It is
// used for explicit operator-triggered reloads such as SIGHUP.
func (r *CertificateReloader) Reload(reason string) error {
	_, err := r.reload(reason, false)
	return err
}

// ReloadIfChanged replaces the active pair only after either file's mtime or
// size changes. A failed parse deliberately leaves the remembered metadata
// unchanged so the next poll retries the replacement.
func (r *CertificateReloader) ReloadIfChanged(reason string) (bool, error) {
	return r.reload(reason, true)
}

// Watch reloads on an explicit signal and polls file metadata at interval until
// ctx is cancelled. Production uses a one-minute interval; tests use a shorter
// interval to exercise the same path deterministically.
func (r *CertificateReloader) Watch(ctx context.Context, interval time.Duration, reloadSignals <-chan os.Signal) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case signal := <-reloadSignals:
			if signal != nil {
				_ = r.Reload(signal.String())
			}
		case <-ticker.C:
			_, _ = r.ReloadIfChanged("mtime poll")
		}
	}
}

func (r *CertificateReloader) reload(reason string, onlyIfChanged bool) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if onlyIfChanged {
		certState, keyState, err := statCertificatePair(r.certFile, r.keyFile)
		if err != nil {
			r.logReloadFailure(reason, err)
			return false, err
		}
		if certState == r.certState && keyState == r.keyState {
			return false, nil
		}
	}

	certificate, certState, keyState, notAfter, err := loadCertificatePair(r.certFile, r.keyFile)
	if err != nil {
		r.logReloadFailure(reason, err)
		return false, err
	}
	r.certificate.Store(certificate)
	r.certState = certState
	r.keyState = keyState
	r.logger.Info("carrier TLS certificate reloaded", "reason", reason, "not_after", notAfter.UTC().Format(time.RFC3339))
	return true, nil
}

func (r *CertificateReloader) logReloadFailure(reason string, err error) {
	r.logger.Warn("carrier TLS certificate reload failed; keeping last good certificate", "reason", reason, "err", err)
}

func loadCertificatePair(certFile, keyFile string) (*tls.Certificate, certificateFileState, certificateFileState, time.Time, error) {
	certBefore, keyBefore, err := statCertificatePair(certFile, keyFile)
	if err != nil {
		return nil, certificateFileState{}, certificateFileState{}, time.Time{}, err
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, certificateFileState{}, certificateFileState{}, time.Time{}, fmt.Errorf("load TLS key pair: %w", err)
	}
	certAfter, keyAfter, err := statCertificatePair(certFile, keyFile)
	if err != nil {
		return nil, certificateFileState{}, certificateFileState{}, time.Time{}, err
	}
	if certBefore != certAfter || keyBefore != keyAfter {
		return nil, certificateFileState{}, certificateFileState{}, time.Time{}, fmt.Errorf("certificate files changed while loading")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, certificateFileState{}, certificateFileState{}, time.Time{}, fmt.Errorf("parse leaf certificate: %w", err)
	}
	return &certificate, certAfter, keyAfter, leaf.NotAfter, nil
}

func statCertificatePair(certFile, keyFile string) (certificateFileState, certificateFileState, error) {
	certInfo, err := os.Stat(certFile)
	if err != nil {
		return certificateFileState{}, certificateFileState{}, fmt.Errorf("stat TLS certificate: %w", err)
	}
	keyInfo, err := os.Stat(keyFile)
	if err != nil {
		return certificateFileState{}, certificateFileState{}, fmt.Errorf("stat TLS key: %w", err)
	}
	return certificateFileState{modTime: certInfo.ModTime(), size: certInfo.Size()},
		certificateFileState{modTime: keyInfo.ModTime(), size: keyInfo.Size()}, nil
}
