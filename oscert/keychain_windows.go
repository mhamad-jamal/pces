// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build windows

package oscert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/facebookincubator/sks"
	"github.com/google/certtostore"
)

// WindowsKeychain implements OSKeychain for Windows certificate store.
type WindowsKeychain struct{}

// NewOSKeychain creates a new Windows-specific keychain implementation.
func NewOSKeychain() OSKeychain {
	return &WindowsKeychain{}
}

// getWinCertStore opens the Windows certificate store for the given certificate.
func (w *WindowsKeychain) getWinCertStore(cert *tls.Certificate) (*certtostore.WinCertStore, error) {
	if cert == nil || len(cert.Certificate) < 1 {
		return nil, fmt.Errorf("failed to fetch wincertstore: certificate missing")
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("winstore: failed to convert tls cert to x509: %w", err)
	}

	return certtostore.OpenWinCertStoreCurrentUser(
		sks.KeyStorageProvider,
		"PCeSCert",
		[]string{x509Cert.Issuer.CommonName},
		[]string{},
		false,
	)
}

// Add adds certificate to Windows certificate store.
func (w *WindowsKeychain) Add(ctx context.Context, cert *tls.Certificate) error {
	if cert == nil {
		return nil
	}

	if len(cert.Certificate) < 2 {
		return fmt.Errorf("winstore: expected both leaf and intermediate certificates")
	}

	leafCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("winstore: failed to parse leaf certificate: %w", err)
	}

	intermediate, err := x509.ParseCertificate(cert.Certificate[1])
	if err != nil {
		return fmt.Errorf("winstore: failed to parse intermediate certificate: %w", err)
	}

	certStore, err := w.getWinCertStore(cert)
	if err != nil {
		return err
	}
	defer certStore.Close()

	_, certContext, err := certStore.CertWithContext()
	if err == nil && certContext != nil {
		defer certtostore.FreeCertContext(certContext)
	}

	if err := certStore.Store(leafCert, intermediate); err != nil {
		return fmt.Errorf("winstore: failed to store certificates: %w", err)
	}

	return nil
}

// Remove removes certificate from Windows certificate store.
// We use the cert parameter only to identify which store to open,
// not to match against the certificate being removed.
func (w *WindowsKeychain) Remove(ctx context.Context, cert *tls.Certificate) error {
	if cert == nil {
		return nil
	}

	certStore, err := w.getWinCertStore(cert)
	if err != nil {
		return err
	}
	defer certStore.Close()

	if err := certStore.Remove(false); err != nil {
		return fmt.Errorf("winstore: failed to remove certificate: %w", err)
	}

	return nil
}

// Status checks if certificate exists in Windows certificate store.
func (w *WindowsKeychain) Status(ctx context.Context, cert *tls.Certificate) error {
	if cert == nil {
		return nil
	}

	certStore, err := w.getWinCertStore(cert)
	if err != nil {
		return fmt.Errorf("failed to open Windows Certificate Store: %w", err)
	}
	defer certStore.Close()

	storeCert, err := certStore.Cert()
	if err != nil {
		return err
	}
	if storeCert == nil {
		return fmt.Errorf("certificate missing")
	}

	passedCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse passed certificate: %w", err)
	}

	if !storeCert.Equal(passedCert) {
		return fmt.Errorf("stored certificate does not match passed certificate")
	}

	return nil
}

// Remediate attempts to fix certificate issues in Windows certificate store.
func (w *WindowsKeychain) Remediate(ctx context.Context, cert *tls.Certificate) error {
	if cert == nil {
		return nil
	}
	return w.Add(ctx, cert)
}
