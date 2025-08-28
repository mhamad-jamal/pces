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

package issuers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/facebookincubator/pces/cert"
	"golang.org/x/crypto/ssh"
)

// SSHIssuerConfig contains all configuration parameters for SSHIssuer.
type SSHIssuerConfig struct {
	CASigner        ssh.Signer
	CertType        uint32
	KeyID           string
	ValidPrincipals []string
	ValidDuration   time.Duration
	CertSigner      crypto.Signer
	CertDir         string
}

// SSHIssuer implements the cert.Issuer interface for SSH certificates.
type SSHIssuer struct {
	cfg SSHIssuerConfig
}

// Issue implements the cert.Issuer interface method that generates and returns a signed SSH certificate.
func (sshIssuer SSHIssuer) Issue(_ context.Context) (*ssh.Certificate, error) {
	cfg := sshIssuer.cfg
	now := time.Now()

	sshPubKey, err := ssh.NewPublicKey(cfg.CertSigner.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key to SSH format: %w", err)
	}

	cert := &ssh.Certificate{
		CertType:        cfg.CertType,
		Key:             sshPubKey,
		KeyId:           cfg.KeyID,
		ValidPrincipals: cfg.ValidPrincipals,
		ValidAfter:      uint64(now.Unix()),
		ValidBefore:     uint64(now.Add(cfg.ValidDuration).Unix()),
		SignatureKey:    cfg.CASigner.PublicKey(),
	}

	if err := cert.SignCert(rand.Reader, cfg.CASigner); err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	if err := saveSSHCertToFile(cert, cfg.CertSigner, cfg.CertDir); err != nil {
		slog.Warn("failed to save SSH certificate to file", "error", err)
	}

	return cert, nil
}

// NewSSHIssuer creates a new instance of SSHIssuer using a config struct.
func NewSSHIssuer(config SSHIssuerConfig) (*SSHIssuer, error) {
	if config.CASigner == nil {
		return nil, errors.New("caSigner is required but was nil")
	}
	if config.CertSigner == nil {
		return nil, errors.New("certificate signer is required but was nil")
	}

	return &SSHIssuer{cfg: config}, nil
}

func saveSSHCertToFile(sshCert *ssh.Certificate, signer crypto.Signer, certDir string) error {
	if sshCert == nil {
		return fmt.Errorf("certificate is nil")
	}
	if signer == nil {
		return fmt.Errorf("signer is nil")
	}

	// If no certificate directory is specified, skip saving to disk
	if certDir == "" {
		return nil
	}

	if ecdsaKey, ok := signer.(*ecdsa.PrivateKey); ok {
		keyPath := filepath.Join(certDir, cert.TypeSSH)
		keyBytes, err := x509.MarshalECPrivateKey(ecdsaKey)
		if err != nil {
			return fmt.Errorf("failed to marshal ECDSA private key: %w", err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyBytes,
		})

		if err := saveBytesToFile(keyPath, keyPEM, 0600); err != nil {
			return fmt.Errorf("failed to save private key: %w", err)
		}
	}

	certPath := filepath.Join(certDir, fmt.Sprintf("%s.pub", cert.TypeSSH))
	certBytes := ssh.MarshalAuthorizedKey(sshCert)
	if err := saveBytesToFile(certPath, certBytes, 0600); err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}

	return nil
}
