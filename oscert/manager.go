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

package oscert

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Errors returned by oscert.
var (
	ErrRemediationInProgress = errors.New("another remediation in progress")
	ErrCertNotSet            = errors.New("certificate not set")
)

// OSKeychain is an interface for OS specific implementation of Keychain.
type OSKeychain interface {
	Add(ctx context.Context, cert *tls.Certificate) error
	Remove(ctx context.Context, cert *tls.Certificate) error
	Status(ctx context.Context, cert *tls.Certificate) error
	Remediate(ctx context.Context, cert *tls.Certificate) error
}

// Manager is a wrapper around OS specific implementation of OSKeychain.
// Additionally it provides auto remediation functionality.
type Manager struct {
	lock sync.Mutex

	kc OSKeychain

	cert *tls.Certificate

	token chan struct{}

	logger *slog.Logger
}

// Option is a functional option for Manager.
type Option func(m *Manager)

// WithLogger sets the logger for Manager.
func WithLogger(logger *slog.Logger) Option {
	return func(m *Manager) {
		m.logger = logger
	}
}

// WithCertificate sets the certificate for Manager.
func WithCertificate(cert *tls.Certificate) Option {
	return func(m *Manager) {
		m.cert = cert
	}
}

// New creates a new Manager.
func New(kc OSKeychain, options ...Option) *Manager {
	m := &Manager{
		kc:     kc,
		token:  make(chan struct{}, 1),
		logger: slog.Default(),
	}
	for _, opt := range options {
		opt(m)
	}
	m.token <- struct{}{}
	return m
}

// Add adds a certificate to the OS Keychain.
func (m *Manager) Add(ctx context.Context, cert *tls.Certificate) error {
	if cert == nil {
		return nil
	}

	m.lock.Lock()
	defer m.lock.Unlock()
	return m.kc.Add(ctx, cert)
}

// Remove removes a certificate from the OS Keychain.
func (m *Manager) Remove(ctx context.Context) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.kc.Remove(ctx, m.cert)
}

// Status checks the status of the certificate in the OS Keychain.
func (m *Manager) Status(ctx context.Context) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.cert == nil {
		return ErrCertNotSet
	}
	return m.kc.Status(ctx, m.cert)
}

// Remediate attempts to remediate the certificate in the OS Keychain.
func (m *Manager) Remediate(ctx context.Context, attempts int, cooldown time.Duration) error {
	if err := m.Status(ctx); err == nil {
		m.logger.Info("no remediations needed")
		return nil
	}

	select {
	case <-m.token:
		defer func() {
			m.token <- struct{}{}
		}()
	default:
		return ErrRemediationInProgress
	}

	for attempt := 1; attempt <= attempts; attempt++ {
		m.lock.Lock()
		cert := m.cert
		m.lock.Unlock()

		if err := m.kc.Remediate(ctx, cert); err != nil {
			m.logger.Warn("remediation failed", "attempt", attempt, "err", err)
		}
		if err := m.kc.Status(ctx, cert); err == nil {
			m.logger.Info("remediation success", "attempt", attempt)
			return nil
		}

		if attempt != attempts {
			time.Sleep(cooldown)
		}
	}

	return fmt.Errorf("remediation failed after %d attempts", attempts)
}

// AutoRemediations runs the remediation in a loop with the specified frequency and cooldown.
func (m *Manager) AutoRemediations(ctx context.Context, attempts int, frequency, cooldown time.Duration) {
	if err := m.Remediate(ctx, attempts, cooldown); err != nil {
		m.logger.Error("auto remediation failed", "err", err)
	}

	ticker := time.NewTicker(frequency)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.Remediate(ctx, attempts, cooldown); err != nil {
				m.logger.Error("auto remediation failed", "err", err)
			}
		}
	}
}
