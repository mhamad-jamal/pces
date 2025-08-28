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

package storage

import (
	"context"
	"errors"
	"sync"

	"github.com/facebookincubator/pces/cert"
)

type certificate struct {
	c   cert.Certificate
	upd Updater
}

// Storage provides interface to access certificates and
// manages their lifecycle.
type Storage interface {
	Close()
	GetValidCert(ctx context.Context, label string) (any, error)
	Renew(ctx context.Context, label, reason string) error
	Certificates() map[string]cert.Certificate
	Certificate(label string) (cert.Certificate, error)
	Add(label string, c cert.Certificate, upd Updater) error
	Remove(label string) error
}

type storage struct {
	lock sync.Mutex

	certs map[string]certificate
}

// NewStorage creates new certificate storage.
func NewStorage(opts ...StorageOption) Storage {
	st := &storage{
		certs: make(map[string]certificate),
	}

	for _, opt := range opts {
		opt(st)
	}

	for _, v := range st.certs {
		go v.upd.run()
	}

	return st
}

// Close closes Storage st.
func (st *storage) Close() {
	st.lock.Lock()
	defer st.lock.Unlock()
	for _, v := range st.certs {
		v.upd.close()
	}
}

func (st *storage) getCert(label string) (certificate, error) {
	st.lock.Lock()
	defer st.lock.Unlock()
	c, ok := st.certs[label]
	if !ok {
		return certificate{}, cert.ErrCertNotFound
	}
	return c, nil
}

// GetValidCert returns certificate for the label. If the certificate is not valid
// Storage st will attempt to renew it.
func (st *storage) GetValidCert(ctx context.Context, label string) (any, error) {
	certificate, err := st.getCert(label)
	if err != nil {
		return nil, err
	}

	c, err := certificate.c.GetCert(ctx)
	if err == nil {
		return c, nil
	}

	if !errors.Is(err, cert.ErrCertInvalid) {
		return nil, err
	}

	if err = certificate.upd.do(ctx, "get valid"); err != nil {
		return nil, err
	}
	return certificate.c.GetCert(ctx)
}

// Renew renews certificate by the label.
func (st *storage) Renew(ctx context.Context, label, reason string) error {
	certificate, err := st.getCert(label)
	if err != nil {
		return err
	}
	return certificate.upd.do(ctx, reason)
}

// Certificates returns certificates managed by Storage st.
func (st *storage) Certificates() map[string]cert.Certificate {
	m := make(map[string]cert.Certificate)

	st.lock.Lock()
	defer st.lock.Unlock()

	for label, cert := range st.certs {
		m[label] = cert.c
	}
	return m
}

// Certificate returns certificate with label managed by Storage st.
func (st *storage) Certificate(label string) (cert.Certificate, error) {
	st.lock.Lock()
	defer st.lock.Unlock()

	c, ok := st.certs[label]
	if !ok {
		return nil, cert.ErrCertNotFound
	}
	return c.c, nil
}

// Add adds certificate to storage and runs corresponding updater.
func (st *storage) Add(label string, c cert.Certificate, upd Updater) error {
	st.lock.Lock()
	defer st.lock.Unlock()

	if _, ok := st.certs[label]; ok {
		return cert.ErrCertExists
	}

	st.certs[label] = certificate{
		c:   c,
		upd: upd,
	}
	go upd.run()

	return nil
}

// Remove removes cert from the storage stopping corresponding updater.
func (st *storage) Remove(label string) error {
	st.lock.Lock()
	c, ok := st.certs[label]
	if ok {
		delete(st.certs, label)
	}
	st.lock.Unlock()
	if !ok {
		return cert.ErrCertNotFound
	}
	c.upd.close()
	return nil
}
