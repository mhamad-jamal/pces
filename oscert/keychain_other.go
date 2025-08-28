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

//go:build !windows

package oscert

import (
	"context"
	"crypto/tls"
	"fmt"
)

// DummyKeychain implements OSKeychain for other OS certificate stores.
type DummyKeychain struct{}

// NewOSKeychain creates a new keychain implementation.
func NewOSKeychain() OSKeychain {
	return &DummyKeychain{}
}

// Add adds certificate to certificate store.
func (l *DummyKeychain) Add(_ context.Context, _ *tls.Certificate) error {
	return fmt.Errorf("certificate store implementation not yet available")
}

// Remove removes certificate from certificate store.
func (l *DummyKeychain) Remove(_ context.Context, _ *tls.Certificate) error {
	return fmt.Errorf("certificate store implementation not yet available")
}

// Status checks if certificate exists in certificate store.
func (l *DummyKeychain) Status(_ context.Context, _ *tls.Certificate) error {
	return fmt.Errorf("certificate store implementation not yet available")
}

// Remediate attempts to fix certificate issues in certificate store.
func (l *DummyKeychain) Remediate(_ context.Context, _ *tls.Certificate) error {
	return fmt.Errorf("certificate store implementation not yet available")
}
