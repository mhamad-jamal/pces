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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func getTLSCert() *tls.Certificate {
	return &tls.Certificate{
		Certificate: [][]byte{[]byte("test")},
	}
}

func TestManagerWithLogger(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	kc := NewMockOSKeychain(ctrl)
	cert := getTLSCert()
	// By default logger is initialised with slog.Default(), see New() function.
	m := New(kc, WithCertificate(cert), WithLogger(nil))
	assert.Equal(t, cert, m.cert)
	assert.Equal(t, kc, m.kc)
	assert.Nil(t, m.logger)
}

func TestManagerAdd(t *testing.T) {
	t.Run("add error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		err := errors.New("test error")
		kc := NewMockOSKeychain(ctrl)
		cert := getTLSCert()
		m := New(kc, WithCertificate(cert))
		kc.EXPECT().Add(gomock.Any(), cert).Return(err)
		assert.Error(t, err, m.Add(context.Background(), cert))
	})

	t.Run("nil cert success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		kc := NewMockOSKeychain(ctrl)
		m := New(kc)
		assert.NoError(t, m.Add(context.Background(), nil))
	})

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		kc := NewMockOSKeychain(ctrl)
		cert := getTLSCert()
		m := New(kc, WithCertificate(cert))
		kc.EXPECT().Add(gomock.Any(), cert).Return(nil)
		assert.NoError(t, m.Add(context.Background(), cert))
	})
}

func TestManagerRemove(t *testing.T) {
	t.Run("error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		err := errors.New("test error")
		kc := NewMockOSKeychain(ctrl)
		cert := getTLSCert()
		m := New(kc, WithCertificate(cert))
		kc.EXPECT().Remove(gomock.Any(), cert).Return(err)
		assert.Error(t, err, m.Remove(context.Background()))
	})

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		kc := NewMockOSKeychain(ctrl)
		cert := getTLSCert()
		m := New(kc, WithCertificate(cert))
		kc.EXPECT().Remove(gomock.Any(), cert).Return(nil)
		assert.NoError(t, m.Remove(context.Background()))
	})
}

func TestManagerStatus(t *testing.T) {
	t.Run("error cert not set", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		kc := NewMockOSKeychain(ctrl)
		m := New(kc)
		assert.Error(t, ErrCertNotSet, m.Status(context.Background()))
	})

	t.Run("error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		err := errors.New("test error")
		kc := NewMockOSKeychain(ctrl)
		cert := getTLSCert()
		m := New(kc, WithCertificate(cert))
		kc.EXPECT().Status(gomock.Any(), cert).Return(err)
		assert.Error(t, err, m.Status(context.Background()))
	})

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		kc := NewMockOSKeychain(ctrl)
		cert := getTLSCert()
		m := New(kc, WithCertificate(cert))
		kc.EXPECT().Status(gomock.Any(), cert).Return(nil)
		assert.NoError(t, m.Status(context.Background()))
	})
}

func TestManagerRemediate(t *testing.T) {
	cert := getTLSCert()

	t.Run("no remediation needed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		kc := NewMockOSKeychain(ctrl)
		kc.EXPECT().Status(gomock.Any(), cert).Return(nil)
		m := New(kc, WithCertificate(cert))
		assert.NoError(t, m.Remediate(context.Background(), 3, time.Second))
	})

	t.Run("another remediation in progress", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		kc := NewMockOSKeychain(ctrl)
		m := New(kc)
		<-m.token // simulate remediation in progress.
		assert.Error(t, ErrRemediationInProgress, m.Remediate(context.Background(), 3, time.Second))
	})

	t.Run("failed attempts", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		err := errors.New("test error")

		kc := NewMockOSKeychain(ctrl)
		attempts := 3
		cooldown := 500 * time.Millisecond
		kc.EXPECT().Status(gomock.Any(), cert).Return(err).Times(attempts + 1)
		kc.EXPECT().Remediate(gomock.Any(), cert).Return(err).Times(attempts)
		m := New(kc, WithCertificate(cert))
		start := time.Now()
		assert.Error(t, m.Remediate(context.Background(), attempts, cooldown))
		elapsed := time.Since(start)
		assert.True(t, elapsed >= time.Duration(attempts-1)*cooldown)
	})

	t.Run("success second attempt", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		err := errors.New("test error")

		kc := NewMockOSKeychain(ctrl)
		attempts := 3
		cooldown := 500 * time.Millisecond
		kc.EXPECT().Status(gomock.Any(), cert).Return(err).Times(2)
		kc.EXPECT().Status(gomock.Any(), cert).Return(nil)
		kc.EXPECT().Remediate(gomock.Any(), cert).Return(err)
		kc.EXPECT().Remediate(gomock.Any(), cert).Return(nil)
		m := New(kc, WithCertificate(cert))
		start := time.Now()
		assert.NoError(t, m.Remediate(context.Background(), attempts, cooldown))
		elapsed := time.Since(start)
		assert.True(t, elapsed >= cooldown)
	})
}
