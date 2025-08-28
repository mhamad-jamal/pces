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

package sshagent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/facebookincubator/pces/cert"
)

func TestNew(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	st := NewMockStorage(ctrl)

	a, err := New(st)
	assert.NoError(t, err)

	assert.Equal(t, st, a.st)
	assert.Equal(t, 30*time.Second, a.requestTimeout, "Default request timeout should be 30 seconds")
}

func TestWithRequestTimeout(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	st := NewMockStorage(ctrl)

	customTimeout := 60 * time.Second
	a, err := New(st, WithRequestTimeout(customTimeout))
	assert.NoError(t, err)

	assert.Equal(t, customTimeout, a.requestTimeout, "Request timeout should be set to the custom value")
}

func TestWithKeys(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	st := NewMockStorage(ctrl)

	key1, signer1, err := getSSHSigner()
	assert.NoError(t, err)
	key2, signer2, err := getSSHSigner()
	assert.NoError(t, err)
	keys := []agent.AddedKey{
		{PrivateKey: key1},
		{PrivateKey: key2},
	}

	t.Run("success", func(t *testing.T) {
		a, err := New(st, WithKeys(keys))
		assert.NoError(t, err)

		got, err := a.keyring.List()
		assert.NoError(t, err)
		want := []*agent.Key{
			{Format: signer1.PublicKey().Type(), Blob: signer1.PublicKey().Marshal()},
			{Format: signer2.PublicKey().Type(), Blob: signer2.PublicKey().Marshal()},
		}
		assert.Equal(t, want, got)
	})

	t.Run("error", func(t *testing.T) {
		keys := []agent.AddedKey{
			{PrivateKey: signer1}, // wrong type
		}
		_, err := New(st, WithKeys(keys))
		assert.Error(t, err)
	})
}

func TestWithLogger(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	st := NewMockStorage(ctrl)

	a, err := New(st, WithLogger(nil))
	assert.NoError(t, err)
	assert.Nil(t, a.logger)
}

func TestLockUnlock(t *testing.T) {
	a := Agent{
		keyring: agent.NewKeyring(),
	}
	pass := []byte("hunter2")

	assert.NoError(t, a.Lock(pass))
	assert.ErrorIs(t, a.Lock(pass), ErrAgentLocked)
	assert.Error(t, a.Unlock([]byte("incorrect-password")))
	assert.NoError(t, a.Unlock(pass))
	assert.ErrorIs(t, a.Unlock(pass), ErrAgentNotLocked)
}

func TestLocked(t *testing.T) {
	a := Agent{
		keyring: agent.NewKeyring(),
	}
	assert.NoError(t, a.Lock([]byte("hunter2")))
	keys, err := a.List()
	assert.NoError(t, err)
	assert.Nil(t, keys)

	assert.ErrorIs(t, a.Add(agent.AddedKey{}), ErrAgentLocked)
	assert.ErrorIs(t, a.Remove(nil), ErrAgentLocked)
	assert.ErrorIs(t, a.RemoveAll(), ErrAgentLocked)

	_, err = a.Sign(nil, nil)
	assert.ErrorIs(t, err, ErrAgentLocked)

	_, err = a.Signers()
	assert.ErrorIs(t, err, ErrAgentLocked)
}

func TestRemove(t *testing.T) {
	a := Agent{}
	assert.ErrorIs(t, a.Remove(nil), ErrNotImplemented)
	assert.ErrorIs(t, a.RemoveAll(), ErrNotImplemented)
}

func TestAdd(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	keyring := NewMockAgent(ctrl)
	a := Agent{keyring: keyring}

	key := agent.AddedKey{Comment: "test"}
	testError := errors.New("test error")
	keyring.EXPECT().Add(key).Return(nil)
	keyring.EXPECT().Add(key).Return(testError)

	assert.NoError(t, a.Add(key))
	assert.ErrorIs(t, a.Add(key), testError)

	assert.ErrorIs(t, a.Add(agent.AddedKey{Certificate: new(ssh.Certificate)}), ErrNotImplemented)
}

func TestSigners(t *testing.T) {
	sshCert, signer, certSigner, err := getSSHCertificate()
	assert.NoError(t, err)

	c, err := cert.NewSSH(signer, nil, cert.WithSSHCert(sshCert))
	assert.NoError(t, err)

	key1, signer1, err := getSSHSigner()
	assert.NoError(t, err)
	key2, signer2, err := getSSHSigner()
	assert.NoError(t, err)
	keys := []agent.AddedKey{
		{PrivateKey: key1},
		{PrivateKey: key2},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	st := NewMockStorage(ctrl)
	st.EXPECT().Certificates().Return(map[string]cert.Certificate{
		"test": c,
	})

	a, err := New(st, WithKeys(keys))
	assert.NoError(t, err)

	got, err := a.Signers()
	assert.NoError(t, err)
	want := []ssh.Signer{
		signer1, signer2, certSigner,
	}
	assert.Equal(t, want, got)
}

func TestList(t *testing.T) {
	sshCert, signer, certSigner, err := getSSHCertificate()
	assert.NoError(t, err)

	c, err := cert.NewSSH(signer, nil, cert.WithSSHCert(sshCert))
	assert.NoError(t, err)
	key1, signer1, err := getSSHSigner()
	assert.NoError(t, err)
	key2, signer2, err := getSSHSigner()
	assert.NoError(t, err)
	keys := []agent.AddedKey{
		{PrivateKey: key1},
		{PrivateKey: key2},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	st := NewMockStorage(ctrl)
	st.EXPECT().Certificates().Return(map[string]cert.Certificate{
		"test": c,
	})

	a, err := New(st, WithKeys(keys))
	assert.NoError(t, err)

	got, err := a.List()
	assert.NoError(t, err)

	want := []*agent.Key{
		{Format: signer1.PublicKey().Type(), Blob: signer1.PublicKey().Marshal()},
		{Format: signer2.PublicKey().Type(), Blob: signer2.PublicKey().Marshal()},
		{Format: certSigner.PublicKey().Type(), Blob: certSigner.PublicKey().Marshal()},
	}

	assert.Equal(t, want, got)
}

func TestSign(t *testing.T) {
	sshCert, signer, certSigner, err := getSSHCertificate()
	assert.NoError(t, err)

	c, err := cert.NewSSH(signer, nil, cert.WithSSHCert(sshCert))
	assert.NoError(t, err)
	key, keySigner, err := getSSHSigner()
	assert.NoError(t, err)
	_, notFound, err := getSSHSigner()
	assert.NoError(t, err)

	keys := []agent.AddedKey{
		{PrivateKey: key},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	st := NewMockStorage(ctrl)
	st.EXPECT().Certificates().AnyTimes().Return(map[string]cert.Certificate{
		"test": c,
	})

	a, err := New(st, WithKeys(keys))
	assert.NoError(t, err)

	dataToSign := []byte("data to sign")

	for _, test := range []struct {
		name    string
		signer  ssh.Signer
		success bool
	}{
		{"with keyring", keySigner, true},
		{"with cert", certSigner, true},
		{"not found", notFound, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			sig, err := a.Sign(test.signer.PublicKey(), dataToSign)
			if test.success {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				return
			}

			err = test.signer.PublicKey().Verify(dataToSign, sig)
			assert.NoError(t, err)
		})
	}
}

func TestInterceptor(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	st := NewMockStorage(ctrl)

	_, signer, err := getSSHSigner()
	assert.NoError(t, err)

	var (
		gotMethods []string
		gotErrors  []error
	)
	testInterceptor := func(method string, duration time.Duration, err error) {
		gotMethods = append(gotMethods, method)
		gotErrors = append(gotErrors, err)
	}

	a, err := New(st, WithInterceptor(testInterceptor))
	assert.NoError(t, err)

	pass := []byte("hunter2")

	a.Lock(pass)
	a.List()
	a.Sign(signer.PublicKey(), []byte("data to sign"))
	a.Signers()
	a.Add(agent.AddedKey{Comment: "test"})
	a.Remove(signer.PublicKey())
	a.RemoveAll()
	a.Unlock(pass)

	wantMethods := []string{"Lock", "List", "Sign", "Signers", "Add", "Remove", "RemoveAll", "Unlock"}
	wantErrors := []error{nil, nil, ErrAgentLocked, ErrAgentLocked, ErrAgentLocked, ErrAgentLocked, ErrAgentLocked, nil}
	assert.Equal(t, wantMethods, gotMethods)
	assert.Equal(t, wantErrors, gotErrors)
}

func getSSHSigner() (*ecdsa.PrivateKey, ssh.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	signer, err := ssh.NewSignerFromSigner(key)
	return key, signer, nil
}

func getSSHCertificate() (*ssh.Certificate, ssh.Signer, ssh.Signer, error) {
	_, signer, err := getSSHSigner()
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	sshCert := &ssh.Certificate{
		Nonce:           []byte("nonce"),
		Key:             signer.PublicKey(),
		Serial:          100500,
		CertType:        ssh.UserCert,
		KeyId:           "PCeS",
		ValidPrincipals: []string{"root"},
		ValidAfter:      uint64(now.Unix()),
		ValidBefore:     uint64(now.Unix()) + 3600,
		SignatureKey:    signer.PublicKey(),
	}

	if err := sshCert.SignCert(rand.Reader, signer); err != nil {
		return nil, nil, nil, err
	}
	certSigner, err := ssh.NewCertSigner(sshCert, signer)
	return sshCert, signer, certSigner, err
}
