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
	"log/slog"
	"time"

	"github.com/facebookincubator/pces/cert"
)

// UpdaterOption is an Updater configuration option.
type UpdaterOption func(*Updater)

// UpdaterDisableAutoUpdate disables automatic updates.
func UpdaterDisableAutoUpdate() UpdaterOption {
	return func(upd *Updater) {
		upd.autoUpdate = false
	}
}

// UpdaterMinRetry sets minimal retry interval.
func UpdaterMinRetry(d time.Duration) UpdaterOption {
	return func(upd *Updater) {
		upd.minRetry = d
	}
}

// UpdaterMaxRetry sets maximal retry interval.
func UpdaterMaxRetry(d time.Duration) UpdaterOption {
	return func(upd *Updater) {
		upd.maxRetry = d
	}
}

// UpdaterFrequency sets update frequency.
func UpdaterFrequency(d time.Duration) UpdaterOption {
	return func(upd *Updater) {
		upd.frequency = d
	}
}

// UpdaterWithLogger sets logger.
func UpdaterWithLogger(l *slog.Logger) UpdaterOption {
	return func(upd *Updater) {
		upd.logger = l
	}
}

// StorageOption is a Storage configuration option.
type StorageOption func(*storage)

// WithCertificate adds a certificate to the storage.
func WithCertificate(label string, c cert.Certificate, upd Updater) StorageOption {
	return func(s *storage) {
		s.certs[label] = certificate{
			c:   c,
			upd: upd,
		}
	}
}
