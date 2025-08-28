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

package handler

import (
	"context"
	"crypto"
	"time"

	"log/slog"

	"github.com/facebookincubator/pces/cert"
	"github.com/facebookincubator/pces/example/api/pces"
	"github.com/facebookincubator/pces/storage"
)

// Handler implements the PCeSAgent interface.
type Handler struct {
	pces.UnimplementedPCeSAgentServer
	storage   storage.Storage
	logger    *slog.Logger
	startTime time.Time
}

// NewHandler creates a new PCeSAgent handler.
func NewHandler(storage storage.Storage, logger *slog.Logger, startTime time.Time) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	if startTime.IsZero() {
		startTime = time.Now()
	}
	return &Handler{
		storage:   storage,
		logger:    logger,
		startTime: startTime,
	}
}

// Renew implements the PCeSAgent.Renew method.
func (h *Handler) Renew(ctx context.Context, request *pces.RenewRequest) (*pces.RenewResponse, error) {
	h.logger.Info("Renew request received", "label", request.Label, "reason", request.Reason)

	if request.Label == "" {
		return &pces.RenewResponse{}, nil
	}

	err := h.storage.Renew(ctx, request.Label, request.Reason)
	if err != nil {
		h.logger.Error("Failed to renew certificate", "label", request.Label, "error", err)
		return &pces.RenewResponse{}, err
	}

	h.logger.Info("Certificate renewed successfully", "label", request.Label)
	return &pces.RenewResponse{}, nil
}

// Status implements the PCeSAgent.Status method.
func (h *Handler) Status(ctx context.Context, _ *pces.StatusRequest) (*pces.StatusResponse, error) {
	h.logger.Info("Status request received")

	uptime := time.Since(h.startTime).Milliseconds()

	certificates := h.storage.Certificates()
	certStatuses := make([]*pces.CertificateStatus, 0, len(certificates))

	for label, cert := range certificates {
		certStatus, err := getTLSCertificateStatus(ctx, label, cert)
		if err != nil {
			h.logger.Warn("Failed to get certificate status", "label", label, "error", err)
		}

		certStatuses = append(certStatuses, certStatus)
	}

	response := &pces.StatusResponse{
		Status: &pces.AgentStatus{
			Uptime:       uptime,
			Certificates: certStatuses,
		},
	}

	h.logger.Info("Status request completed", "certificates_count", len(certStatuses))
	return response, nil
}

// GetTLSCertificateStatus retrieves the status of a certificate.
func getTLSCertificateStatus(ctx context.Context, label string, cert cert.Certificate) (*pces.CertificateStatus, error) {
	validAfter, validBefore, err := cert.Lifetime(ctx)
	st := pces.CertificateStatus{
		Label:       label,
		Type:        cert.Type(),
		ValidAfter:  validAfter.Unix(),
		ValidBefore: validBefore.Unix(),
	}
	if err != nil {
		errMsg := err.Error()
		st.ErrorMessage = &errMsg
	}

	return &st, err
}

// GetTLSCert implements the PCeSAgent.GetTLSCert method.
func (h *Handler) GetTLSCert(ctx context.Context, request *pces.GetTLSCertRequest) (*pces.GetTLSCertResponse, error) {
	h.logger.Info("GetTLSCert request received", "label", request.Label)

	if request.Label == "" {
		h.logger.Error("Empty label provided for GetTLSCert request")
		return &pces.GetTLSCertResponse{}, nil
	}

	certificate, err := h.storage.Certificate(request.Label)
	if err != nil {
		h.logger.Error("Certificate not found", "label", request.Label, "error", err)
		return &pces.GetTLSCertResponse{}, nil
	}

	// Use type assertion to ensure we only work with TLS certificates.
	tlsCert, ok := certificate.(*cert.TLS)
	if !ok {
		h.logger.Error("Certificate is not a TLS certificate", "label", request.Label, "type", certificate.Type())
		return &pces.GetTLSCertResponse{}, nil
	}

	certData, err := tlsCert.EncodedCert(ctx)
	if err != nil {
		h.logger.Error("Failed to get encoded certificate", "label", request.Label, "error", err)
		return &pces.GetTLSCertResponse{}, err
	}

	h.logger.Info("Certificate retrieved successfully", "label", request.Label)
	return &pces.GetTLSCertResponse{CertData: certData}, nil
}

// Sign processes a signing request, using the certificate associated with the given label.
func (h *Handler) SignWithTLSCert(ctx context.Context, request *pces.SignWithTLSCertRequest) (*pces.SignWithTLSCertResponse, error) {
	h.logger.Info("Sign request received", "label", request.Label, "data_length", len(request.Data))

	certificate, err := h.storage.Certificate(request.Label)
	if err != nil {
		h.logger.Error("Certificate not found", "label", request.Label, "error", err)
		return &pces.SignWithTLSCertResponse{}, nil
	}

	// Use type assertion to ensure we only work with TLS certificates.
	tlsCert, ok := certificate.(*cert.TLS)
	if !ok {
		h.logger.Error("Certificate is not a TLS certificate", "label", request.Label, "type", certificate.Type())
		return &pces.SignWithTLSCertResponse{}, nil
	}

	signature, err := tlsCert.SignMessage(nil, request.Data, crypto.SHA256)
	if err != nil {
		h.logger.Error("Failed to sign data with TLS certificate", "label", request.Label, "error", err)
		return &pces.SignWithTLSCertResponse{}, err
	}

	h.logger.Info("Data signed successfully with TLS certificate", "label", request.Label)
	return &pces.SignWithTLSCertResponse{Signature: signature}, nil
}
