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
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/facebookincubator/pces/example/api/pces"
	"github.com/facebookincubator/pces/storage"
	"google.golang.org/grpc"
)

// Option is a functional option for configuring the PCeS gRPC server.
type Option func(*Server) error

// WithLogger sets the logger for the server.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Server) error {
		s.logger = logger
		return nil
	}
}

// Server implements a gRPC server for the PCeS API.
type Server struct {
	lock                              sync.Mutex
	storage                           storage.Storage
	logger                            *slog.Logger
	startTime                         time.Time
	running                           bool
	grpcServer                        *grpc.Server
	pces.UnimplementedPCeSAgentServer // Embed the unimplemented server to satisfy the interface
}

// NewServer creates a new PCeS gRPC server.
func NewServer(storage storage.Storage, opts ...Option) (*Server, error) {
	if storage == nil {
		return nil, errors.New("storage cannot be empty")
	}

	server := &Server{
		storage:   storage,
		logger:    slog.Default(),
		startTime: time.Now(),
	}

	for _, opt := range opts {
		if err := opt(server); err != nil {
			return nil, err
		}
	}

	return server, nil
}

// Start starts the PCeS gRPC server.
func (s *Server) Start(listener net.Listener) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.running {
		return errors.New("server is already running")
	}

	grpcErrCh := s.startGRPCServer(listener)

	return <-grpcErrCh
}

// startGRPCServer sets up and starts the gRPC server.
func (s *Server) startGRPCServer(listener net.Listener) <-chan error {
	s.logger.Info("Created gRPC Server Unix socket", "path", listener.Addr().String())

	s.grpcServer = grpc.NewServer()

	handler := NewHandler(s.storage, s.logger, s.startTime)

	pces.RegisterPCeSAgentServer(s.grpcServer, handler)

	s.running = true

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("Starting PCeS gRPC server", "socket_path", listener.Addr().String())
		if err := s.grpcServer.Serve(listener); err != nil {
			s.logger.Error("gRPC server error", "error", err)
			errCh <- err
		}
	}()

	return errCh
}
