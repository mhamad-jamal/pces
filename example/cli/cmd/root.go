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

package cmd

import (
	"time"

	"github.com/spf13/cobra"
)

var (
	grpcSocketPath string
	timeout        time.Duration
	rootCmd        = &cobra.Command{
		Use:   "pces",
		Short: "PCeS client",
		Long:  `PCeS client is a command line interface to the PCeS agent.`,
	}
)

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

// GetRootCmd returns the root command for documentation generation
func GetRootCmd() *cobra.Command {
	return rootCmd
}

func init() {
	rootCmd.PersistentFlags().StringVar(&grpcSocketPath, "grpc-socket-path", "", "path to the PCeS agent socket")
	rootCmd.PersistentFlags().DurationVar(&timeout, "timeout", 30*time.Second, "the timeout for both connection and request")
	rootCmd.MarkPersistentFlagRequired("grpc-socket-path")
	rootCmd.CompletionOptions.DisableDefaultCmd = true
}
