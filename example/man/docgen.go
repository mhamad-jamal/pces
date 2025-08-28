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

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra/doc"

	"github.com/facebookincubator/pces/example/cli/cmd"
)

func main() {
	var outputDir string
	flag.StringVar(&outputDir, "output", ".", "Directory to store generated man pages")
	flag.Parse()

	if err := generateManPages(outputDir); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// generateManPages generates man pages for the PCeS CLI using the actual command structure
func generateManPages(dir string) error {
	// Get the root command from the actual CLI package
	rootCmd := cmd.GetRootCmd()

	header := &doc.GenManHeader{
		Title:   "PCES",
		Section: "1", // Section 1 is for executable programs or shell commands
	}

	if err := doc.GenManTree(rootCmd, header, dir); err != nil {
		return fmt.Errorf("failed to generate man pages: %w", err)
	}

	fmt.Printf("Man pages successfully generated in %s\n", dir)
	fmt.Printf("Generated files:\n")

	files, err := filepath.Glob(filepath.Join(dir, "*.1"))
	if err != nil {
		return fmt.Errorf("failed to list generated files: %w", err)
	}

	for _, file := range files {
		fmt.Printf("  %s\n", filepath.Base(file))
	}

	return nil
}
