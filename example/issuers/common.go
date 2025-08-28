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

package issuers

import (
	"fmt"
	"os"
)

// saveBytesToFile writes data to a file by first writing to a temporary file
// and then renaming it to the destination path.
func saveBytesToFile(filePath string, data []byte, perm os.FileMode) error {
	tempFile := filePath + ".tmp"

	if err := os.WriteFile(tempFile, data, perm); err != nil {
		return fmt.Errorf("failed to write to temporary file: %w", err)
	}

	if err := os.Rename(tempFile, filePath); err != nil {
		return fmt.Errorf("failed to atomically move file: %w", err)
	}

	return nil
}
