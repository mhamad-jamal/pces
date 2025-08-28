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
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSaveBytesToFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "saveBytesToFile_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	tests := []struct {
		name      string
		data      []byte
		perm      os.FileMode
		fileName  string
		setupFile func(t *testing.T, filePath string) // Optional setup for existing files
	}{
		{
			name:     "successful write with 0644 permissions - binary data",
			data:     []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD},
			perm:     0644,
			fileName: "binary-file.bin",
		},
		{
			name:     "empty data",
			data:     []byte{},
			perm:     0644,
			fileName: "empty-file.txt",
		},
		{
			name:     "overwrite existing file",
			data:     []byte("new content"),
			perm:     0600,
			fileName: "existing-file.txt",
			setupFile: func(t *testing.T, filePath string) {
				err := os.WriteFile(filePath, []byte("old content"), 0644)
				assert.NoError(t, err)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := filepath.Join(tempDir, tt.fileName)

			if tt.setupFile != nil {
				tt.setupFile(t, filePath)
			}

			err := saveBytesToFile(filePath, tt.data, tt.perm)
			assert.NoError(t, err)

			// Validate the file
			assert.FileExists(t, filePath)

			actualData, err := os.ReadFile(filePath)
			assert.NoError(t, err)
			assert.Equal(t, tt.data, actualData)

			fileInfo, err := os.Stat(filePath)
			assert.NoError(t, err)

			// Skip permission check on Windows: Unix uses simple octal permissions,
			// but Windows uses complex ACLs that don't map reliably.
			if runtime.GOOS != "windows" {
				assert.Equal(t, tt.perm, fileInfo.Mode().Perm())
			}

			tempFile := filePath + ".tmp"
			assert.NoFileExists(t, tempFile)
		})
	}
}
