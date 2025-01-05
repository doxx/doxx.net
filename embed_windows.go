//go:build windows

package main

import (
	"embed"
	"io"
	"os"
	"path/filepath"
)

//go:embed assets/windows/wintun.dll
var embeddedFiles embed.FS

// extractEmbeddedWintun extracts the embedded wintun.dll to the executable's directory
func extractEmbeddedWintun() (string, error) {
	// Get executable directory
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	exeDir := filepath.Dir(exe)

	// Define target path
	targetPath := filepath.Join(exeDir, "wintun.dll")

	// Check if file already exists
	if _, err := os.Stat(targetPath); err == nil {
		return targetPath, nil // File already exists
	}

	// Open embedded file
	embeddedDll, err := embeddedFiles.Open("assets/windows/wintun.dll")
	if err != nil {
		return "", err
	}
	defer embeddedDll.Close()

	// Create target file
	targetFile, err := os.Create(targetPath)
	if err != nil {
		return "", err
	}
	defer targetFile.Close()

	// Copy contents
	if _, err := io.Copy(targetFile, embeddedDll); err != nil {
		os.Remove(targetPath) // Clean up on failure
		return "", err
	}

	return targetPath, nil
}
