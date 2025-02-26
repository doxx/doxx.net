//go:build windows

package main

import (
	"embed"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

//go:embed assets/windows/wintun-amd64.dll assets/windows/wintun-arm64.dll
var embeddedFiles embed.FS

// checkSystemWintun checks common installation locations for an existing wintun.dll
func checkSystemWintun() (string, bool) {
	systemPaths := []string{
		`C:\Windows\System32\wintun.dll`,
		`C:\Windows\SysWOW64\wintun.dll`,
		`C:\Program Files\Wintun\bin\wintun.dll`,
		`C:\Program Files (x86)\Wintun\bin\wintun.dll`,
	}

	for _, path := range systemPaths {
		debugLog("Checking for existing Wintun installation at: %s", path)
		if _, err := os.Stat(path); err == nil {
			debugLog("Found existing Wintun installation at: %s", path)
			return path, true
		}
	}

	debugLog("No existing Wintun installation found in system directories")
	return "", false
}

// extractEmbeddedWintun extracts the embedded wintun.dll to the executable's directory
func extractEmbeddedWintun() (string, error) {
	// First check for system-installed version
	if systemPath, found := checkSystemWintun(); found {
		return systemPath, nil
	}

	// Get executable directory
	exe, err := os.Executable()
	if err != nil {
		debugLog("Failed to get executable path: %v", err)
		return "", err
	}
	exeDir := filepath.Dir(exe)
	debugLog("Executable directory: %s", exeDir)

	// Define target path
	targetPath := filepath.Join(exeDir, "wintun.dll")
	debugLog("Target DLL path: %s", targetPath)

	// Check if we already extracted it
	if _, err := os.Stat(targetPath); err == nil {
		debugLog("Previously extracted Wintun DLL found at: %s", targetPath)
		return targetPath, nil
	}

	// Determine which DLL to use based on architecture
	var dllPath string
	debugLog("Current architecture: %s", runtime.GOARCH)
	if runtime.GOARCH == "arm64" {
		dllPath = "assets/windows/wintun-arm64.dll"
		debugLog("Using ARM64 DLL: %s", dllPath)
	} else {
		dllPath = "assets/windows/wintun-amd64.dll"
		debugLog("Using AMD64 DLL: %s", dllPath)
	}

	// List embedded files for debugging
	entries, err := embeddedFiles.ReadDir("assets/windows")
	if err != nil {
		debugLog("Failed to read embedded directory: %v", err)
	} else {
		debugLog("Available embedded files:")
		for _, entry := range entries {
			debugLog("- %s", entry.Name())
		}
	}

	// Open embedded file
	embeddedDll, err := embeddedFiles.Open(dllPath)
	if err != nil {
		debugLog("Failed to open embedded DLL %s: %v", dllPath, err)
		return "", err
	}
	defer embeddedDll.Close()

	// Create target file
	targetFile, err := os.Create(targetPath)
	if err != nil {
		debugLog("Failed to create target file %s: %v", targetPath, err)
		return "", err
	}
	defer targetFile.Close()

	// Copy contents
	written, err := io.Copy(targetFile, embeddedDll)
	if err != nil {
		os.Remove(targetPath) // Clean up on failure
		debugLog("Failed to copy DLL contents: %v", err)
		return "", err
	}
	debugLog("Successfully wrote %d bytes to %s", written, targetPath)

	return targetPath, nil
}
