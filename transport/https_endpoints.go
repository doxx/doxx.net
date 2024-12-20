package transport

import (
	"fmt"
	"math/rand"
	"strings"
)

// EndpointPaths maps logical endpoints to URL paths
var EndpointPaths = map[string]string{
	"write":       "/wp-content/",
	"read":        "/assets/",
	"poll":        "/assets/",
	"auth":        "/api/v1/",
	"auth_status": "/api/v2/",
}

// EndpointExtensions maps logical endpoints to allowed file extensions
var EndpointExtensions = map[string][]string{
	"write":       {".php", ".pdf", ".js", ".jpg"},
	"read":        {".css", ".png", ".woff2", ".svg"},
	"poll":        {".css", ".png", ".woff2", ".svg"},
	"auth":        {".html", ".htm", ".asp", ".aspx"},
	"auth_status": {".php", ".config", ".map"},
}

// randomString generates a random string of specified length
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// getEndpointFromPath extracts the logical endpoint from a URL path
func getEndpointFromPath(path string) string {
	// Normalize path by removing leading/trailing slashes
	path = strings.Trim(path, "/")

	// Check each endpoint path
	for endpoint, urlPath := range EndpointPaths {
		// Normalize the URL path as well
		normalizedPath := strings.Trim(urlPath, "/")
		if strings.HasPrefix(path, normalizedPath) {
			// Verify the extension matches this endpoint
			ext := getExtensionFromPath(path)
			if ext != "" {
				for _, validExt := range EndpointExtensions[endpoint] {
					if ext == validExt {
						return endpoint
					}
				}
			}
		}
	}

	// Only log if path isn't empty (skip root path requests)
	if path != "" {
		fmt.Printf("[HTTPS Server] Invalid path requested: %s\n", path)
	}
	return ""
}

// getExtensionFromPath gets the file extension from a path
func getExtensionFromPath(path string) string {
	for _, extensions := range EndpointExtensions {
		for _, ext := range extensions {
			if strings.HasSuffix(path, ext) {
				return ext
			}
		}
	}
	return ""
}

// generateEndpointPath generates a random path for a given endpoint
func generateEndpointPath(endpoint string) string {
	basePath := EndpointPaths[endpoint]
	extensions := EndpointExtensions[endpoint]
	if basePath == "" || len(extensions) == 0 {
		return ""
	}

	// Ensure basePath starts with / and ends with /
	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}
	if !strings.HasSuffix(basePath, "/") {
		basePath = basePath + "/"
	}

	// Generate random filename (20 characters) with random extension
	filename := randomString(20)
	extension := extensions[rand.Intn(len(extensions))]

	return fmt.Sprintf("%s%s%s", basePath, filename, extension)
}
