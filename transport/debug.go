package transport

import "log"

// Package-level debug flag
var debug bool

// SetDebug sets the debug mode for the transport package
func SetDebug(d bool) {
	debug = d
}

// debugLogc logs debug messages for the HTTPS client
func debugLogc(format string, args ...interface{}) {
	if debug {
		log.Printf("[Client Debug] "+format, args...)
	}
}

// debugLogh logs debug messages for HTTPS helpers
func debugLogh(format string, args ...interface{}) {
	if debug {
		log.Printf("[Helper Debug] "+format, args...)
	}
}
