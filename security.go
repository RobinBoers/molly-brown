// +build js nacl plan9 windows

package main

type userInfo struct {
}

// Restrict access to the files specified in config in an OS-dependent way.
// This is intended to be called immediately prior to accepting client
// connections and may be used to establish a security "jail" for the molly
// brown executable.
func enableSecurityRestrictions(config Config, ui userInfo) error {
	return nil
}
