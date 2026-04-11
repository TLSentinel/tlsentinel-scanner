//go:build !windows

package main

import "errors"

func isWindowsService() (bool, error) { return false, nil }
func runService()                     {}

func installService(_, _ string) error {
	return errors.New("installing a Windows service is not supported on this platform")
}

func removeService(_ string) error {
	return errors.New("removing a Windows service is not supported on this platform")
}
