//go:build !windows

package main

import "context"

// runAsService reports false: only Windows has a service manager that
// needs the process to check in. See service_windows.go.
func runAsService(func(context.Context)) bool { return false }
