//go:build windows

package main

import (
	"syscall"
	"time"
	"unsafe"
)

// Go's monotonic clock on Windows ticks about every half millisecond, too
// coarse for single decisions, so the spike reads QueryPerformanceCounter, as
// Python's perf_counter does in spike S1.
var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	qpc      = kernel32.NewProc("QueryPerformanceCounter")
	qpf      = kernel32.NewProc("QueryPerformanceFrequency")
	freq     int64
)

func init() {
	_, _, _ = qpf.Call(uintptr(unsafe.Pointer(&freq))) //nolint:gosec // G103: the documented way to call a Windows API
}

func ticks() int64 {
	var t int64
	_, _, _ = qpc.Call(uintptr(unsafe.Pointer(&t))) //nolint:gosec // G103: the documented way to call a Windows API
	return t
}

func elapsed(from, to int64) time.Duration {
	return time.Duration(float64(to-from) * float64(time.Second) / float64(freq))
}
