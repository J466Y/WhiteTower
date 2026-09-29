//go:build !windows

package main

import "time"

var epoch = time.Now()

func ticks() int64 { return int64(time.Since(epoch)) }

func elapsed(from, to int64) time.Duration { return time.Duration(to - from) }
