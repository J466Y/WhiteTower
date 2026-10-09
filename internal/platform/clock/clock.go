// Package clock gives the core its time through an interface, so that tests
// control it (plan P1-01, step 7): code that schedules, expires or measures
// takes a Clock instead of calling the time package.
package clock

import "time"

// Clock tells the time and makes timers.
type Clock interface {
	// Now returns the current time.
	Now() time.Time
	// NewTimer returns a timer that fires once d has passed.
	NewTimer(d time.Duration) Timer
}

// Timer fires once, on C, unless it is stopped first.
type Timer interface {
	// C delivers the time at which the timer fired.
	C() <-chan time.Time
	// Stop prevents the timer from firing, and reports whether it did.
	Stop() bool
}

// System is the clock of the operating system.
var System Clock = systemClock{}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) NewTimer(d time.Duration) Timer { return systemTimer{time.NewTimer(d)} }

type systemTimer struct{ t *time.Timer }

func (t systemTimer) C() <-chan time.Time { return t.t.C }

func (t systemTimer) Stop() bool { return t.t.Stop() }
