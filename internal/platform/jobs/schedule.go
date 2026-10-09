package jobs

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Schedule says when a job runs.
type Schedule interface {
	// Next returns the first time after t at which the job runs.
	Next(t time.Time) time.Time
}

// Every runs a job at intervals of d, counted from the start of one run to
// the start of the next.
func Every(d time.Duration) Schedule { return every(d) }

type every time.Duration

func (e every) Next(t time.Time) time.Time { return t.Add(time.Duration(e)) }

// Cron runs a job at the times that a cron expression selects, in UTC. The
// expression has five fields: the minute (0-59), the hour (0-23), the day of
// the month (1-31), the month (1-12) and the day of the week (0-7, Sunday
// being 0 or 7). Each field is *, a number or a range a-b, or a list of them
// separated by commas; any of them may end in /n, which takes every nth
// value, and a/n stands for a-max/n. As in Vixie cron, when both days are
// restricted, a day that matches either one is selected. An expression that
// selects no time is an error.
func Cron(expr string) (Schedule, error) {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return nil, fmt.Errorf("cron expression %q: want 5 fields, got %d", expr, len(fields))
	}
	var c cron
	var err error
	for i, f := range []struct {
		bits     *uint64
		min, max int
	}{{&c.minute, 0, 59}, {&c.hour, 0, 23}, {&c.dom, 1, 31}, {&c.month, 1, 12}, {&c.dow, 0, 7}} {
		if *f.bits, err = parseField(fields[i], f.min, f.max); err != nil {
			return nil, fmt.Errorf("cron expression %q, field %d: %w", expr, i+1, err)
		}
	}
	if c.dow&(1<<7) != 0 { // Sunday, written 7
		c.dow |= 1
	}
	c.domStar, c.dowStar = fields[2] == "*", fields[4] == "*"
	if c.Next(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)).IsZero() {
		return nil, fmt.Errorf("cron expression %q selects no time", expr)
	}
	return c, nil
}

// cron holds the values that each field selects, as bits.
type cron struct {
	minute, hour, dom, month, dow uint64
	domStar, dowStar              bool
}

// Next returns the first selected minute after t, or the zero time when
// there is none in the next ten years: a day such as 29 February may be eight
// years away.
func (c cron) Next(t time.Time) time.Time {
	t = t.UTC().Truncate(time.Minute).Add(time.Minute)
	for limit := t.AddDate(10, 0, 0); t.Before(limit); {
		switch {
		case c.month&(1<<uint(t.Month())) == 0:
			t = time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, time.UTC)
		case !c.day(t):
			t = time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, time.UTC)
		case c.hour&(1<<uint(t.Hour())) == 0:
			t = t.Truncate(time.Hour).Add(time.Hour)
		case c.minute&(1<<uint(t.Minute())) == 0:
			t = t.Add(time.Minute)
		default:
			return t
		}
	}
	return time.Time{}
}

// day reports whether the day of t is selected.
func (c cron) day(t time.Time) bool {
	dom := c.dom&(1<<uint(t.Day())) != 0
	dow := c.dow&(1<<uint(t.Weekday())) != 0
	if c.domStar || c.dowStar {
		return dom && dow
	}
	return dom || dow
}

// parseField returns the values that a field selects, as bits.
func parseField(field string, low, high int) (uint64, error) {
	var bits uint64
	for part := range strings.SplitSeq(field, ",") {
		span, stepText, stepped := strings.Cut(part, "/")
		step := 1
		if stepped {
			n, err := strconv.Atoi(stepText)
			if err != nil || n < 1 {
				return 0, fmt.Errorf("invalid step %q", stepText)
			}
			step = n
		}
		var first, last int
		switch from, to, ranged := strings.Cut(span, "-"); {
		case span == "*":
			first, last = low, high
		case ranged:
			a, errA := number(from, low, high)
			b, errB := number(to, low, high)
			if err := errors.Join(errA, errB); err != nil {
				return 0, err
			}
			if a > b {
				return 0, fmt.Errorf("invalid range %q", span)
			}
			first, last = a, b
		default:
			a, err := number(span, low, high)
			if err != nil {
				return 0, err
			}
			first, last = a, a
			if stepped {
				last = high
			}
		}
		for v := first; v <= last; v += step {
			bits |= 1 << uint(v)
		}
	}
	return bits, nil
}

func number(s string, low, high int) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < low || n > high {
		return 0, fmt.Errorf("%q is not a number from %d to %d", s, low, high)
	}
	return n, nil
}
