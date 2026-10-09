package jobs

import (
	"strings"
	"testing"
	"time"
)

func date(s string) time.Time {
	t, err := time.Parse("2006-01-02 15:04", s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestEvery(t *testing.T) {
	at := date("2026-10-09 12:00").Add(7 * time.Second)
	if got := Every(90 * time.Second).Next(at); !got.Equal(at.Add(90 * time.Second)) {
		t.Fatalf("got %v", got)
	}
}

func TestCron(t *testing.T) {
	for _, tt := range []struct {
		expr, after string
		want        []string
	}{
		{"* * * * *", "2026-10-09 12:00", []string{"2026-10-09 12:01", "2026-10-09 12:02"}},
		{"*/15 * * * *", "2026-10-09 12:07", []string{"2026-10-09 12:15", "2026-10-09 12:30", "2026-10-09 12:45", "2026-10-09 13:00"}},
		{"5/20 * * * *", "2026-10-09 12:00", []string{"2026-10-09 12:05", "2026-10-09 12:25", "2026-10-09 12:45", "2026-10-09 13:05"}},
		{"0 3 * * *", "2026-10-09 03:00", []string{"2026-10-10 03:00", "2026-10-11 03:00"}},
		{"30 8,17 * * *", "2026-10-09 09:00", []string{"2026-10-09 17:30", "2026-10-10 08:30"}},
		{"0 0 1 */3 *", "2026-10-09 00:00", []string{"2027-01-01 00:00", "2027-04-01 00:00"}},
		// Weekdays: Friday 9 October 2026, then Monday.
		{"0 9 * * 1-5", "2026-10-09 08:00", []string{"2026-10-09 09:00", "2026-10-12 09:00"}},
		// Sunday is 0 or 7.
		{"0 12 * * 7", "2026-10-09 00:00", []string{"2026-10-11 12:00", "2026-10-18 12:00"}},
		{"0 12 * * 0", "2026-10-09 00:00", []string{"2026-10-11 12:00", "2026-10-18 12:00"}},
		// Both days restricted: the 13th, or any Friday.
		{"0 0 13 * 5", "2026-10-09 00:00", []string{"2026-10-13 00:00", "2026-10-16 00:00", "2026-10-23 00:00"}},
		// The 31st of the months that have one.
		{"0 0 31 * *", "2026-10-31 00:00", []string{"2026-12-31 00:00", "2027-01-31 00:00", "2027-03-31 00:00"}},
		// 29 February: 2100 is no leap year.
		{"0 0 29 2 *", "2096-03-01 00:00", []string{"2104-02-29 00:00"}},
	} {
		t.Run(tt.expr, func(t *testing.T) {
			s, err := Cron(tt.expr)
			if err != nil {
				t.Fatal(err)
			}
			at := date(tt.after)
			for _, w := range tt.want {
				at = s.Next(at)
				if !at.Equal(date(w)) {
					t.Fatalf("got %s, want %s", at.Format("2006-01-02 15:04 Mon"), w)
				}
			}
		})
	}
}

// Times in other zones, and seconds, count as the UTC minute they fall in.
func TestCronWorksInUTC(t *testing.T) {
	s, err := Cron("0 3 * * *")
	if err != nil {
		t.Fatal(err)
	}
	madrid := time.FixedZone("CEST", 2*60*60)
	got := s.Next(time.Date(2026, 10, 9, 4, 59, 30, 0, madrid)) // 02:59:30 UTC
	if !got.Equal(date("2026-10-09 03:00")) || got.Location() != time.UTC {
		t.Fatalf("got %v", got)
	}
}

func TestCronRefusesWhatItCannotRun(t *testing.T) {
	for expr, want := range map[string]string{
		"* * * *":       "want 5 fields",
		"* * * * * *":   "want 5 fields",
		"60 * * * *":    "not a number from 0 to 59",
		"* 24 * * *":    "not a number from 0 to 23",
		"* * 0 * *":     "not a number from 1 to 31",
		"* * * 13 *":    "not a number from 1 to 12",
		"* * * * 8":     "not a number from 0 to 7",
		"5-1 * * * *":   "invalid range",
		"*/0 * * * *":   "invalid step",
		"*/x * * * *":   "invalid step",
		"MON * * * *":   "not a number",
		"0 0 30 2 *":    "selects no time",
		"0 0 31 4,6 *":  "selects no time",
		"1,,2 * * * *":  "not a number",
		"-1 * * * *":    "not a number",
		"1-2-3 * * * *": "not a number",
	} {
		if _, err := Cron(expr); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want an error with %q", expr, err, want)
		}
	}
}
