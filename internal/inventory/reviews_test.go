package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/J466Y/WhiteTower/internal/inventory"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/db"
)

// member stores a person in the IdP groups of the roles given, and returns
// them as an API caller with those roles.
func (f *fixture) member(t *testing.T, name string, roles ...string) auth.Principal {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	groups := make([]string, len(roles))
	for i, r := range roles {
		groups[i] = "wt-" + r
	}
	f.set(t, `INSERT INTO whitetower.principals (id, kind, issuer, subject, display_name, idp_groups)
		VALUES ($1, 'human', 'https://idp.example.com', $2, $3, $4)`, id, id.String(), name, groups)
	return auth.Principal{ID: id.String(), Kind: auth.Human, Name: name, Roles: roles}
}

// openReview returns the agent's open review, as an operator reads it.
func (f *fixture) openReview(t *testing.T, agent uuid.UUID) *inventory.Review {
	t.Helper()
	id := scalar[uuid.UUID](t, f, `SELECT id FROM whitetower.reviews WHERE agent_id = $1 AND status IN ('scheduled', 'awaiting_signoff')`, agent)
	r, err := f.inv.GetReview(context.Background(), f.omar, id)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// attested is an attestation whose statements all hold, which keeps the
// tooling given.
func attested(kept ...string) inventory.Attestation {
	return inventory.Attestation{
		StillNeeded: true, OwnerStillRight: true, DataCategoriesCurrent: true, PolicyAdequate: true, ToolingStillNeeded: true,
		KeptTooling: kept,
	}
}

// completed brings an agent of Olivia's, of high risk, into service, and
// completes its first review as Olivia: it then waits for its sign-off.
func (f *fixture) completed(t *testing.T, slug string) (*inventory.Agent, *inventory.Review) {
	t.Helper()
	a := f.inState(t, slug, "active")
	r := f.openReview(t, a.ID)
	done, err := f.inv.CompleteReview(context.Background(), f.olivia, r.ID, r.Version, attested())
	if err != nil {
		t.Fatal(err)
	}
	return a, done
}

// signoffItems counts the open inbox items that ask for the review's
// sign-off.
func (f *fixture) signoffItems(t *testing.T, review uuid.UUID) int {
	t.Helper()
	return scalar[int](t, f, `SELECT count(*) FROM whitetower.inbox_items
		WHERE kind = 'review_signoff' AND subject_type = 'review' AND subject_id = $1 AND resolved_at IS NULL`, review)
}

// lastReviewEvent returns the newest whitetower.review.changed.v1 event.
func (f *fixture) lastReviewEvent(t *testing.T) event {
	t.Helper()
	changed := f.events(t, "whitetower.review.changed.v1")
	if len(changed) == 0 {
		t.Fatal("no review event")
	}
	return changed[len(changed)-1]
}

// recordedVersions counts the versions that a transaction takes.
type recordedVersions struct {
	inventory.StateVersions
	taken int
}

func (v *recordedVersions) Next(ctx context.Context, tx *db.Tx) (int64, error) {
	v.taken++
	return v.StateVersions.Next(ctx, tx)
}

// Activation schedules the agent's first review, with the terms that the
// settings give then: a due date by risk tier, the end of the grace period,
// and whether it needs a sign-off. A later change of the settings applies to
// the reviews scheduled after it.
func TestActivationSchedulesTheFirstReview(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.inState(t, "invoice-triage", "active")
	r := f.openReview(t, a.ID)
	due := f.clk.Now().UTC().AddDate(0, 0, 180)
	if r.Status != "scheduled" || !r.DueAt.Equal(due) || !r.GraceEndsAt.Equal(due.AddDate(0, 0, 14)) || !r.SignoffRequired ||
		r.Overdue || r.Attestation != nil || r.CompletedBy != nil || r.Version != 1 || !r.CreatedAt.Equal(f.clk.Now()) {
		t.Errorf("the first review of a high risk agent: %+v", r)
	}
	e := f.lastReviewEvent(t)
	if *e.subject != a.ID || e.actorID != f.olivia.ID || e.data["change"] != "scheduled" || e.data["review_id"] != r.ID.String() ||
		e.data["due_at"] != due.Format("2006-01-02T15:04:05.000Z") || e.data["signoff_required"] != true {
		t.Errorf("event %+v", e)
	}

	for key, value := range map[string]string{
		"lifecycle.review_interval_days":      `{"low": 30, "medium": 60, "high": 90, "critical": 7}`,
		"lifecycle.review_grace_days":         `3`,
		"lifecycle.review_signoff_risk_tiers": `["medium", "high", "critical"]`,
	} {
		f.set(t, `UPDATE whitetower.settings SET value = $2::jsonb WHERE key = $1`, key, value)
	}
	if again := f.openReview(t, a.ID); !again.DueAt.Equal(r.DueAt) || !again.GraceEndsAt.Equal(r.GraceEndsAt) {
		t.Errorf("a change of the settings moved a scheduled review: %+v", again)
	}
	f.clk.Advance(time.Hour)
	b := f.inState(t, "medium-agent", "ready")
	f.set(t, `UPDATE whitetower.agents SET risk_tier = 'medium', version = version + 1 WHERE id = $1`, b.ID)
	if _, err := f.inv.Transition(ctx, f.olivia, b.ID, b.Version+1, "activate", ""); err != nil {
		t.Fatal(err)
	}
	medium := f.openReview(t, b.ID)
	due = f.clk.Now().UTC().AddDate(0, 0, 60)
	if !medium.DueAt.Equal(due) || !medium.GraceEndsAt.Equal(due.AddDate(0, 0, 3)) || !medium.SignoffRequired {
		t.Errorf("the first review of a medium risk agent after the change: %+v", medium)
	}
}

// A review setting outside its rules fails the activation, which reads the
// settings, and schedules the review, before it takes the version counter:
// no default stands in for the setting, and the counter is never held while
// a setting is read (the design of the halt path, section 2).
func TestAMalformedReviewSettingFailsActivationBeforeItTakesTheHead(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	versions := &recordedVersions{StateVersions: f.opts.Versions}
	opts := f.opts
	opts.Versions = versions
	inv := inventory.New(opts)
	const (
		interval = "lifecycle.review_interval_days"
		grace    = "lifecycle.review_grace_days"
		tiers    = "lifecycle.review_signoff_risk_tiers"
	)
	for i, c := range []struct{ name, key, value string }{
		{"an interval without a risk tier", interval, `{"low": 365, "medium": 365, "high": 180}`},
		{"an interval of a risk tier that is not one", interval, `{"low": 365, "medium": 365, "high": 180, "critical": 90, "extreme": 7}`},
		{"an interval of no day", interval, `{"low": 365, "medium": 365, "high": 0, "critical": 90}`},
		{"an interval longer than two years", interval, `{"low": 365, "medium": 365, "high": 180, "critical": 731}`},
		{"an interval that is not a number of days", interval, `{"low": 365, "medium": 365, "high": 180.5, "critical": 90}`},
		{"a negative grace period", grace, `-1`},
		{"a grace period longer than 90 days", grace, `91`},
		{"no grace period", grace, `null`},
		{"sign-off tiers without critical", tiers, `["high"]`},
		{"a sign-off tier twice", tiers, `["high", "critical", "high"]`},
		{"a sign-off tier that is not one", tiers, `["high", "critical", "extreme"]`},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := f.inState(t, fmt.Sprintf("agent-%d", i), "ready")
			before := scalar[string](t, f, `SELECT value::text FROM whitetower.settings WHERE key = $1`, c.key)
			f.set(t, `UPDATE whitetower.settings SET value = $2::jsonb WHERE key = $1`, c.key, c.value)
			defer f.set(t, `UPDATE whitetower.settings SET value = $2::jsonb WHERE key = $1`, c.key, before)
			versions.taken = 0
			_, err := inv.Transition(ctx, f.olivia, a.ID, a.Version, "activate", "")
			var r *inventory.Refusal
			if err == nil || errors.As(err, &r) || !strings.Contains(err.Error(), c.key) {
				t.Fatalf("got %v, want an internal error that names the setting", err)
			}
			if versions.taken > 0 {
				t.Error("the activation took a version before it read the setting")
			}
			if got := f.get(t, a.ID); got.LifecycleState != "ready" ||
				scalar[int](t, f, `SELECT count(*) FROM whitetower.reviews WHERE agent_id = $1`, a.ID) != 0 {
				t.Errorf("the agent is %s", got.LifecycleState)
			}
		})
	}
	a := f.inState(t, "invoice-triage", "ready")
	versions.taken = 0
	if _, err := inv.Transition(ctx, f.olivia, a.ID, a.Version, "activate", ""); err != nil || versions.taken != 1 {
		t.Fatalf("with the settings as they were: %v, %d versions", err, versions.taken)
	}
}

// The owner completes a review: the attestation is recorded, with the tooling
// kept among the candidates to disable. A review that needs no sign-off is
// completed, and the next one is scheduled from its completion; one that
// needs a sign-off waits for it in the advisory committee's inbox. A
// delegate completes a review as the primary owner does.
func TestTheOwnerCompletesAReview(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	b := f.inState(t, "medium-agent", "ready")
	f.set(t, `UPDATE whitetower.agents SET risk_tier = 'medium', version = version + 1 WHERE id = $1`, b.ID)
	if _, err := f.inv.Transition(ctx, f.olivia, b.ID, b.Version+1, "activate", ""); err != nil {
		t.Fatal(err)
	}
	lastUsed := f.clk.Now().Add(-100 * 24 * time.Hour)
	f.tooling.set(b.ID,
		inventory.UnusedTool{Key: "invoices/archive_invoice", Kind: "tool", LastUsedAt: &lastUsed},
		inventory.UnusedTool{Key: "gpu-01/llama3.1-8b", Kind: "model"})
	r := f.openReview(t, b.ID)
	if len(r.UnusedTooling) != 2 || r.SignoffRequired {
		t.Fatalf("the review lists %+v", r)
	}
	f.clk.Advance(30 * 24 * time.Hour)
	att := attested("invoices/archive_invoice")
	att.Comment = "Still sorting invoices."
	done, err := f.inv.CompleteReview(ctx, f.olivia, r.ID, r.Version, att)
	if err != nil {
		t.Fatal(err)
	}
	now := f.clk.Now()
	if done.Status != "completed" || done.Version != 2 || done.CompletedBy == nil || done.CompletedBy.ID.String() != f.olivia.ID ||
		!done.CompletedAt.Equal(now) || done.UnusedTooling != nil || done.Attestation == nil ||
		!slices.Equal(done.Attestation.KeptTooling, []string{"invoices/archive_invoice"}) || done.Attestation.Comment != att.Comment {
		t.Errorf("completed: %+v", done)
	}
	changed := f.events(t, "whitetower.review.changed.v1")
	completion, next := changed[len(changed)-2], changed[len(changed)-1]
	attestation, _ := completion.data["attestation"].(map[string]any)
	if completion.data["change"] != "completed" || completion.data["status"] != "completed" || attestation["still_needed"] != true ||
		fmt.Sprint(attestation["kept_tooling"]) != "[invoices/archive_invoice]" || attestation["comment"] != nil {
		t.Errorf("completion event %+v", completion)
	}
	following := f.openReview(t, b.ID)
	if due := now.UTC().AddDate(0, 0, 365); following.ID == r.ID || !following.DueAt.Equal(due) || next.data["change"] != "scheduled" ||
		next.data["review_id"] != following.ID.String() || next.actorID != f.olivia.ID {
		t.Errorf("the next review %+v, event %+v", following, next)
	}

	a := f.inState(t, "invoice-triage", "active")
	if _, err := f.inv.AddDelegate(ctx, f.olivia, a.ID, uuid.MustParse(f.otto.ID)); err != nil {
		t.Fatal(err)
	}
	r = f.openReview(t, a.ID)
	waiting, err := f.inv.CompleteReview(ctx, f.otto, r.ID, r.Version, attested())
	if err != nil {
		t.Fatal(err)
	}
	if waiting.Status != "awaiting_signoff" || waiting.CompletedBy.ID.String() != f.otto.ID || waiting.Attestation.KeptTooling == nil ||
		len(waiting.UnusedTooling) != 0 || waiting.UnusedTooling == nil {
		t.Errorf("waiting for its sign-off: %+v", waiting)
	}
	if f.signoffItems(t, r.ID) != 1 ||
		scalar[string](t, f, `SELECT role FROM whitetower.inbox_items WHERE subject_id = $1`, r.ID) != "advisory" ||
		f.openReview(t, a.ID).ID != r.ID || f.lastReviewEvent(t).data["status"] != "awaiting_signoff" {
		t.Error("the review does not wait for the advisory committee's sign-off alone")
	}
}

// Only a person who is the agent's primary owner or one of its delegates
// completes its review, with their token's scope, at the review's version,
// with every statement true and an attestation within its bounds that keeps
// only candidates to disable. A review that does not wait for the owner, and
// one of an agent that can have no open review, are refused.
func TestACompletionIsRefused(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.inState(t, "invoice-triage", "active")
	f.tooling.set(a.ID, inventory.UnusedTool{Key: "invoices/archive_invoice", Kind: "tool"})
	r := f.openReview(t, a.ID)
	with := func(edit func(*inventory.Attestation)) inventory.Attestation {
		att := attested()
		edit(&att)
		return att
	}
	many := make([]string, 501)
	for i := range many {
		many[i] = fmt.Sprintf("tool-%d", i)
	}
	olivia := func(edit func(*auth.Principal)) auth.Principal {
		p := f.olivia
		edit(&p)
		return p
	}
	for _, c := range []struct {
		name    string
		caller  auth.Principal
		version int64
		att     inventory.Attestation
		want    inventory.RefusalKind
	}{
		{"another owner", f.otto, 1, attested(), inventory.Forbidden},
		{"the advisory committee", f.alex, 1, attested(), inventory.Forbidden},
		{"an operator", f.omar, 1, attested(), inventory.Forbidden},
		{"a user", f.uma, 1, attested(), inventory.Forbidden},
		{"a service account", f.serviceAccount(t, "owner"), 1, attested(), inventory.Forbidden},
		{"a break-glass session", olivia(func(p *auth.Principal) { p.IsBreakglass = true }), 1, attested(), inventory.Forbidden},
		{"a token without the scope", olivia(func(p *auth.Principal) { p.Scopes = []string{"inventory.view"} }), 1, attested(), inventory.Forbidden},
		{"a stale version", f.olivia, 2, attested(), inventory.Stale},
		{"an agent no longer needed", f.olivia, 1, with(func(a *inventory.Attestation) { a.StillNeeded = false }), inventory.Invalid},
		{"an owner no longer right", f.olivia, 1, with(func(a *inventory.Attestation) { a.OwnerStillRight = false }), inventory.Invalid},
		{"data categories out of date", f.olivia, 1, with(func(a *inventory.Attestation) { a.DataCategoriesCurrent = false }), inventory.Invalid},
		{"a policy no longer adequate", f.olivia, 1, with(func(a *inventory.Attestation) { a.PolicyAdequate = false }), inventory.Invalid},
		{"tooling no longer needed", f.olivia, 1, with(func(a *inventory.Attestation) { a.ToolingStillNeeded = false }), inventory.Invalid},
		{"a kept key that is no candidate", f.olivia, 1, attested("github/create_pull_request"), inventory.Invalid},
		{"a kept key twice", f.olivia, 1, attested("invoices/archive_invoice", "invoices/archive_invoice"), inventory.Invalid},
		{"an empty kept key", f.olivia, 1, attested(""), inventory.Invalid},
		{"a kept key of 256 characters", f.olivia, 1, attested(strings.Repeat("k", 256)), inventory.Invalid},
		{"501 kept keys", f.olivia, 1, attested(many...), inventory.Invalid},
		{"a comment of 2001 characters", f.olivia, 1, with(func(a *inventory.Attestation) { a.Comment = strings.Repeat("c", 2001) }), inventory.Invalid},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := f.inv.CompleteReview(ctx, c.caller, r.ID, c.version, c.att)
			refused(t, err, c.want)
		})
	}
	if got := f.openReview(t, a.ID); got.Status != "scheduled" || got.Version != 1 {
		t.Fatalf("a refusal changed the review: %+v", got)
	}
	_, err := f.inv.CompleteReview(ctx, f.olivia, uuid.Must(uuid.NewV7()), 1, attested())
	refused(t, err, inventory.NotFound)

	scoped := olivia(func(p *auth.Principal) { p.Scopes = []string{"inventory.view", "agent.review"} })
	done, err := f.inv.CompleteReview(ctx, scoped, r.ID, 1, attested("invoices/archive_invoice"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.inv.CompleteReview(ctx, f.olivia, r.ID, done.Version, attested())
	refused(t, err, inventory.Conflict)

	// Only an agent in service, or suspended, has an open review.
	v := f.inState(t, "validated-agent", "validated")
	future := f.clk.Now().Add(time.Hour)
	f.review(t, v.ID, &future)
	_, err = f.inv.CompleteReview(ctx, f.olivia, f.openReview(t, v.ID).ID, 1, attested())
	refused(t, err, inventory.Conflict)
}

// An agent that White Tower suspended because its review is overdue comes
// back once the review is completed and signed off: the owner completes it
// while the agent is suspended, and the advisory committee reinstates it.
func TestCompletingAnOverdueReviewLetsTheAgentBeReinstated(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.inState(t, "invoice-triage", "active")
	f.clk.Advance((180 + 14 + 1) * 24 * time.Hour)
	if !f.system(t, a.ID, inventory.Cause{Action: "auto_suspend", Reason: "review_overdue"}) {
		t.Fatal("the agent of an overdue review was not suspended")
	}
	_, err := f.act(f.alex, f.get(t, a.ID), "reinstate", "Reviewed.")
	refusedBy(t, err, "review_not_overdue")
	r := f.openReview(t, a.ID)
	if !r.Overdue {
		t.Errorf("the review is not overdue: %+v", r)
	}
	r, err = f.inv.CompleteReview(ctx, f.olivia, r.ID, r.Version, attested())
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.act(f.alex, f.get(t, a.ID), "reinstate", "Reviewed.")
	refusedBy(t, err, "review_not_overdue") // until it is signed off
	if _, err := f.inv.SignOffReview(ctx, f.alex, r.ID, r.Version); err != nil {
		t.Fatal(err)
	}
	if back, err := f.act(f.alex, f.get(t, a.ID), "reinstate", "Reviewed."); err != nil || back.LifecycleState != "active" {
		t.Fatalf("got %+v, %v", back, err)
	}
}

// A member of the advisory committee signs off a review that waits for it:
// the review is completed, it leaves the inbox, and the next one is
// scheduled from the sign-off. It is signed off once.
func TestTheAdvisoryCommitteeSignsOffAReview(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a, r := f.completed(t, "invoice-triage")
	f.clk.Advance(24 * time.Hour)
	_, err := f.inv.SignOffReview(ctx, f.alex, r.ID, r.Version-1)
	refused(t, err, inventory.Stale)
	_, err = f.inv.SignOffReview(ctx, f.uma, r.ID, r.Version)
	refused(t, err, inventory.Forbidden)
	_, err = f.inv.SignOffReview(ctx, f.alex, uuid.Must(uuid.NewV7()), 1)
	refused(t, err, inventory.NotFound)
	done, err := f.inv.SignOffReview(ctx, f.alex, r.ID, r.Version)
	if err != nil {
		t.Fatal(err)
	}
	now := f.clk.Now()
	if done.Status != "completed" || done.Version != r.Version+1 || done.SignedOffBy == nil || done.SignedOffBy.ID.String() != f.alex.ID ||
		!done.SignedOffAt.Equal(now) || done.CompletedBy.ID.String() != f.olivia.ID {
		t.Errorf("signed off: %+v", done)
	}
	changed := f.events(t, "whitetower.review.changed.v1")
	signed, next := changed[len(changed)-2], changed[len(changed)-1]
	following := f.openReview(t, a.ID)
	if f.signoffItems(t, r.ID) != 0 || signed.data["change"] != "signed_off" || signed.actorID != f.alex.ID ||
		following.ID == r.ID || !following.DueAt.Equal(now.UTC().AddDate(0, 0, 180)) || next.data["review_id"] != following.ID.String() {
		t.Errorf("after the sign-off: items %d, events %+v %+v, next review %+v", f.signoffItems(t, r.ID), signed, next, following)
	}
	_, err = f.inv.SignOffReview(ctx, f.alex, r.ID, done.Version)
	refused(t, err, inventory.Conflict)
	_, err = f.inv.SignOffReview(ctx, f.alex, following.ID, following.Version)
	refused(t, err, inventory.Conflict) // scheduled, not completed yet
}

// Security test ST-18: A review is signed off by a person of the advisory committee who never owned the agent, never created it or its use case, and did not complete the review
func TestASignOffKeepsSeparationOfDuties(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	adam := f.member(t, "Adam Advisory", "owner", "advisory")
	adamID := uuid.MustParse(adam.ID)
	for i, c := range []struct {
		name   string
		caller auth.Principal
		spoil  func(t *testing.T, a *inventory.Agent, r *inventory.Review)
		want   inventory.RefusalKind
	}{
		{"a delegate", adam, func(t *testing.T, a *inventory.Agent, _ *inventory.Review) {
			if _, err := f.inv.AddDelegate(ctx, f.olivia, a.ID, adamID); err != nil {
				t.Fatal(err)
			}
		}, inventory.Forbidden},
		{"a former delegate", adam, func(t *testing.T, a *inventory.Agent, _ *inventory.Review) {
			if _, err := f.inv.AddDelegate(ctx, f.olivia, a.ID, adamID); err != nil {
				t.Fatal(err)
			}
			if err := f.inv.RemoveDelegate(ctx, f.olivia, a.ID, adamID, "Moved on."); err != nil {
				t.Fatal(err)
			}
		}, inventory.Forbidden},
		{"a former primary owner", adam, func(t *testing.T, a *inventory.Agent, _ *inventory.Review) {
			for _, to := range []auth.Principal{adam, f.olivia} {
				if _, err := f.inv.Reassign(ctx, f.omar, a.ID, f.get(t, a.ID).Version, uuid.MustParse(to.ID), "Cover."); err != nil {
					t.Fatal(err)
				}
			}
		}, inventory.Forbidden},
		{"the creator of the agent", adam, func(t *testing.T, a *inventory.Agent, _ *inventory.Review) {
			f.set(t, `UPDATE whitetower.agents SET created_by = $2 WHERE id = $1`, a.ID, adamID)
		}, inventory.Forbidden},
		{"the creator of its use case", adam, func(t *testing.T, a *inventory.Agent, _ *inventory.Review) {
			f.set(t, `UPDATE whitetower.use_cases SET created_by = $2 WHERE id = $1`, a.UseCaseID, adamID)
		}, inventory.Forbidden},
		{"whoever completed the review", adam, func(t *testing.T, _ *inventory.Agent, r *inventory.Review) {
			f.set(t, `UPDATE whitetower.reviews SET completed_by = $2 WHERE id = $1`, r.ID, adamID)
		}, inventory.Forbidden},
		{"a service account", f.serviceAccount(t, "advisory"), nil, inventory.Forbidden},
		{"an owner", f.otto, nil, inventory.Forbidden},
		{"an operator", f.omar, nil, inventory.Forbidden},
		{"a break-glass session", auth.Principal{ID: f.alex.ID, Kind: auth.Human, Roles: []string{"advisory"}, IsBreakglass: true}, nil, inventory.Forbidden},
		{"a token without the scope", auth.Principal{ID: f.alex.ID, Kind: auth.Human, Roles: []string{"advisory"}, Scopes: []string{"inventory.view"}}, nil, inventory.Forbidden},
	} {
		t.Run(c.name, func(t *testing.T) {
			a, r := f.completed(t, fmt.Sprintf("agent-%d", i))
			if c.spoil != nil {
				c.spoil(t, a, r)
			}
			_, err := f.inv.SignOffReview(ctx, c.caller, r.ID, r.Version)
			refused(t, err, c.want)
			if got := f.openReview(t, a.ID); got.Status != "awaiting_signoff" || got.SignedOffBy != nil {
				t.Errorf("a refusal changed the review: %+v", got)
			}
		})
	}
	a, r := f.completed(t, "independent")
	if _, err := f.inv.AddDelegate(ctx, f.olivia, a.ID, uuid.MustParse(f.otto.ID)); err != nil {
		t.Fatal(err)
	}
	scoped := auth.Principal{ID: adam.ID, Kind: auth.Human, Roles: adam.Roles, Scopes: []string{"inventory.view", "agent.review"}}
	if _, err := f.inv.SignOffReview(ctx, scoped, r.ID, r.Version); err != nil {
		t.Fatalf("an independent member of the committee: %v", err)
	}

	// The review's signoffRequired decides, not the agent's risk tier: a
	// review of a low risk agent that needs a sign-off is signed off, and
	// one of a high risk agent that does not is not.
	low, r := f.completed(t, "low-risk")
	f.set(t, `UPDATE whitetower.agents SET risk_tier = 'low' WHERE id = $1`, low.ID)
	if _, err := f.inv.SignOffReview(ctx, f.alex, r.ID, r.Version); err != nil {
		t.Fatalf("a low risk agent's review that needs a sign-off: %v", err)
	}
	high, r := f.completed(t, "without-signoff")
	f.set(t, `UPDATE whitetower.reviews SET signoff_required = false WHERE id = $1`, r.ID)
	_, err := f.inv.SignOffReview(ctx, f.alex, r.ID, r.Version)
	refused(t, err, inventory.Forbidden)
	if f.openReview(t, high.ID).Status != "awaiting_signoff" {
		t.Error("a review that needs no sign-off was signed off")
	}
}

// Security test ST-18: The database refuses a review's sign-off by anyone but an independent person, as the inventory does
func TestTheDatabaseRefusesASignOffByAParty(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	adam := f.member(t, "Adam Advisory", "owner", "advisory")
	bot := f.serviceAccount(t, "advisory")
	signOff := func(review uuid.UUID, by string) error {
		_, err := f.pool.Exec(ctx, `UPDATE whitetower.reviews SET status = 'completed', signed_off_by = $2, signed_off_at = now()
			WHERE id = $1`, review, uuid.MustParse(by))
		return err
	}
	for i, c := range []struct {
		name  string
		by    string
		spoil func(t *testing.T, a *inventory.Agent, r *inventory.Review)
	}{
		{"the primary owner, who completed it", f.olivia.ID, nil},
		{"a delegate", adam.ID, func(t *testing.T, a *inventory.Agent, _ *inventory.Review) {
			if _, err := f.inv.AddDelegate(ctx, f.olivia, a.ID, uuid.MustParse(adam.ID)); err != nil {
				t.Fatal(err)
			}
		}},
		{"a former delegate", adam.ID, func(t *testing.T, a *inventory.Agent, _ *inventory.Review) {
			if _, err := f.inv.AddDelegate(ctx, f.olivia, a.ID, uuid.MustParse(adam.ID)); err != nil {
				t.Fatal(err)
			}
			if err := f.inv.RemoveDelegate(ctx, f.olivia, a.ID, uuid.MustParse(adam.ID), "Moved on."); err != nil {
				t.Fatal(err)
			}
		}},
		{"the creator of the agent", adam.ID, func(t *testing.T, a *inventory.Agent, _ *inventory.Review) {
			f.set(t, `UPDATE whitetower.agents SET created_by = $2 WHERE id = $1`, a.ID, uuid.MustParse(adam.ID))
		}},
		{"the creator of its use case", adam.ID, func(t *testing.T, a *inventory.Agent, _ *inventory.Review) {
			f.set(t, `UPDATE whitetower.use_cases SET created_by = $2 WHERE id = $1`, a.UseCaseID, uuid.MustParse(adam.ID))
		}},
		{"whoever completed it", adam.ID, func(t *testing.T, _ *inventory.Agent, r *inventory.Review) {
			f.set(t, `UPDATE whitetower.reviews SET completed_by = $2 WHERE id = $1`, r.ID, uuid.MustParse(adam.ID))
		}},
		{"a review that nobody completed", f.alex.ID, func(t *testing.T, _ *inventory.Agent, r *inventory.Review) {
			f.set(t, `UPDATE whitetower.reviews SET completed_by = NULL WHERE id = $1`, r.ID)
		}},
		{"a service account", bot.ID, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			a, r := f.completed(t, fmt.Sprintf("agent-%d", i))
			if c.spoil != nil {
				c.spoil(t, a, r)
			}
			var pgErr *pgconn.PgError
			if err := signOff(r.ID, c.by); !errors.As(err, &pgErr) || pgErr.Code != "42501" {
				t.Fatalf("got %v, want insufficient_privilege", err)
			}
		})
	}
	a, r := f.completed(t, "inserted")
	var pgErr *pgconn.PgError
	if _, err := f.pool.Exec(ctx, `INSERT INTO whitetower.reviews (id, agent_id, due_at, grace_ends_at, status, completed_by, signoff_required, signed_off_by)
		VALUES ($1, $2, now(), now(), 'completed', $3, true, $3)`, uuid.Must(uuid.NewV7()), a.ID, uuid.MustParse(f.olivia.ID)); !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("an inserted review signed off by its owner: %v", err)
	}
	if err := signOff(r.ID, f.alex.ID); err != nil {
		t.Fatalf("an independent member of the committee: %v", err)
	}
}

// Retiring an agent cancels its open review, which leaves every inbox; it is
// then neither completed nor signed off.
func TestRetirementCancelsTheOpenReview(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a, r := f.completed(t, "invoice-triage")
	if _, err := f.act(f.olivia, f.get(t, a.ID), "retire", "No longer needed."); err != nil {
		t.Fatal(err)
	}
	got, err := f.inv.GetReview(ctx, f.omar, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	e := f.lastReviewEvent(t)
	if got.Status != "cancelled" || got.Version != r.Version+1 || got.Overdue || f.signoffItems(t, r.ID) != 0 || //nolint:misspell // the schema's spelling
		e.data["change"] != "cancelled" || e.actorID != f.olivia.ID || e.data["review_id"] != r.ID.String() { //nolint:misspell // the schema's spelling
		t.Errorf("after the retirement: %+v, event %+v", got, e)
	}
	_, err = f.inv.SignOffReview(ctx, f.alex, r.ID, got.Version)
	refused(t, err, inventory.Conflict)
}

// Whoever sees an agent sees its reviews; only a caller who may view agents'
// tooling sees the candidates to disable and the tooling kept, and lists
// leave the candidates out. Lists go a page at a time, by due date, and
// filter on status and on whether a review is overdue.
func TestReviewsAreReadAsTheCallerMaySeeThem(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.inState(t, "invoice-triage", "active")
	f.tooling.set(a.ID, inventory.UnusedTool{Key: "invoices/archive_invoice", Kind: "tool"})
	r := f.openReview(t, a.ID)
	if _, err := f.inv.CompleteReview(ctx, f.olivia, r.ID, r.Version, attested("invoices/archive_invoice")); err != nil {
		t.Fatal(err)
	}
	breakglass := auth.Principal{ID: f.omar.ID, Kind: auth.Human, Roles: []string{"operator"}, IsBreakglass: true}
	for _, c := range []struct {
		name    string
		caller  auth.Principal
		tooling bool
	}{
		{"the advisory committee", f.alex, true},
		{"a user", f.uma, false},
		{"a break-glass session", breakglass, false},
	} {
		got, err := f.inv.GetReview(ctx, c.caller, r.ID)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if (got.UnusedTooling != nil) != c.tooling || (got.Attestation.KeptTooling != nil) != c.tooling || !got.Attestation.StillNeeded {
			t.Errorf("%s reads %+v, attestation %+v", c.name, got, got.Attestation)
		}
	}
	suspended := f.inState(t, "suspended-agent", "suspended from active")
	hidden := f.openReview(t, suspended.ID)
	_, err := f.inv.GetReview(ctx, f.uma, hidden.ID)
	refused(t, err, inventory.NotFound)
	_, err = f.inv.GetReview(ctx, f.olivia, uuid.Must(uuid.NewV7()))
	refused(t, err, inventory.NotFound)
	_, _, err = f.inv.AgentReviews(ctx, f.uma, suspended.ID, nil, 10)
	refused(t, err, inventory.NotFound)

	// Three reviews of one agent, each completed but the last.
	m := f.inState(t, "medium-agent", "ready")
	f.set(t, `UPDATE whitetower.agents SET risk_tier = 'medium', version = version + 1 WHERE id = $1`, m.ID)
	if _, err := f.inv.Transition(ctx, f.olivia, m.ID, m.Version+1, "activate", ""); err != nil {
		t.Fatal(err)
	}
	var ids []uuid.UUID
	for range 2 {
		open := f.openReview(t, m.ID)
		ids = append(ids, open.ID)
		f.clk.Advance(24 * time.Hour)
		if _, err := f.inv.CompleteReview(ctx, f.olivia, open.ID, open.Version, attested()); err != nil {
			t.Fatal(err)
		}
	}
	ids = append(ids, f.openReview(t, m.ID).ID)
	first, more, err := f.inv.AgentReviews(ctx, f.uma, m.ID, nil, 2)
	if err != nil || !more || len(first) != 2 || first[0].ID != ids[2] || first[1].ID != ids[1] || first[1].Attestation.KeptTooling != nil {
		t.Fatalf("the first page: %+v, %v, %v", first, more, err)
	}
	rest, more, err := f.inv.AgentReviews(ctx, f.uma, m.ID, &inventory.ReviewPosition{DueAt: first[1].DueAt, ID: first[1].ID}, 2)
	if err != nil || more || len(rest) != 1 || rest[0].ID != ids[0] {
		t.Fatalf("the last page: %+v, %v, %v", rest, more, err)
	}

	list := func(caller auth.Principal, filter inventory.ReviewFilter) []uuid.UUID {
		t.Helper()
		reviews, more, err := f.inv.ListReviews(ctx, caller, filter, nil, 50)
		if err != nil || more {
			t.Fatalf("listReviews %+v: %v, %v", filter, more, err)
		}
		found := make([]uuid.UUID, len(reviews))
		for i, rv := range reviews {
			found[i] = rv.ID
			if rv.UnusedTooling != nil {
				t.Errorf("a list shows candidates to disable: %+v", rv)
			}
		}
		return found
	}
	yes, no := true, false
	if got := list(f.alex, inventory.ReviewFilter{Statuses: []string{"completed"}}); !slices.Equal(got, ids[:2]) {
		t.Errorf("the completed reviews: %v, want %v", got, ids[:2])
	}
	if got := list(f.alex, inventory.ReviewFilter{}); !slices.Equal(got, []uuid.UUID{r.ID, hidden.ID, ids[0], ids[1], ids[2]}) {
		t.Errorf("every review, the earliest due first: %v", got)
	}
	if got := list(f.uma, inventory.ReviewFilter{}); slices.Contains(got, hidden.ID) || len(got) != 4 {
		t.Errorf("a user lists the reviews of agents out of service: %v", got)
	}
	f.clk.Advance(200 * 24 * time.Hour)
	if got := list(f.alex, inventory.ReviewFilter{Overdue: &yes}); !slices.Equal(got, []uuid.UUID{r.ID, hidden.ID}) {
		t.Errorf("the overdue reviews: %v", got)
	}
	if got := list(f.alex, inventory.ReviewFilter{Overdue: &no, Statuses: []string{"scheduled", "completed"}}); !slices.Equal(got, []uuid.UUID{ids[0], ids[1], ids[2]}) {
		t.Errorf("the reviews that are not overdue: %v", got)
	}
	for _, statuses := range [][]string{{"lost"}, {"scheduled", "scheduled", "completed", "cancelled", "awaiting_signoff"}} { //nolint:misspell // the schema's spelling
		_, _, err := f.inv.ListReviews(ctx, f.alex, inventory.ReviewFilter{Statuses: statuses}, nil, 10)
		refused(t, err, inventory.Invalid)
	}
}
