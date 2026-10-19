package inventory_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/inventory"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/db"
)

// ownerID is the owner that the agent's governance state tells policies.
func (f *fixture) ownerID(t *testing.T, agent uuid.UUID) string {
	t.Helper()
	var raw []byte
	if err := f.pool.QueryRow(context.Background(),
		`SELECT attributes FROM whitetower.governance_state WHERE agent_id = $1`, agent).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var attrs map[string]any
	if err := json.Unmarshal(raw, &attrs); err != nil {
		t.Fatal(err)
	}
	owner, _ := attrs["owner_id"].(string)
	return owner
}

// primaries counts the agent's current primary owners, of which there is
// always exactly one.
func (f *fixture) primaries(t *testing.T, agent uuid.UUID) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM whitetower.agent_owners WHERE agent_id = $1 AND role = 'primary' AND ended_at IS NULL`, agent).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// lockWaits counts the sessions of the test's database that wait for a lock.
func (f *fixture) lockWaits(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// openInboxItems counts the open inbox items about the transfer.
func (f *fixture) openInboxItems(t *testing.T, transfer uuid.UUID) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM whitetower.inbox_items
		 WHERE subject_type = 'ownership_transfer' AND subject_id = $1 AND resolved_at IS NULL`, transfer).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestReassigningMakesAnotherPersonThePrimaryOwnerAtOnce(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.propose(t, "invoice-triage")
	before := f.stateVersion(t, a.ID)

	got, err := f.inv.Reassign(ctx, f.omar, a.ID, a.Version, uuid.MustParse(f.otto.ID), "Olivia left the finance team")
	if err != nil {
		t.Fatal(err)
	}
	if got.PrimaryOwner.ID.String() != f.otto.ID || got.Version != a.Version+1 {
		t.Fatalf("primary owner %v at version %d", got.PrimaryOwner, got.Version)
	}
	if after := f.stateVersion(t, a.ID); after <= before || f.ownerID(t, a.ID) != f.otto.ID {
		t.Errorf("state version %d after %d, owner %s: policies must see the new owner", after, before, f.ownerID(t, a.ID))
	}
	if owns, err := f.inv.IsOwner(ctx, a.ID, uuid.MustParse(f.olivia.ID)); err != nil || owns || f.primaries(t, a.ID) != 1 {
		t.Errorf("the former owner still owns: %v, %v; %d primary owners", owns, err, f.primaries(t, a.ID))
	}
	changed := f.events(t, "whitetower.agent.ownership_changed.v1")
	if len(changed) != 1 || changed[0].data["change"] != "owner_reassigned" || changed[0].data["former_owner"] != f.olivia.ID ||
		changed[0].data["state_version"] != float64(f.stateVersion(t, a.ID)) {
		t.Fatalf("events %+v", changed)
	}
	if _, copied := changed[0].data["reason"]; copied {
		t.Error("the reason that people write is copied into the event")
	}
	history, _, err := f.inv.Owners(ctx, f.alex, a.ID, nil, false, 50)
	if err != nil || len(history) != 2 || history[1].Principal.ID.String() != f.olivia.ID ||
		history[1].EndReason != "Olivia left the finance team" || history[1].EndedBy.ID.String() != f.omar.ID {
		t.Fatalf("history %+v, %v", history, err)
	}

	// The advisory committee reassigns too; owners do not, and a stale version
	// is refused.
	if _, err := f.inv.Reassign(ctx, f.alex, a.ID, got.Version, uuid.MustParse(f.olivia.ID), "back from leave"); err != nil {
		t.Fatalf("the advisory committee: %v", err)
	}
	_, err = f.inv.Reassign(ctx, f.otto, a.ID, got.Version+1, uuid.MustParse(f.otto.ID), "taking it back")
	refused(t, err, inventory.Forbidden)
	_, err = f.inv.Reassign(ctx, f.omar, a.ID, got.Version, uuid.MustParse(f.otto.ID), "again")
	refused(t, err, inventory.Stale)
	_, err = f.inv.Reassign(ctx, f.omar, a.ID, got.Version+1, uuid.MustParse(f.olivia.ID), "no change")
	refused(t, err, inventory.Conflict)
	_, err = f.inv.Reassign(ctx, f.omar, a.ID, got.Version+1, uuid.MustParse(f.otto.ID), " ")
	refused(t, err, inventory.Invalid)
}

func TestOnlyAnActivePersonWithTheOwnerRoleOwnsAnAgent(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.propose(t, "invoice-triage")
	inactive := f.person(t, "Ines Inactive", "owner")
	f.set(t, `UPDATE whitetower.principals SET status = 'inactive' WHERE id = $1`, uuid.MustParse(inactive.ID))
	bot := uuid.Must(uuid.NewV7())
	f.set(t, `INSERT INTO whitetower.principals (id, kind, display_name, responsible_principal_id)
		VALUES ($1, 'service_account', 'Bot', $2)`, bot, uuid.MustParse(f.olivia.ID))
	bind := func(principal uuid.UUID) {
		f.set(t, `INSERT INTO whitetower.role_bindings (id, principal_id, role, reason, granted_by)
			VALUES ($1, $2, 'owner', 'owns agents', $3)`, uuid.Must(uuid.NewV7()), principal, uuid.MustParse(f.omar.ID))
	}
	bind(bot)
	for name, target := range map[string]uuid.UUID{
		"a user":                   uuid.MustParse(f.uma.ID),
		"an inactive owner":        uuid.MustParse(inactive.ID),
		"a service account":        bot,
		"a principal that is none": uuid.Must(uuid.NewV7()),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := f.inv.Reassign(ctx, f.omar, a.ID, a.Version, target, "a reason")
			refused(t, err, inventory.Invalid)
			_, err = f.inv.AddDelegate(ctx, f.olivia, a.ID, target)
			refused(t, err, inventory.Invalid)
			_, err = f.inv.RequestTransfer(ctx, f.olivia, a.ID, target)
			refused(t, err, inventory.Invalid)
		})
	}

	// The owner role can come from a local binding rather than an IdP group.
	local := f.person(t, "Lou Local", "nothing")
	bind(uuid.MustParse(local.ID))
	if _, err := f.inv.AddDelegate(ctx, f.olivia, a.ID, uuid.MustParse(local.ID)); err != nil {
		t.Fatalf("a person bound to the owner role: %v", err)
	}
}

func TestOwnersAndOperatorsManageTheDelegates(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.propose(t, "invoice-triage")
	otto := uuid.MustParse(f.otto.ID)

	assignment, err := f.inv.AddDelegate(ctx, f.olivia, a.ID, otto)
	if err != nil || assignment.Role != "delegate" || assignment.Principal.ID != otto || assignment.AssignedBy.ID.String() != f.olivia.ID {
		t.Fatalf("got %+v, %v", assignment, err)
	}
	got, err := f.inv.Get(ctx, f.alex, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Delegates) != 1 || got.Version != a.Version+1 {
		t.Fatalf("delegates %v at version %d; the ETag changes with the delegates", got.Delegates, got.Version)
	}
	_, err = f.inv.AddDelegate(ctx, f.olivia, a.ID, otto)
	refused(t, err, inventory.Conflict)
	_, err = f.inv.AddDelegate(ctx, f.olivia, a.ID, uuid.MustParse(f.olivia.ID))
	refused(t, err, inventory.Conflict)
	nora := f.person(t, "Nora Owner", "owner")
	for name, caller := range map[string]auth.Principal{"an owner of other agents": nora, "the advisory committee": f.alex, "a user": f.uma} {
		t.Run(name, func(t *testing.T) {
			_, err := f.inv.AddDelegate(ctx, caller, a.ID, uuid.MustParse(nora.ID))
			refused(t, err, inventory.Forbidden)
			err = f.inv.RemoveDelegate(ctx, caller, a.ID, otto, "a reason")
			refused(t, err, inventory.Forbidden)
		})
	}

	// The delegate acts for the owner.
	name := "Invoice sorter"
	if _, err := f.inv.Edit(ctx, f.otto, a.ID, got.Version, inventory.AgentChanges{Name: &name}); err != nil {
		t.Fatalf("the delegate edits: %v", err)
	}

	err = f.inv.RemoveDelegate(ctx, f.omar, a.ID, otto, "")
	refused(t, err, inventory.Invalid)
	err = f.inv.RemoveDelegate(ctx, f.omar, a.ID, uuid.MustParse(f.olivia.ID), "not a delegate")
	refused(t, err, inventory.NotFound)
	if err := f.inv.RemoveDelegate(ctx, f.omar, a.ID, otto, "moved to another team"); err != nil {
		t.Fatal(err)
	}
	if owns, err := f.inv.IsOwner(ctx, a.ID, otto); err != nil || owns {
		t.Errorf("a removed delegate still owns: %v, %v", owns, err)
	}
	var changes []string
	for _, e := range f.events(t, "whitetower.agent.ownership_changed.v1") {
		changes = append(changes, e.data["change"].(string))
	}
	if len(changes) != 2 || changes[0] != "delegate_added" || changes[1] != "delegate_removed" {
		t.Errorf("changes %v", changes)
	}
}

func TestATransferWaitsForItsRecipient(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.propose(t, "invoice-triage")
	otto := uuid.MustParse(f.otto.ID)

	request := func(t *testing.T) *inventory.Transfer {
		t.Helper()
		tr, err := f.inv.RequestTransfer(ctx, f.olivia, a.ID, otto)
		if err != nil {
			t.Fatal(err)
		}
		if tr.Status != "pending" || tr.From.ID.String() != f.olivia.ID || tr.To.ID != otto || f.openInboxItems(t, tr.ID) != 1 {
			t.Fatalf("got %+v: want a pending transfer from Olivia to Otto, in Otto's inbox", tr)
		}
		return tr
	}

	t.Run("declined", func(t *testing.T) {
		tr := request(t)
		got, err := f.inv.Get(ctx, f.alex, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.PendingTransfer == nil || got.PendingTransfer.ID != tr.ID {
			t.Fatalf("pending transfer %+v", got.PendingTransfer)
		}
		_, err = f.inv.RequestTransfer(ctx, f.olivia, a.ID, otto)
		refused(t, err, inventory.Conflict)
		_, err = f.inv.DeclineTransfer(ctx, f.alex, a.ID, tr.ID)
		refused(t, err, inventory.Forbidden)
		declined, err := f.inv.DeclineTransfer(ctx, f.otto, a.ID, tr.ID)
		if err != nil || declined.Status != "declined" || declined.DecidedAt == nil || f.openInboxItems(t, tr.ID) != 0 {
			t.Fatalf("got %+v, %v", declined, err)
		}
		_, err = f.inv.AcceptTransfer(ctx, f.otto, a.ID, tr.ID)
		refused(t, err, inventory.Conflict)
	})

	t.Run("canceled by the owner who offered it, or by an operator", func(t *testing.T) {
		for _, by := range []auth.Principal{f.olivia, f.omar} {
			tr := request(t)
			for _, other := range []auth.Principal{f.otto, f.alex} {
				refused(t, f.inv.CancelTransfer(ctx, other, a.ID, tr.ID), inventory.Forbidden)
			}
			if err := f.inv.CancelTransfer(ctx, by, a.ID, tr.ID); err != nil || f.openInboxItems(t, tr.ID) != 0 {
				t.Fatalf("%s: %v", by.Name, err)
			}
		}
	})

	t.Run("refused to an inactive recipient", func(t *testing.T) {
		tr := request(t)
		f.set(t, `UPDATE whitetower.principals SET status = 'inactive' WHERE id = $1`, otto)
		defer f.set(t, `UPDATE whitetower.principals SET status = 'active' WHERE id = $1`, otto)
		_, err := f.inv.AcceptTransfer(ctx, f.otto, a.ID, tr.ID)
		refused(t, err, inventory.Invalid)
		if err := f.inv.CancelTransfer(ctx, f.olivia, a.ID, tr.ID); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("accepted by its recipient", func(t *testing.T) {
		tr := request(t)
		scoped := f.otto
		scoped.Scopes = []string{"identity.me.read"}
		_, err := f.inv.AcceptTransfer(ctx, scoped, a.ID, tr.ID)
		refused(t, err, inventory.Forbidden)
		before := f.stateVersion(t, a.ID)
		accepted, err := f.inv.AcceptTransfer(ctx, f.otto, a.ID, tr.ID)
		if err != nil || accepted.Status != "accepted" || f.openInboxItems(t, tr.ID) != 0 {
			t.Fatalf("got %+v, %v", accepted, err)
		}
		got, err := f.inv.Get(ctx, f.alex, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.PrimaryOwner.ID != otto || got.PendingTransfer != nil {
			t.Fatalf("primary owner %v, pending %v", got.PrimaryOwner, got.PendingTransfer)
		}
		if after := f.stateVersion(t, a.ID); after <= before || f.ownerID(t, a.ID) != f.otto.ID || f.primaries(t, a.ID) != 1 {
			t.Errorf("state version %d after %d, %d primary owners: policies must see the new owner", after, before, f.primaries(t, a.ID))
		}
		events := f.events(t, "whitetower.agent.ownership_changed.v1")
		last := events[len(events)-1].data
		if last["change"] != "transfer_accepted" || last["former_owner"] != f.olivia.ID || last["transfer_id"] != tr.ID.String() {
			t.Errorf("event data %v", last)
		}
	})

	t.Run("offered only by the primary owner, to someone else", func(t *testing.T) {
		// Otto owns the agent now; Olivia is no longer an owner of it.
		_, err := f.inv.RequestTransfer(ctx, f.olivia, a.ID, uuid.MustParse(f.olivia.ID))
		refused(t, err, inventory.Forbidden)
		_, err = f.inv.RequestTransfer(ctx, f.omar, a.ID, uuid.MustParse(f.olivia.ID))
		refused(t, err, inventory.Forbidden)
		_, err = f.inv.RequestTransfer(ctx, f.otto, a.ID, otto)
		refused(t, err, inventory.Invalid)
	})
}

func TestTheNewPrimaryOwnerStopsBeingADelegate(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.propose(t, "invoice-triage")
	olivia, otto := uuid.MustParse(f.olivia.ID), uuid.MustParse(f.otto.ID)
	if _, err := f.inv.AddDelegate(ctx, f.olivia, a.ID, otto); err != nil {
		t.Fatal(err)
	}
	current, err := f.inv.Get(ctx, f.alex, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.inv.Reassign(ctx, f.omar, a.ID, current.Version, otto, "Olivia moved to another team")
	if err != nil {
		t.Fatal(err)
	}
	if got.PrimaryOwner.ID != otto || len(got.Delegates) != 0 {
		t.Fatalf("primary owner %v, delegates %v", got.PrimaryOwner, got.Delegates)
	}

	// The same through a transfer, back to Olivia as a delegate.
	if _, err := f.inv.AddDelegate(ctx, f.otto, a.ID, olivia); err != nil {
		t.Fatal(err)
	}
	tr, err := f.inv.RequestTransfer(ctx, f.otto, a.ID, olivia)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.inv.AcceptTransfer(ctx, f.olivia, a.ID, tr.ID); err != nil {
		t.Fatal(err)
	}
	if got, err = f.inv.Get(ctx, f.alex, a.ID); err != nil {
		t.Fatal(err)
	}
	if got.PrimaryOwner.ID != olivia || len(got.Delegates) != 0 || f.primaries(t, a.ID) != 1 {
		t.Fatalf("primary owner %v, delegates %v, %d primary owners", got.PrimaryOwner, got.Delegates, f.primaries(t, a.ID))
	}
	history, _, err := f.inv.Owners(ctx, f.alex, a.ID, nil, false, 50)
	if err != nil {
		t.Fatal(err)
	}
	var reasons []string
	for _, h := range history {
		if h.EndedAt != nil {
			reasons = append(reasons, h.Principal.DisplayName+" "+h.Role+": "+h.EndReason)
		}
	}
	want := fmt.Sprint([]string{
		"Olivia Owner delegate: became the primary owner",
		"Otto Owner primary: ownership transferred",
		"Otto Owner delegate: became the primary owner",
		"Olivia Owner primary: Olivia moved to another team",
	})
	if fmt.Sprint(reasons) != want {
		t.Errorf("ended assignments %v, want %v", reasons, want)
	}
}

// Changes of an agent's owners happen one after the other: of two
// reassignments at the same version that are under way together, one wins,
// and the other is refused as stale rather than failing on the database's
// constraints.
func TestReassignmentsUnderWayTogetherHappenOneAfterTheOther(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.propose(t, "invoice-triage")

	// Holding the row of the agent's governance state, which a reassignment
	// writes last, keeps the first one from committing until both wait.
	held, release, holder := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	t.Cleanup(free)
	go func() {
		holder <- f.pool.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT 1 FROM whitetower.governance_state WHERE agent_id = $1 FOR UPDATE`, a.ID); err != nil {
				return err
			}
			close(held)
			<-release
			return nil
		})
	}()
	select {
	case <-held:
	case err := <-holder:
		t.Fatal(err)
	}
	errs := make(chan error, 2)
	for _, name := range []string{"Nora Owner", "Noah Owner"} {
		owner := uuid.MustParse(f.person(t, name, "owner").ID)
		go func() {
			_, err := f.inv.Reassign(ctx, f.omar, a.ID, a.Version, owner, "reorganization")
			errs <- err
		}()
	}
	for deadline := time.Now().Add(10 * time.Second); f.lockWaits(t) < 2; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the reassignments never waited for a lock")
		}
	}
	free()
	if err := <-holder; err != nil {
		t.Fatal(err)
	}
	won := 0
	for range 2 {
		if err := <-errs; err != nil {
			refused(t, err, inventory.Stale)
			continue
		}
		won++
	}
	if won != 1 || f.primaries(t, a.ID) != 1 {
		t.Errorf("%d reassignments won, and the agent has %d primary owners: want 1 and 1", won, f.primaries(t, a.ID))
	}
}

// A change of the primary owner cancels a pending transfer. Were a later
// change to forget, the transfer would still not hand the agent over.
func TestATransferDoesNotOutliveItsGiversOwnership(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.propose(t, "invoice-triage")
	tr, err := f.inv.RequestTransfer(ctx, f.olivia, a.ID, uuid.MustParse(f.otto.ID))
	if err != nil {
		t.Fatal(err)
	}
	nora := f.person(t, "Nora Owner", "owner")
	f.set(t, `UPDATE whitetower.agent_owners SET ended_by = $2, ended_at = now(), end_reason = 'left'
		WHERE agent_id = $1 AND role = 'primary' AND ended_at IS NULL`, a.ID, uuid.MustParse(f.omar.ID))
	f.set(t, `INSERT INTO whitetower.agent_owners (id, agent_id, principal_id, role, assigned_by)
		VALUES ($1, $2, $3, 'primary', $4)`, uuid.Must(uuid.NewV7()), a.ID, uuid.MustParse(nora.ID), uuid.MustParse(f.omar.ID))
	_, err = f.inv.AcceptTransfer(ctx, f.otto, a.ID, tr.ID)
	refused(t, err, inventory.Conflict)
	got, err := f.inv.Get(ctx, f.alex, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PrimaryOwner.ID.String() != nora.ID {
		t.Errorf("primary owner %v, want Nora", got.PrimaryOwner)
	}
}

func TestReassigningCancelsAPendingTransfer(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.propose(t, "invoice-triage")
	tr, err := f.inv.RequestTransfer(ctx, f.olivia, a.ID, uuid.MustParse(f.otto.ID))
	if err != nil {
		t.Fatal(err)
	}
	current, err := f.inv.Get(ctx, f.alex, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	newOwner := f.person(t, "Nora Owner", "owner")
	if _, err := f.inv.Reassign(ctx, f.omar, a.ID, current.Version, uuid.MustParse(newOwner.ID), "reorganization"); err != nil {
		t.Fatal(err)
	}
	_, err = f.inv.AcceptTransfer(ctx, f.otto, a.ID, tr.ID)
	refused(t, err, inventory.Conflict)
	if f.openInboxItems(t, tr.ID) != 0 {
		t.Error("the canceled transfer is still in an inbox")
	}
}

func TestTheOwnersOfARetiredAgentNoLongerChange(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.propose(t, "invoice-triage")
	f.set(t, `UPDATE whitetower.agents SET lifecycle_state = 'retired', retired_at = now() WHERE id = $1`, a.ID)
	otto := uuid.MustParse(f.otto.ID)
	_, err := f.inv.AddDelegate(ctx, f.olivia, a.ID, otto)
	refused(t, err, inventory.Conflict)
	_, err = f.inv.Reassign(ctx, f.omar, a.ID, a.Version, otto, "a reason")
	refused(t, err, inventory.Conflict)
	_, err = f.inv.RequestTransfer(ctx, f.olivia, a.ID, otto)
	refused(t, err, inventory.Conflict)
}

func TestTheOwnersHistoryListsTheCurrentAssignmentsFirst(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.propose(t, "invoice-triage")
	otto, omar := uuid.MustParse(f.otto.ID), uuid.MustParse(f.person(t, "Oren Owner", "owner").ID)
	for _, delegate := range []uuid.UUID{otto, omar} {
		if _, err := f.inv.AddDelegate(ctx, f.olivia, a.ID, delegate); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.inv.RemoveDelegate(ctx, f.olivia, a.ID, otto, "moved on"); err != nil {
		t.Fatal(err)
	}

	var seen []string
	var after *uuid.UUID
	ended := false
	for {
		page, more, err := f.inv.Owners(ctx, f.alex, a.ID, after, ended, 1)
		if err != nil || len(page) != 1 {
			t.Fatalf("page %v, %v", page, err)
		}
		state := "current"
		if page[0].EndedAt != nil {
			state = "ended"
		}
		seen = append(seen, page[0].Principal.DisplayName+" "+page[0].Role+" "+state)
		if !more {
			break
		}
		after, ended = &page[0].ID, page[0].EndedAt != nil
	}
	want := []string{"Oren Owner delegate current", "Olivia Owner primary current", "Otto Owner delegate ended"}
	if len(seen) != len(want) {
		t.Fatalf("got %v, want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("got %v, want %v", seen, want)
		}
	}
}
