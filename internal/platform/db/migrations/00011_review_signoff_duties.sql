-- +goose Up
-- The sign-off of a periodic review, by someone independent (plan P1-04,
-- pull request 5a; HUM-04), enforced again by the database, as the approval
-- of a policy version is (reject_self_approval).
--
-- A member of the advisory committee signs off a review that its agent's
-- owner completed. The inventory refuses the sign-off to anyone but a person,
-- to whoever is or ever was the agent's primary owner or one of its
-- delegates, to the creator of the agent or of its use case, and to whoever
-- completed the review. This trigger refuses the same, so that a sign-off
-- written past the inventory, or a later change of the inventory that forgot
-- a rule, fails. The check reviews_signoff_by_someone_else stays; it lets a
-- review that nobody completed through, which this trigger does not.
-- +goose StatementBegin
CREATE FUNCTION whitetower.reject_review_signoff_by_party() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (SELECT FROM whitetower.principals p WHERE p.id = NEW.signed_off_by AND p.kind = 'human') THEN
    RAISE EXCEPTION 'whitetower: only a person signs off a periodic review'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.completed_by IS NULL OR NEW.signed_off_by = NEW.completed_by THEN
    RAISE EXCEPTION 'whitetower: a periodic review is signed off by someone other than whoever completed it'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF EXISTS (SELECT FROM whitetower.agent_owners o
             WHERE o.agent_id = NEW.agent_id AND o.principal_id = NEW.signed_off_by)
     OR EXISTS (SELECT FROM whitetower.agents a
                JOIN whitetower.use_cases u ON u.id = a.use_case_id
                WHERE a.id = NEW.agent_id AND NEW.signed_off_by IN (a.created_by, u.created_by)) THEN
    RAISE EXCEPTION 'whitetower: nobody signs off the review of an agent they own, delegate for, ever did, or created, nor of one whose use case they created'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER reviews_signoff_not_by_party
  BEFORE INSERT OR UPDATE OF signed_off_by, completed_by, agent_id ON whitetower.reviews
  FOR EACH ROW WHEN (NEW.signed_off_by IS NOT NULL)
  EXECUTE FUNCTION whitetower.reject_review_signoff_by_party();

-- The list of reviews goes by due date (listReviews).
CREATE INDEX reviews_by_due ON whitetower.reviews (due_at, id);
