package authz

import "errors"

var (
	// ErrSelfApproval is returned when an author attempts to approve or validate their own item.
	ErrSelfApproval = errors.New("separation of duties: an author cannot approve or validate their own item (HUM-04)")

	// ErrSinglePersonRelease is returned when a halt release is attempted without a second person.
	ErrSinglePersonRelease = errors.New("separation of duties: halt release requires two distinct principals (HUM-04)")

	// ErrSelfRoleGrant is returned when a principal attempts to grant a role to themselves.
	ErrSelfRoleGrant = errors.New("separation of duties: a principal cannot grant a role to themselves (HUM-04)")

	// ErrMissingPrincipal is returned when required principal identification is missing.
	ErrMissingPrincipal = errors.New("separation of duties: principal identifier is required")
)

// CheckApproval enforces that the approver of a proposal, usecase, or policy version
// is distinct from the author (HUM-04, ST-18).
func CheckApproval(authorID, approverID string) error {
	if authorID == "" || approverID == "" {
		return ErrMissingPrincipal
	}
	if authorID == approverID {
		return ErrSelfApproval
	}
	return nil
}

// CheckHaltRelease enforces that the release of an agent or fleet halt requires
// two distinct individuals: the requester and the approver (HUM-04, ST-18).
func CheckHaltRelease(requesterID, approverID string) error {
	if requesterID == "" || approverID == "" {
		return ErrMissingPrincipal
	}
	if requesterID == approverID {
		return ErrSinglePersonRelease
	}
	return nil
}

// CheckRoleGrant enforces that an administrator cannot bind roles to themselves (HUM-04, ST-18).
func CheckRoleGrant(actorID, targetID string) error {
	if actorID == "" || targetID == "" {
		return ErrMissingPrincipal
	}
	if actorID == targetID {
		return ErrSelfRoleGrant
	}
	return nil
}
