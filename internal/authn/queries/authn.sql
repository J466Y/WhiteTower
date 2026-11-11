-- Queries of the human authentication and session domain (plan P1-03).

-- name: LockHumanPrincipalByExternalID :one
-- Locks the principal of the person whom the identity provider names by the
-- external ID, so that a sign-in reads the groups that it changes.
SELECT * FROM whitetower.principals
WHERE external_id = $1 AND kind = 'human'
FOR UPDATE;

-- name: LockHumanPrincipalByIdentity :one
-- Locks the principal, so that a sign-in reads the groups that it changes.
SELECT * FROM whitetower.principals
WHERE issuer = $1 AND subject = $2 AND kind = 'human'
FOR UPDATE;

-- name: InsertHumanPrincipal :one
-- Returns no row when a principal with the issuer and subject, or with the
-- external ID, exists, or another transaction created one meanwhile, once
-- that transaction commits.
INSERT INTO whitetower.principals (
    id, kind, issuer, subject, external_id, display_name, email, status, idp_groups, last_login_at, created_at, updated_at
) VALUES (
    $1, 'human', $2, $3, $4, $5, $6, 'active', $7, $8, $9, $9
)
ON CONFLICT DO NOTHING
RETURNING *;

-- name: UpdateHumanPrincipalAtSignIn :one
UPDATE whitetower.principals
SET external_id = $2,
    display_name = $3,
    email = $4,
    idp_groups = $5,
    last_login_at = $6,
    updated_at = $6
WHERE id = $1
RETURNING *;

-- name: AdoptHumanPrincipal :one
-- SCIM takes over the principal of a person who signed in before SCIM
-- provisioned them: SCIM's issuer and userName, and the attributes it sends.
UPDATE whitetower.principals
SET issuer = $2,
    subject = $3,
    display_name = $4,
    email = $5,
    updated_at = $6,
    version = version + 1
WHERE id = $1
RETURNING *;

-- name: GetPrincipalByID :one
SELECT * FROM whitetower.principals
WHERE id = $1;

-- name: GetHumanPrincipalByIdentity :one
SELECT * FROM whitetower.principals
WHERE issuer = $1 AND subject = $2 AND kind = 'human';

-- name: GetPrincipalBySCIMUserName :one
-- The principal that SCIM provisioned, or adopted, with the userName: SCIM's
-- issuer, and the userName as subject, compared without regard to case
-- (RFC 7643, section 4.1.1), as the unique index principals_scim_user_name
-- compares it.
SELECT * FROM whitetower.principals
WHERE kind = 'human' AND issuer = 'scim' AND lower(subject) = lower(sqlc.arg(user_name));

-- name: UpdatePrincipalStatus :exec
UPDATE whitetower.principals
SET status = $2,
    status_changed_at = $3,
    status_reason = $4,
    updated_at = $3,
    version = version + 1
WHERE id = $1;

-- name: CreateSession :exec
INSERT INTO whitetower.sessions (
    id_hash, principal_id, method, roles, csrf_token_hash,
    created_at, last_seen_at, idle_expires_at, absolute_expires_at,
    sign_in_configuration_sha256
) VALUES (
    $1, $2, $3, $4, $5, $6, $6, $7, $8, $9
);

-- name: GetSessionByHash :one
SELECT * FROM whitetower.sessions
WHERE id_hash = $1;

-- name: TouchSession :exec
UPDATE whitetower.sessions
SET last_seen_at = $2,
    idle_expires_at = $3
WHERE id_hash = $1 AND revoked_at IS NULL;

-- name: RevokeSession :exec
UPDATE whitetower.sessions
SET revoked_at = $2
WHERE id_hash = $1 AND revoked_at IS NULL;

-- name: RevokeActiveSession :one
-- Revokes the session only while it is neither revoked nor expired, and
-- returns whose it was: no row when nothing was revoked. A session of another
-- sign-in configuration, which SessionStore.Get refuses, counts: a replica
-- that still runs that configuration, or a return to it, would accept the
-- session.
UPDATE whitetower.sessions
SET revoked_at = $2
WHERE id_hash = $1 AND revoked_at IS NULL
  AND idle_expires_at >= $2 AND absolute_expires_at >= $2
RETURNING principal_id, method;

-- name: RevokeSessionsForPrincipal :exec
UPDATE whitetower.sessions
SET revoked_at = $2
WHERE principal_id = $1 AND revoked_at IS NULL;

-- name: DeleteExpiredSessions :execrows
DELETE FROM whitetower.sessions
WHERE absolute_expires_at < $1
   OR idle_expires_at < $1
   OR (revoked_at IS NOT NULL AND revoked_at < $2);

-- name: ListActiveRoleBindings :many
SELECT role FROM whitetower.role_bindings
WHERE principal_id = $1 AND revoked_at IS NULL;

-- name: CreateAPIToken :exec
INSERT INTO whitetower.api_tokens (
    id, principal_id, name, token_prefix, token_hash, scopes, created_by, created_at, expires_at,
    sign_in_configuration_sha256
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
);

-- name: GetAPITokenByHash :one
SELECT * FROM whitetower.api_tokens
WHERE token_hash = $1;

-- name: GetAPITokenByID :one
SELECT * FROM whitetower.api_tokens
WHERE id = $1;

-- name: TouchAPITokenLastUsed :exec
UPDATE whitetower.api_tokens
SET last_used_at = $2
WHERE id = $1;

-- name: RevokeAPIToken :execrows
UPDATE whitetower.api_tokens
SET revoked_at = $2
WHERE id = $1 AND revoked_at IS NULL;

-- name: RevokeAPITokensForPrincipal :execrows
UPDATE whitetower.api_tokens
SET revoked_at = $2
WHERE principal_id = $1 AND revoked_at IS NULL;

-- name: LockSessionsAndAPITokens :exec
-- Locks the sessions and the API tokens until the transaction ends against
-- every insert, update and delete, on every replica, and against another
-- transaction that takes this lock: a sign-in or an exchange that has written
-- its session or token commits before the lock is granted, and one that has
-- not waits until the transaction ends. Reads go on.
LOCK TABLE whitetower.sessions, whitetower.api_tokens IN SHARE ROW EXCLUSIVE MODE;

-- name: RevokeAllActiveSessions :execrows
-- Revokes every session that is neither revoked nor expired, but the one whose
-- hash is keep, when it is set.
UPDATE whitetower.sessions
SET revoked_at = sqlc.arg(revoked_at)
WHERE revoked_at IS NULL
  AND idle_expires_at >= sqlc.arg(revoked_at) AND absolute_expires_at >= sqlc.arg(revoked_at)
  AND id_hash IS DISTINCT FROM sqlc.narg(keep);

-- name: RevokeAllActiveAPITokens :execrows
-- Revokes every API token that is neither revoked nor expired.
UPDATE whitetower.api_tokens
SET revoked_at = sqlc.arg(revoked_at)
WHERE revoked_at IS NULL AND expires_at >= sqlc.arg(revoked_at);

-- name: ListAPITokensByPrincipal :many
SELECT * FROM whitetower.api_tokens
WHERE principal_id = $1
ORDER BY created_at DESC;

-- name: CreateServiceAccountPrincipal :one
INSERT INTO whitetower.principals (
    id, kind, display_name, email, status, responsible_principal_id, created_at, updated_at
) VALUES (
    $1, 'service_account', $2, $3, 'active', $4, $5, $5
)
RETURNING *;

-- name: ListServiceAccountsByResponsiblePrincipal :many
SELECT * FROM whitetower.principals
WHERE kind = 'service_account' AND responsible_principal_id = $1
ORDER BY created_at DESC;

-- name: ListAllServiceAccounts :many
SELECT * FROM whitetower.principals
WHERE kind = 'service_account'
ORDER BY created_at DESC;

-- name: AddRoleBinding :exec
INSERT INTO whitetower.role_bindings (
    id, principal_id, role, reason, granted_by, granted_at
) VALUES (
    $1, $2, $3, $4, $5, $6
);

-- name: GetHumanPrincipalByEmail :one
SELECT * FROM whitetower.principals
WHERE kind = 'human' AND email = $1;

-- name: GetPerson :one
-- People: human principals other than those that White Tower acts as, such
-- as the break-glass custodian.
SELECT * FROM whitetower.principals
WHERE id = $1 AND kind = 'human' AND id <> ALL(sqlc.arg(system_ids)::uuid[]);

-- name: ListPeople :many
SELECT * FROM whitetower.principals
WHERE kind = 'human' AND id <> ALL(sqlc.arg(system_ids)::uuid[])
ORDER BY created_at DESC, id DESC
LIMIT $1 OFFSET $2;

-- name: CountPeople :one
SELECT COUNT(*) FROM whitetower.principals
WHERE kind = 'human' AND id <> ALL(sqlc.arg(system_ids)::uuid[]);

