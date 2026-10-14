-- Queries of the human authentication and session domain (plan P1-03).

-- name: UpsertHumanPrincipal :one
INSERT INTO whitetower.principals (
    id, kind, issuer, subject, display_name, email, status, idp_groups, last_login_at, created_at, updated_at
) VALUES (
    $1, 'human', $2, $3, $4, $5, 'active', $6, $7, $7, $7
)
ON CONFLICT (issuer, subject) WHERE kind = 'human'
DO UPDATE SET
    display_name = EXCLUDED.display_name,
    email = EXCLUDED.email,
    idp_groups = EXCLUDED.idp_groups,
    last_login_at = EXCLUDED.last_login_at,
    updated_at = EXCLUDED.last_login_at
RETURNING *;

-- name: GetPrincipalByID :one
SELECT * FROM whitetower.principals
WHERE id = $1;

-- name: GetHumanPrincipalByIdentity :one
SELECT * FROM whitetower.principals
WHERE issuer = $1 AND subject = $2 AND kind = 'human';

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
    created_at, last_seen_at, idle_expires_at, absolute_expires_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $6, $7, $8
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
