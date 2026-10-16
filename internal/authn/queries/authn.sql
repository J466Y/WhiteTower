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

-- name: CreateAPIToken :exec
INSERT INTO whitetower.api_tokens (
    id, principal_id, name, token_prefix, token_hash, scopes, created_by, created_at, expires_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
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

-- name: GetHumanPrincipalBySubjectOrEmail :one
SELECT * FROM whitetower.principals
WHERE kind = 'human' AND (subject = $1 OR email = $1)
LIMIT 1;

-- name: ListHumanPrincipals :many
SELECT * FROM whitetower.principals
WHERE kind = 'human'
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountHumanPrincipals :one
SELECT COUNT(*) FROM whitetower.principals
WHERE kind = 'human';

