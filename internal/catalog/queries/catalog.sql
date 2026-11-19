-- What tooling reports bring --------------------------------------------------

-- name: ServersByReference :many
SELECT id, key, reference FROM whitetower.catalog_servers WHERE reference = ANY(sqlc.arg(refs)::text[]);

-- name: ServerKeysFrom :many
-- The servers' keys that start with a prefix, which holds no wildcard of
-- LIKE: a slug's letters, digits and hyphens.
SELECT key FROM whitetower.catalog_servers WHERE key LIKE sqlc.arg(prefix)::text || '%';

-- name: InsertServer :execrows
-- A discovered server, unless the catalog has its reference or its key
-- already. It names no status: a report never approves anything.
INSERT INTO whitetower.catalog_servers (
  id, key, reference, transport, announced_name, announced_version, display_form, flags,
  first_agent_id, first_seen_at, last_seen_at
) VALUES (
  sqlc.arg(id), sqlc.arg(key), sqlc.arg(reference), sqlc.arg(transport), sqlc.narg(announced_name),
  sqlc.narg(announced_version), sqlc.narg(display_form), sqlc.arg(flags), sqlc.arg(first_agent_id),
  sqlc.arg(seen_at), sqlc.arg(seen_at)
) ON CONFLICT DO NOTHING;

-- name: SeeServers :exec
-- Moves the servers' last seen time, kept to the minute so that the servers
-- that many agents report are not written on every report.
UPDATE whitetower.catalog_servers SET last_seen_at = sqlc.arg(seen_at)
WHERE id = ANY(sqlc.arg(ids)::uuid[]) AND last_seen_at < sqlc.arg(stale_before);

-- name: ReportedTools :many
-- The tools that a report may name: those of its servers, the agent's own
-- and the built-in ones, by name, provider and type. The caller keeps those
-- it names.
SELECT id, key, kind, name, server_id, agent_id, provider, type, status, definition_sha256
FROM whitetower.catalog_tools
WHERE (server_id = ANY(sqlc.arg(server_ids)::uuid[]) AND name = ANY(sqlc.arg(server_tool_names)::text[]))
   OR (agent_id = sqlc.arg(agent_id) AND name = ANY(sqlc.arg(agent_tool_names)::text[]))
   OR (kind = 'builtin' AND provider = ANY(sqlc.arg(providers)::text[]) AND type = ANY(sqlc.arg(types)::text[]));

-- name: InsertTool :execrows
-- A discovered tool, unless the catalog has it or its key already. It names
-- no status and pins no definition.
INSERT INTO whitetower.catalog_tools (
  id, key, kind, name, server_id, agent_id, provider, type, first_agent_id, first_seen_at, last_seen_at
) VALUES (
  sqlc.arg(id), sqlc.arg(key), sqlc.arg(kind), sqlc.arg(name), sqlc.narg(server_id), sqlc.narg(agent_id),
  sqlc.narg(provider), sqlc.narg(type), sqlc.arg(first_agent_id), sqlc.arg(seen_at), sqlc.arg(seen_at)
) ON CONFLICT DO NOTHING;

-- name: SeeTools :exec
UPDATE whitetower.catalog_tools SET last_seen_at = sqlc.arg(seen_at)
WHERE id = ANY(sqlc.arg(ids)::uuid[]) AND last_seen_at < sqlc.arg(stale_before);

-- name: RecordReportedDefinitions :many
-- Records the definitions that a report names for its tools, and returns
-- those that the catalog did not have for their tool.
INSERT INTO whitetower.catalog_reported_definitions (tool_id, definition_sha256, first_agent_id, first_seen_at)
SELECT unnest(sqlc.arg(tool_ids)::uuid[]), unnest(sqlc.arg(hashes)::bytea[]), sqlc.arg(first_agent_id)::uuid,
  sqlc.arg(seen_at)::timestamptz
ON CONFLICT DO NOTHING
RETURNING tool_id, definition_sha256;

-- name: ReportedModels :many
-- The models with these endpoints and names. The caller keeps those whose
-- provider, endpoint and name a report names together.
SELECT id, key, provider, endpoint, name, status, digest
FROM whitetower.catalog_models
WHERE endpoint = ANY(sqlc.arg(endpoints)::text[]) AND name = ANY(sqlc.arg(names)::text[]);

-- name: ModelKeysFrom :many
-- The models' keys that start with a prefix, which holds no wildcard of
-- LIKE: letters, digits, hyphens, dots and one slash.
SELECT key FROM whitetower.catalog_models WHERE key LIKE sqlc.arg(prefix)::text || '%';

-- name: InsertModel :execrows
-- A discovered model, unless the catalog has it or its key already. It names
-- no status and pins no digest.
INSERT INTO whitetower.catalog_models (
  id, key, provider, endpoint, name, flags, first_agent_id, first_seen_at, last_seen_at
) VALUES (
  sqlc.arg(id), sqlc.arg(key), sqlc.arg(provider), sqlc.arg(endpoint), sqlc.arg(name), sqlc.arg(flags),
  sqlc.arg(first_agent_id), sqlc.arg(seen_at), sqlc.arg(seen_at)
) ON CONFLICT DO NOTHING;

-- name: SeeModels :exec
UPDATE whitetower.catalog_models SET last_seen_at = sqlc.arg(seen_at)
WHERE id = ANY(sqlc.arg(ids)::uuid[]) AND last_seen_at < sqlc.arg(stale_before);

-- name: RecordReportedDigests :many
-- Records the digests that a report names for its models, and returns those
-- that the catalog did not have for their model.
INSERT INTO whitetower.catalog_reported_digests (model_id, digest, first_agent_id, first_seen_at)
SELECT unnest(sqlc.arg(model_ids)::uuid[]), unnest(sqlc.arg(digests)::text[]), sqlc.arg(first_agent_id)::uuid,
  sqlc.arg(seen_at)::timestamptz
ON CONFLICT DO NOTHING
RETURNING model_id, digest;

-- Reads ------------------------------------------------------------------------

-- name: ListServers :many
-- A page of servers, by key, that match every filter given; with id, the
-- server with this ID. A server waits for review while it is discovered.
SELECT id, key, reference, transport, announced_name, announced_version, display_form, status, flags,
  first_agent_id, first_seen_at, last_seen_at, version, (status = 'discovered')::boolean AS pending_review
FROM whitetower.catalog_servers
WHERE (sqlc.narg(id)::uuid IS NULL OR id = sqlc.narg(id)::uuid)
  AND (sqlc.narg(statuses)::text[] IS NULL OR status = ANY(sqlc.narg(statuses)::text[]))
  AND (sqlc.narg(pending_review)::boolean IS NULL OR (status = 'discovered') = sqlc.narg(pending_review)::boolean)
  AND flags @> sqlc.arg(flags)::text[]
  AND (sqlc.narg(key)::text IS NULL OR key = sqlc.narg(key)::text)
  AND (sqlc.narg(after)::text IS NULL OR key > sqlc.narg(after)::text)
ORDER BY key
LIMIT sqlc.arg(page_limit);

-- name: ListTools :many
-- A page of tools, by key and ID, that match every filter given; with id,
-- the tool with this ID. A tool waits for review while it is discovered, or
-- while a reported definition that differs from its pinned one does.
SELECT t.id, t.key, t.kind, t.name, t.server_id, t.agent_id, t.provider, t.type, t.status, t.definition_sha256,
  t.first_agent_id, t.first_seen_at, t.last_seen_at, t.version, p.pending_definitions::bytea[] AS pending_definitions,
  (t.status = 'discovered' OR cardinality(p.pending_definitions) > 0)::boolean AS pending_review
FROM whitetower.catalog_tools t
CROSS JOIN LATERAL (
  SELECT ARRAY(
    SELECT d.definition_sha256 FROM whitetower.catalog_reported_definitions d
    WHERE d.tool_id = t.id AND d.definition_sha256 IS DISTINCT FROM t.definition_sha256
    ORDER BY d.first_seen_at, d.definition_sha256
  ) AS pending_definitions
) p
WHERE (sqlc.narg(id)::uuid IS NULL OR t.id = sqlc.narg(id)::uuid)
  AND (sqlc.narg(statuses)::text[] IS NULL OR t.status = ANY(sqlc.narg(statuses)::text[]))
  AND (sqlc.narg(pending_review)::boolean IS NULL
    OR (t.status = 'discovered' OR cardinality(p.pending_definitions) > 0) = sqlc.narg(pending_review)::boolean)
  AND (sqlc.narg(key)::text IS NULL OR t.key = sqlc.narg(key)::text)
  AND (sqlc.narg(server_id)::uuid IS NULL OR t.server_id = sqlc.narg(server_id)::uuid)
  AND (sqlc.narg(agent_id)::uuid IS NULL OR t.agent_id = sqlc.narg(agent_id)::uuid)
  AND (sqlc.narg(kinds)::text[] IS NULL OR t.kind = ANY(sqlc.narg(kinds)::text[]))
  AND (sqlc.narg(after_key)::text IS NULL OR (t.key, t.id) > (sqlc.narg(after_key)::text, sqlc.narg(after_id)::uuid))
ORDER BY t.key, t.id
LIMIT sqlc.arg(page_limit);

-- name: ListModels :many
-- A page of models, by key, that match every filter given; with id, the
-- model with this ID. A model waits for review while it is discovered, or
-- while a reported digest that differs from its pinned one does.
SELECT m.id, m.key, m.provider, m.endpoint, m.name, m.status, m.digest, m.flags, m.first_agent_id,
  m.first_seen_at, m.last_seen_at, m.version, p.pending_digests::text[] AS pending_digests,
  (m.status = 'discovered' OR cardinality(p.pending_digests) > 0)::boolean AS pending_review
FROM whitetower.catalog_models m
CROSS JOIN LATERAL (
  SELECT ARRAY(
    SELECT d.digest FROM whitetower.catalog_reported_digests d
    WHERE d.model_id = m.id AND d.digest IS DISTINCT FROM m.digest
    ORDER BY d.first_seen_at, d.digest
  ) AS pending_digests
) p
WHERE (sqlc.narg(id)::uuid IS NULL OR m.id = sqlc.narg(id)::uuid)
  AND (sqlc.narg(statuses)::text[] IS NULL OR m.status = ANY(sqlc.narg(statuses)::text[]))
  AND (sqlc.narg(pending_review)::boolean IS NULL
    OR (m.status = 'discovered' OR cardinality(p.pending_digests) > 0) = sqlc.narg(pending_review)::boolean)
  AND m.flags @> sqlc.arg(flags)::text[]
  AND (sqlc.narg(key)::text IS NULL OR m.key = sqlc.narg(key)::text)
  AND (sqlc.narg(provider)::text IS NULL OR m.provider = sqlc.narg(provider)::text)
  AND (sqlc.narg(after)::text IS NULL OR m.key > sqlc.narg(after)::text)
ORDER BY m.key
LIMIT sqlc.arg(page_limit);

-- name: GetDefinition :one
-- A stored definition's canonical bytes, exactly as stored.
SELECT canonical FROM whitetower.catalog_tool_definitions WHERE definition_sha256 = $1;
