-- +goose Up
-- The catalog of MCP servers, tools and models (plan P1-16, pull request 1b;
-- RFC-0002, section 3; domain model, section 3.9).
--
-- Enforcement points report what agents have, and people review it. A report
-- only adds discovered entries and records the definitions and digests it
-- brings: the inserts of a report name no status, so a report never approves
-- anything, and never changes a pinned definition or digest (CORE-10).
-- Reported text is untrusted: its sizes are bounded as a report's are
-- (RFC-0002, section 4.2), and no audit event carries a reference, which
-- events name by its SHA-256 only. Approving and declining add their columns
-- in pull request 1c.

-- MCP servers. A key is a slug of the server's host or of the name it
-- announces, never of a command line, whose paths can hold a user name:
-- events carry keys in clear. agent is reserved for the agent's own tools.
CREATE TABLE whitetower.catalog_servers (
  id                uuid PRIMARY KEY,
  key               text NOT NULL UNIQUE
                    CHECK (key ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$' AND key <> 'agent'),
  reference         text NOT NULL UNIQUE CHECK (octet_length(reference) BETWEEN 1 AND 2048),
  transport         text NOT NULL CHECK (transport IN ('stdio', 'http')),
  announced_name    text CHECK (octet_length(announced_name) BETWEEN 1 AND 256),
  announced_version text CHECK (octet_length(announced_version) BETWEEN 1 AND 128),
  display_form      text CHECK (octet_length(display_form) BETWEEN 1 AND 2048),
  status            text NOT NULL DEFAULT 'discovered' CHECK (status IN ('discovered', 'approved')),
  flags             text[] NOT NULL DEFAULT '{}'
                    CHECK (flags <@ ARRAY['unpinned_package', 'secret_in_path']::text[]),
  first_agent_id    uuid NOT NULL REFERENCES whitetower.agents (id),
  first_seen_at     timestamptz NOT NULL,
  last_seen_at      timestamptz NOT NULL,
  version           bigint NOT NULL DEFAULT 1
);

-- Tool definitions, stored as the bytes of their canonical JSON, never
-- encoded again, under the SHA-256 of those bytes: every stored hash can be
-- recomputed, and the database checks that it is.
CREATE TABLE whitetower.catalog_tool_definitions (
  definition_sha256 bytea PRIMARY KEY CHECK (octet_length(definition_sha256) = 32),
  canonical         bytea NOT NULL CHECK (octet_length(canonical) BETWEEN 2 AND 1048576),
  stored_at         timestamptz NOT NULL,
  CONSTRAINT catalog_tool_definitions_hash CHECK (definition_sha256 = sha256(canonical))
);

-- Tools. An MCP tool belongs to its server, the agent's own tool (kinds
-- function, http and other) to its agent, and a built-in tool to its provider
-- and type; each kind's key is made of them. A provider's / and % are
-- escaped in a built-in tool's key, so that no two keys are alike.
CREATE TABLE whitetower.catalog_tools (
  id                uuid PRIMARY KEY,
  key               text NOT NULL,
  kind              text NOT NULL CHECK (kind IN ('function', 'mcp', 'builtin', 'http', 'other')),
  name              text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 256),
  server_id         uuid REFERENCES whitetower.catalog_servers (id),
  agent_id          uuid REFERENCES whitetower.agents (id),
  provider          text CHECK (octet_length(provider) BETWEEN 1 AND 128),
  type              text CHECK (octet_length(type) BETWEEN 1 AND 128),
  status            text NOT NULL DEFAULT 'discovered' CHECK (status IN ('discovered', 'approved')),
  -- The pinned definition, which only an approval sets.
  definition_sha256 bytea REFERENCES whitetower.catalog_tool_definitions (definition_sha256),
  first_agent_id    uuid NOT NULL REFERENCES whitetower.agents (id),
  first_seen_at     timestamptz NOT NULL,
  last_seen_at      timestamptz NOT NULL,
  version           bigint NOT NULL DEFAULT 1,
  CONSTRAINT catalog_tools_kind CHECK (
       (kind = 'mcp' AND server_id IS NOT NULL AND agent_id IS NULL AND provider IS NULL AND type IS NULL
        AND key ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?/' AND substr(key, strpos(key, '/') + 1) = name)
    OR (kind = 'builtin' AND server_id IS NULL AND agent_id IS NULL AND provider IS NOT NULL AND type IS NOT NULL
        AND key = 'provider.' || replace(replace(provider, '%', '%25'), '/', '%2F') || '/' || type)
    OR (kind IN ('function', 'http', 'other') AND server_id IS NULL AND agent_id IS NOT NULL
        AND provider IS NULL AND type IS NULL AND key = 'agent/' || name)),
  -- An approved tool pins a stored definition, except a built-in tool, which
  -- has none; a discovered tool pins nothing.
  CONSTRAINT catalog_tools_pin CHECK ((definition_sha256 IS NOT NULL) = (status = 'approved' AND kind <> 'builtin'))
);
CREATE UNIQUE INDEX catalog_tools_of_server ON whitetower.catalog_tools (server_id, name) WHERE server_id IS NOT NULL;
CREATE UNIQUE INDEX catalog_tools_of_agent ON whitetower.catalog_tools (agent_id, name) WHERE agent_id IS NOT NULL;
CREATE UNIQUE INDEX catalog_tools_builtin ON whitetower.catalog_tools (provider, type) WHERE kind = 'builtin';
-- Keys are unique in the catalog, except those of the agent's own tools,
-- which are unique within their agent: the same name in two agents is
-- different code.
CREATE UNIQUE INDEX catalog_tools_key ON whitetower.catalog_tools (key) WHERE agent_id IS NULL;
CREATE INDEX catalog_tools_by_key ON whitetower.catalog_tools (key, id);

-- The definitions that reports brought for each tool. One that differs from
-- the tool's pinned definition waits for review, while the pinned one stays
-- (RFC-0002, section 7.1).
CREATE TABLE whitetower.catalog_reported_definitions (
  tool_id           uuid NOT NULL REFERENCES whitetower.catalog_tools (id),
  definition_sha256 bytea NOT NULL CHECK (octet_length(definition_sha256) = 32),
  first_agent_id    uuid NOT NULL REFERENCES whitetower.agents (id),
  first_seen_at     timestamptz NOT NULL,
  PRIMARY KEY (tool_id, definition_sha256)
);

-- Models. A key is a slug of the provider, for an endpoint that the core
-- knows as the provider's default, or of the endpoint's host, a slash, and a
-- slug of the name, which keeps its dots.
CREATE TABLE whitetower.catalog_models (
  id             uuid PRIMARY KEY,
  key            text NOT NULL UNIQUE
                 CHECK (key ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?/[a-z0-9]([a-z0-9.-]{0,126}[a-z0-9])?$'),
  provider       text NOT NULL CHECK (octet_length(provider) BETWEEN 1 AND 128),
  endpoint       text NOT NULL CHECK (octet_length(endpoint) BETWEEN 1 AND 2048),
  name           text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 256),
  status         text NOT NULL DEFAULT 'discovered' CHECK (status IN ('discovered', 'approved')),
  -- The pinned digest of the weights, which only an approval sets.
  digest         text CHECK (octet_length(digest) BETWEEN 1 AND 128),
  flags          text[] NOT NULL DEFAULT '{}' CHECK (flags <@ ARRAY['secret_in_path']::text[]),
  first_agent_id uuid NOT NULL REFERENCES whitetower.agents (id),
  first_seen_at  timestamptz NOT NULL,
  last_seen_at   timestamptz NOT NULL,
  version        bigint NOT NULL DEFAULT 1,
  UNIQUE (provider, endpoint, name),
  CONSTRAINT catalog_models_pin CHECK (status = 'approved' OR digest IS NULL)
);

-- The digests that runtimes reported for each model. One that differs from
-- the model's pinned digest waits for review, while the pinned one stays.
CREATE TABLE whitetower.catalog_reported_digests (
  model_id       uuid NOT NULL REFERENCES whitetower.catalog_models (id),
  digest         text NOT NULL CHECK (octet_length(digest) BETWEEN 1 AND 128),
  first_agent_id uuid NOT NULL REFERENCES whitetower.agents (id),
  first_seen_at  timestamptz NOT NULL,
  PRIMARY KEY (model_id, digest)
);

-- A key never changes once its entry is approved: policies name entries by
-- their keys.
-- +goose StatementBegin
CREATE FUNCTION whitetower.keep_approved_catalog_key() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status = 'approved' AND NEW.key IS DISTINCT FROM OLD.key THEN
    RAISE EXCEPTION 'whitetower: the key of approved entry % of %.% never changes', OLD.id, TG_TABLE_SCHEMA, TG_TABLE_NAME
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER catalog_servers_keep_approved_key BEFORE UPDATE ON whitetower.catalog_servers
  FOR EACH ROW EXECUTE FUNCTION whitetower.keep_approved_catalog_key();
CREATE TRIGGER catalog_tools_keep_approved_key BEFORE UPDATE ON whitetower.catalog_tools
  FOR EACH ROW EXECUTE FUNCTION whitetower.keep_approved_catalog_key();
CREATE TRIGGER catalog_models_keep_approved_key BEFORE UPDATE ON whitetower.catalog_models
  FOR EACH ROW EXECUTE FUNCTION whitetower.keep_approved_catalog_key();

-- Stored definitions are append-only: their content and hash never change.
CREATE TRIGGER catalog_tool_definitions_append_only BEFORE UPDATE OR DELETE ON whitetower.catalog_tool_definitions
  FOR EACH ROW EXECUTE FUNCTION whitetower.reject_change();
CREATE TRIGGER catalog_tool_definitions_no_truncate BEFORE TRUNCATE ON whitetower.catalog_tool_definitions
  FOR EACH STATEMENT EXECUTE FUNCTION whitetower.reject_change();

-- Privileges of the runtime role, table by table.
GRANT SELECT, INSERT, UPDATE ON
  whitetower.catalog_servers, whitetower.catalog_tools, whitetower.catalog_models,
  whitetower.catalog_reported_definitions, whitetower.catalog_reported_digests
  TO whitetower_runtime;
GRANT SELECT, INSERT ON whitetower.catalog_tool_definitions TO whitetower_runtime;
