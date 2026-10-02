-- The roles of a deployment, created as an operator would, when the
-- development database starts for the first time (an empty volume). Every
-- password here is for local development only.
--
-- whitetower_migrator owns the schema; whitetower migrate connects as it.
-- whitetower_app is the server's login role. It belongs to whitetower_runtime,
-- which gets only the privileges the migrations grant (threat model, DC-3).
CREATE ROLE whitetower_migrator LOGIN PASSWORD 'whitetower-migrator-dev-only';
CREATE ROLE whitetower_runtime NOLOGIN;
CREATE ROLE whitetower_app LOGIN PASSWORD 'whitetower-app-dev-only' IN ROLE whitetower_runtime;

-- Owning the database lets the migration role create goose's version table.
ALTER DATABASE whitetower OWNER TO whitetower_migrator;
