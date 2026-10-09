-- name: JobLastStarted :one
-- When the job last started, on any replica.
SELECT last_started_at FROM whitetower.job_state WHERE name = sqlc.arg(name);

-- name: RecordJobStarted :exec
-- Records that a run of the job started, and on which replica.
INSERT INTO whitetower.job_state (name, last_started_at, runner)
VALUES (sqlc.arg(name), sqlc.arg(started_at), sqlc.arg(runner))
ON CONFLICT (name) DO UPDATE SET last_started_at = excluded.last_started_at, runner = excluded.runner;

-- name: RecordJobFinished :exec
-- Records how the job's last run ended; last_error is null after a success.
UPDATE whitetower.job_state
SET last_finished_at = sqlc.arg(finished_at), last_status = sqlc.arg(status), last_error = sqlc.narg(last_error)
WHERE name = sqlc.arg(name);
