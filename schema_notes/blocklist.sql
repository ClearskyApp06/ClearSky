
CREATE TABLE IF NOT EXISTS blocklist (
    user_did text,
    blocked_did text,
    -- block_date should really be: timestamp without time zone,
    block_date text,
);

-- this prevents duplicate blocking entries
CREATE UNIQUE INDEX IF NOT EXISTS
    blocklist_user_did_blocked_did_idx
    ON blocklist (user_did, blocked_did)
;

-- get a user's blocks
CREATE INDEX IF NOT EXISTS
    blocklist_user_did
    ON blocklist (user_did)
;

-- get blockers for a given user
CREATE INDEX IF NOT EXISTS
    blocklist_blocked_did
    ON blocklist (blocked_did)
;
