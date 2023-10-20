
-- i would expect:
--   CREATE UNIQUE INDEX idx_blocklists_user_did_blocked_did ON blocklist(user_did, blocked_did);
-- should be the ONLY index you need for blocklists

CREATE INDEX idx_blocked_did ON blocklists(blocked_did);
CREATE INDEX idx_blocked_did_distinct ON blocklists(blocked_did);
CREATE INDEX idx_user_did_distinct ON blocklists(user_did);
-- i don't believe field order matters, so these are the same
CREATE INDEX idx_user_did_blocked_did_combined ON blocklists(user_did, blocked_did);
CREATE INDEX idx_blocked_did_user_did_combined ON blocklists(blocked_did, user_did);

-- this query is good for looking up DID and status at the same time.
-- do you recall what you were trying to achieve here?
CREATE INDEX idx_users_did_status ON users (did, status);

-- this is extraneous because did is already the primary key
CREATE INDEX users_did_index ON users (did);
