-- The messages a read-only intake has finished with. A source that may not
-- flag or move mail (read-only IMAP, JMAP with a read-only token) keeps its
-- progress here: source names the account and mailbox, message_key the
-- message within it.
CREATE TABLE processed_messages (
	source TEXT NOT NULL,
	message_key TEXT NOT NULL,
	outcome TEXT NOT NULL,
	message_id TEXT,
	processed_at INTEGER NOT NULL,
	PRIMARY KEY (source, message_key)
);

CREATE INDEX idx_processed_messages_processed_at ON processed_messages(processed_at);
