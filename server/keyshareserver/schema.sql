CREATE TABLE IF NOT EXISTS irma.users
(
    id serial PRIMARY KEY,
    username varchar(128),
    coredata bytea,
    lastSeen bigint,
    pinCounter int,
    pinBlockDate bigint
);
CREATE UNIQUE INDEX username_index ON irma.users (username);
GRANT ALL PRIVILEGES ON TABLE irma.users TO irma;

CREATE TABLE IF NOT EXISTS irma.log_entry_records
(
    id serial PRIMARY KEY,
    time bigint,
    event varchar(256),
    param text,
    user_id int
);
CREATE INDEX log_entry_records_user_id_index ON irma.log_entry_records (user_id);
GRANT ALL PRIVILEGES ON TABLE irma.log_entry_records TO irma;