CREATE SCHEMA irma;

CREATE TABLE IF NOT EXISTS irma.users
(
    id serial PRIMARY KEY,
    username text NOT NULL,
    language text NOT NULL,
    coredata bytea NOT NULL,
    lastSeen bigint NOT NULL,
    pinCounter int NOT NULL,
    pinBlockDate bigint NOT NULL
);
CREATE UNIQUE INDEX username_index ON irma.users (username);

CREATE TABLE IF NOT EXISTS irma.log_entry_records
(
    id serial PRIMARY KEY,
    time bigint NOT NULL,
    event text NOT NULL,
    param text,
    user_id int NOT NULL REFERENCES irma.users (id) ON DELETE CASCADE
);
CREATE INDEX log_entry_records_user_id_index ON irma.log_entry_records (user_id, time);

CREATE TABLE IF NOT EXISTS irma.email_verification_tokens
(
    id serial PRIMARY KEY,
    token text NOT NULL,
    email text NOT NULL,
    user_id int NOT NULL REFERENCES irma.users (id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX email_verification_token_index ON irma.email_verification_tokens (token);

CREATE TABLE IF NOT EXISTS irma.email_login_tokens
(
    id serial PRIMARY KEY,
    token text NOT NULL,
    email text NOT NULL
);
CREATE UNIQUE INDEX email_login_token_index ON irma.email_login_tokens (token);

CREATE TABLE IF NOT EXISTS irma.email_addresses
(
    id serial PRIMARY KEY,
    user_id int NOT NULL REFERENCES irma.users (id) ON DELETE CASCADE,
    emailAddress text NOT NULL
);
CREATE INDEX emailAddress_index ON irma.email_addresses (emailAddress);
CREATE INDEX emailAddress_userid_index ON irma.email_addresses (user_id);
CREATE UNIQUE INDEX emailAddress_constraint_index ON irma.email_addresses (user_id, emailAddress);
