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
