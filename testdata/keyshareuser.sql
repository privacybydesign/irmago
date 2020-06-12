DELETE from irma.users
WHERE username = 'test_username';

INSERT INTO irma.users (username, language, coredata, last_seen, pin_counter, pin_block_date)
VALUES (
    'test_username',
    'en',
    decode('YWJjZK4w5SC+7D4lDrhiJGvB1iwxSeF90dGGPoGqqG7g3ivbfHibOdkKoOTZPbFlttBzn2EJgaEsL24Re8OWWWw5pd31/GCd14RXcb9Wy2oWhbr0pvJDLpIxXZt/qiQC0nJiIAYWLGZOdj5o0irDfqP1CSfw3IoKkVEl4lHRj0LCeINJIOpEfGlFtl4DHlWu8SMQFV1AIm3Gv64XzGncdkclVd41ti7cicBrcK8N2u9WvY/jCS4/Lxa2syp/O4IY', 'base64'),
    1591951755,
    0,
    0
);

INSERT INTO irma.log_entry_records (time, event, user_id)
VALUES (
    1591951800,
    'PIN_CHECK_SUCCESS',
    (SELECT id FROM irma.users WHERE username = 'test_username')
);

INSERT INTO irma.email_verification_tokens (token, email, expiry, user_id)
VALUES (
    'test_token',
    'test@example.com',
    1700000000,
    (SELECT id FROM irma.users WHERE username = 'test_username')
);

INSERT INTO irma.emails (user_id, email)
VALUES (
    (SELECT id FROM irma.users WHERE username = 'test_username'),
    'test@example.com'
);
