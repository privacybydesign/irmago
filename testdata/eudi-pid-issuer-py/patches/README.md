# Patches to the EUDI reference PID issuer

Files here are modified copies of files from the
[EU reference PID issuer](https://github.com/eu-digital-identity-wallet/eudi-srv-web-issuing-eudiw-py)
image, bind-mounted over the container's own at run time. `docker-compose.yml`
mounts each one read-only; nothing here is imported by Go code.

Editing a file here needs the container recreated before it takes effect:

```
docker compose up -d --force-recreate eudi_pid_issuer_py
```

## `dynamic_func.py`

Replaces `app/dynamic_func.py`, to lift one restriction on which age thresholds
can be minted.

Upstream, `populate_pdata` builds the credential from the claims declared in the
issuer's own credential configuration and copies a value out of the offer only
where one is named (`if attr in data`). An element the offer asks for and the
configuration does not declare is therefore dropped before the MSO is signed:
the request still returns HTTP 200, issuance still succeeds, and the element is
simply absent, with no error at either end.

The patch lifts that for the age-verification namespace, because ISO/IEC 18013-5
and the EU AV profile both leave the set of `age_over_NN` thresholds open, so a
test needs to mint one the configuration does not list. Any *other* undeclared
element is still dropped the upstream way.

What is *advertised* is a separate question, decided by
`../metadata/age_verification_mdoc.json` (also bind-mounted). It deliberately
stays at the upstream thirteen: the wallet renders one row per advertised claim
on the issuance offer screen, so a long list makes that screen unusable. A
threshold minted without being advertised carries no published label and is
named "Age Over NN" by the wallet's own derived name.
