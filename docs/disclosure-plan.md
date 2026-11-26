# The disclosure plan

How irmago describes a disclosure (or signature) request to the app, and how the
app answers it. The types are in `common/clientmodels` (`session.go`,
`interaction.go`, `types.go`); the JSON tags are the wire format.

## Model

```
DisclosurePlan
  choices[]                one per IRMA discon / DCQL credential set / DCQL query without sets
    optional               may be answered with nothing
    options[]              one per non-empty IRMA con / entry of a set's `options`
      slots[]              all shared together
        id                 DCQL: the query id. IRMA: "{discon index}:{credential type id}"
        multiple           DCQL `multiple`: one or more cards; always false for IRMA
        candidates[]       SelectableCredentialInstance: the cards that fit, best first
        obtainable[]       CredentialDescriptor: what can be added for this slot
  issued_credential_ids    types issued since the request was first shown
  wrong_credential_issued  a card added for the request that does not satisfy it
```

`choices`, `options`, `slots`, `candidates` and `obtainable` are never `null`.

### Choices, options and slots

**IRMA.** One choice per discon, optional when the discon holds an empty con (the
empty con is not an option). One option per non-empty con. One slot per credential
type of the con, in order of first appearance. The same type in two discons is two
slots with different ids, which may be answered with different cards. Because
`AttributeConDisCon.Validate` allows at most one non-singleton type per con, at
most one slot of an option has more than one candidate.

**DCQL.** Without `credential_sets`, one required choice per query, with one option
of one slot. With them, one choice per set (optional when `required` is false), one
option per entry of `options`, and one slot per query id in that entry. Queries no
set names are not part of the plan. A query named in several options or sets is the
same slot each time: it has one presentation, so it takes one selection.

### Candidates

A candidate is a card in the wallet that fits the slot, with only the attributes it
would share:

- IRMA: the attributes the con asks of that type, in schema order. A con entry that
  names only the credential gives a candidate without attributes.
- DCQL: what the format handler would present. With `claim_sets`, the claims of the
  first set that card satisfies, so two candidates of one slot may carry different
  attributes. A query without `claims` gives the claims that are always disclosed
  (SD-JWT VC) or none (IRMA over SD-JWT); mso_mdoc refuses such a query.

A card whose value is not one of the allowed values is not a candidate. A card that
fits but cannot be used now is a candidate with `usable: false` and an
`unusable_reason`:

| Reason | When |
|---|---|
| `revoked` | the issuer revoked it (IRMA: always unusable; DCQL: per its status list) |
| `expired` | past its expiry, unless the IRMA request has `skipExpiryCheck` for the type |
| `used_up` | a batch with no instance left |
| `not_revocable` | IRMA: the request asks a non-revocation proof and the card has no revocation support |

Candidates are sorted by `clientmodels.SortCandidates`: usable first, then most uses
left (unlimited first), latest expiry (none first), latest issuance (unknown last),
and hash.

Each attribute carries `requested_value` and `requested_values`: every value the
request allows, in request order (DCQL `values`, keeping their type; IRMA: the one
required value).

### Obtainable

While a slot has no usable candidate, it offers every descriptor of its type,
including one without an issue URL, which tells the user what is asked when nothing
can be added. Next to a usable card it only offers a type that can be added beside
it: one with an issue URL that is not a singleton. IRMA descriptors list only the
attributes the con asks of the type; mso_mdoc descriptors carry `intent_to_retain`.

### Issued and wrong cards

When a card is issued while the request waits, irmago builds the plan again and
sends it. `issued_credential_ids` holds the type of every usable candidate whose card
was not in the wallet when the request arrived, and keeps what earlier plans
recorded. `wrong_credential_issued` is a card added during the request, of a type a
required choice that cannot be answered yet offers, whose values are not the ones
asked; it holds only the attributes that do not match, each with what was asked.

## The answer

`SessionPermissionInteractionPayload`:

```
granted
choices[]                one per plan choice, same order
  option                 index into the choice's options; -1 shares nothing (optional choices only)
  slots[]                one per slot of that option, same order
    slot_id
    credentials[]        SelectedCredential: one, or one or more when the slot is multiple
```

`clientmodels.ValidateAnswer` checks a granted answer against the plan last sent:
the counts and order above, that every card is a usable candidate of its slot, that
a slot id chosen in two choices carries the same cards (unless it is `multiple`),
and that a card used in several slots has a use left for each. A refused answer
ends the session with an error.

- **DCQL:** one selection per card per slot, with the slot id as query id; a slot
  named in two choices is presented once. `PrepareDisclosure` refuses a second
  presentation for a query that is not `multiple`.
- **IRMA:** for the chosen option, the attributes of the matching con, in the con's
  order, each from the card chosen for its type's slot.

## Chained IRMA sessions

When the requestor chains a follow-up (`nextSession`), the first session is sent,
logged and closed, and its state ends as `success` with `next_session_pending:
true`. The follow-up starts on the `continue_next_session` interaction, on the same
session id, with the first session's attributes disclosed implicitly. Dismissing
instead drops the follow-up; the session stays `success`. A handler that does not
implement `irmaclient.NextSessionHandler` sees the follow-up start right away.
