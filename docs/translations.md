# Translations

irmago shows text to end users in three places: IRMA schemes (issuer and
requestor schemes), SD-JWT VC / OpenID4VCI metadata coming from EUDI issuers,
and the emails sent by the keyshare and MyIRMA servers. All three resolve text
through the same fallback chain, so a wallet set to any language gets the best
available translation and never an empty string. This document describes how
that works and what has to be translated to add a language. The project
currently ships **English, Dutch, French and German**
(`clientmodels.SupportedLanguages`).

## How text is resolved

Every translatable text is a `TranslatedString`: a map from language tag to
text. The wallet supplies its UI locale (e.g. `fr-BE`), and
`clientmodels.BundleLanguage` picks a language in this order:

1. the exact locale (`fr-BE`);
2. its base language (`fr`);
3. English, the `DefaultFallbackLanguage`;
4. the raw (`""`) value, which untranslated data such as attribute values carry;
5. as a deterministic last resort, the lowest remaining key.

Fields that belong together — a credential's name and category, an attribute's
name and description — are resolved as one *text bundle* from a single
language, so a card never shows a French name above a Dutch category
(`irma.CredentialType.ResolveTexts`, `irma.AttributeType.ResolveTexts`).
Links such as issue URLs resolve independently, because a URL is not a
translation and must not vanish when the bundle settles on a language that
lacks it.

Because the chain accepts any BCP 47 tag, **no code change is needed to add a
language**: translate the data, and wallets set to that language pick it up.
`SupportedLanguages` is the list of languages a release is expected to be
complete in; it drives the coverage report below and this documentation, not a
filter.

Never index a `TranslatedString` with a literal language (`ts["en"]`). Use
`ts.Resolve(locale)` (`irma`), `clientmodels.Resolve` / `ResolvePtr`, or, for
maps of non-string values keyed by language, `clientmodels.PickLanguage`
(exact → base language; the caller supplies its own default).

## Adding a language to a scheme

A scheme declares the languages it promises to be complete in:

```xml
<SchemeManager version="7">
  ...
  <Languages>
    <Language>en</Language>
    <Language>nl</Language>
    <Language>fr</Language>
    <Language>de</Language>
  </Languages>
</SchemeManager>
```

Issuers and credential types inherit the scheme's list unless they declare
their own; requestors and issue wizards inherit from the requestor scheme.
Once a language is declared, `irma scheme verify` warns about every text that
lacks it, and demo schemes must prefix names in every declared language with
`Demo `.

To see what a language would take *before* declaring it, run the coverage
report against the languages you intend to add:

```sh
irma scheme translations --lang fr,de ./irma_configuration/pbdf
```

It walks scheme managers, issuers, credential types, attributes, requestors
and issue wizards (including FAQ and wizard items) and prints, per language,
how many texts are translated and which ones are not:

```
Translation coverage for languages: fr, de

  fr:      0/412 (0%)
  de:      0/412 (0%)

Missing translations (412):
  Scheme pbdf <Name>: fr, de
  Scheme pbdf <Description>: fr, de
  Issuer pbdf.gemeente <Name>: fr, de
  Credential type pbdf.gemeente.address <Name>: fr, de
  Attribute street of credential type pbdf.gemeente.address <Name>: fr, de
  ...
```

Without `--lang` it uses the languages the schemes declare, so it doubles as
a completeness check for a scheme that already promises a language. Add
`--summary` for the totals only.

Every translatable element takes the same shape:

```xml
<Name>
  <en>Email address</en>
  <nl>E-mailadres</nl>
  <fr>Adresse e-mail</fr>
  <de>E-Mail-Adresse</de>
</Name>
```

The elements are, per object:

| Object | Translatable elements |
| --- | --- |
| Scheme manager | `Name`, `Description` |
| Issuer | `Name` |
| Credential type | `Name`, `Description`, `IssueURL`, `Category`, `FAQIntro`, `FAQPurpose`, `FAQContent`, `FAQHowto`, `FAQSummary` |
| Attribute | `Name`, `Description` |
| Requestor (`requestors.json`) | `name`, `industry` |
| Issue wizard | `title`, `info`, `intro`, `successHeader`, `successText`, FAQ `question`/`answer`, item `text`/`label` |

Attribute *values* are not translated; they are wrapped so they resolve to the
raw value for any locale (`irma.NewTranslatedString`).

After editing a scheme, re-sign it (`irma scheme sign`). In this repository
`testdata/makeschemes.sh` re-signs the test schemes; the `test` scheme's
`email` credential type carries French and German translations as a worked
example.

## Keyshare and MyIRMA server emails

Email templates and subjects are configured per language, and the user's
language is matched by exact tag, then base language, then the configured
`default_language` — the operator's default keeps the last word here, not
English. So a French-speaking Belgian user (`fr-BE`) receives the `fr`
template without a separate `fr-BE` entry.

```json
{
  "default_language": "en",
  "verification_email_files": {
    "en": "/etc/keyshare/verification-en.html",
    "nl": "/etc/keyshare/verification-nl.html",
    "fr": "/etc/keyshare/verification-fr.html",
    "de": "/etc/keyshare/verification-de.html"
  },
  "verification_email_subjects": {
    "en": "Verify your email address",
    "nl": "Bevestig uw e-mailadres",
    "fr": "Vérifiez votre adresse e-mail",
    "de": "Bestätigen Sie Ihre E-Mail-Adresse"
  },
  "verification_url": {
    "en": "https://example.com/en/verify/",
    "nl": "https://example.com/nl/verify/",
    "fr": "https://example.com/fr/verify/",
    "de": "https://example.com/de/verify/"
  }
}
```

Only the `default_language` entry is mandatory. The same applies to the
MyIRMA server's `login_email_files`, `login_email_subjects`, `login_url`,
`delete_account_files`/`_subjects` and `delete_expired_account_files`/
`_subjects`, and to the keyshare tasks' `expiry_email_files`/`_subjects`.

## EUDI credentials

SD-JWT VC type metadata and OpenID4VCI issuer metadata carry `display` arrays
with a `locale` per entry. They are reduced to language-keyed maps and resolved
through the same chain (`eudi/services/displays.go`), so an issuer that adds a
`fr` or `de` display entry is picked up without changes here.

## Checklist for adding a language

1. Add the base language tag to `clientmodels.SupportedLanguages` (one line;
   this makes the coverage report and documentation aware of it).
2. Run `irma scheme translations --lang <tag>` on each scheme and translate
   the listed texts; then declare the language in the scheme's `<Languages>`
   so `irma scheme verify` keeps it complete.
3. Add email templates, subjects and URLs for the tag to the keyshare and
   MyIRMA server configuration.
4. Translate the wallet app itself — that lives in the app repositories, not
   here.
