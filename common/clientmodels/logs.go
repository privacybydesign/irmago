package clientmodels

import "time"

// LogCredential is a credential entry in a log, containing full credential metadata.
// All text fields are resolved to the current locale.
type LogCredential struct {
	CredentialId        string             `json:"credential_id"`
	Formats             []CredentialFormat `json:"formats"`
	Image               *Image             `json:"image,omitempty"`
	Name                string             `json:"name"`
	Issuer              TrustedParty       `json:"issuer"`
	Attributes          []Attribute        `json:"attributes"`
	IssuanceDate        *int64             `json:"issuance_date"`
	ExpiryDate          *int64             `json:"expiry_date"`
	Revoked             bool               `json:"revoked"`
	RevocationSupported bool               `json:"revocation_supported"`
	IssueURL            *string            `json:"issue_url,omitempty"`
	// Hash is the Credential.Hash of the card this was, when known. Empty for
	// entries the wallet could not match to a card.
	Hash string `json:"hash,omitempty"`
	// HashConfidence says how Hash was found: "exact" when it was recorded at
	// the time, "inferred" when it was matched later from type and values.
	HashConfidence HashConfidence `json:"hash_confidence,omitempty"`
}

// HashConfidence says how the card hash of a log credential was found.
type HashConfidence string

const (
	HashConfidence_Exact    HashConfidence = "exact"
	HashConfidence_Inferred HashConfidence = "inferred"
)

// LogRole is what happened to a credential in a log entry.
type LogRole string

const (
	LogRole_Issued    LogRole = "issued"
	LogRole_Disclosed LogRole = "disclosed"
	LogRole_Removed   LogRole = "removed"
)

// DisclosureLog is a log of a disclosure session.
type DisclosureLog struct {
	Protocol    Protocol        `json:"protocol"`
	Credentials []LogCredential `json:"credentials"`
	Verifier    *TrustedParty   `json:"verifier"`
}

// IssuanceLog is a log of an issuance session.
type IssuanceLog struct {
	Protocol             Protocol        `json:"protocol"`
	Credentials          []LogCredential `json:"credentials"`
	DisclosedCredentials []LogCredential `json:"disclosed_credentials"`
	Issuer               *TrustedParty   `json:"issuer"`
}

// RemovalLog is a log of a credential removal.
type RemovalLog struct {
	Credentials []LogCredential `json:"credentials"`
}

// SignedMessageLog is a log of a signature session.
type SignedMessageLog struct {
	DisclosureLog
	Message string `json:"message"`
}

// LogInfo is a credential format & protocol agnostic log entry with full credential metadata.
type LogInfo struct {
	// ID identifies the entry, for opening it again with Client.GetLog.
	ID               string            `json:"id,omitempty"`
	Type             LogType           `json:"type"`
	Time             time.Time         `json:"time"`
	RemovalLog       *RemovalLog       `json:"removal_log,omitempty"`
	IssuanceLog      *IssuanceLog      `json:"issuance_log,omitempty"`
	DisclosureLog    *DisclosureLog    `json:"disclosure_log,omitempty"`
	SignedMessageLog *SignedMessageLog `json:"signed_message_log,omitempty"`
}

// LogFilter selects log entries. All set fields must match (AND). The
// credential fields (CredentialHash, CredentialId, ClaimPath, Formats, Roles)
// must all match one and the same credential of the entry.
type LogFilter struct {
	// Types keeps entries of these types.
	Types []LogType `json:"types,omitempty"`
	// Protocols keeps entries of these protocols.
	Protocols []Protocol `json:"protocols,omitempty"`
	// Formats keeps entries with a credential in one of these formats.
	Formats []CredentialFormat `json:"formats,omitempty"`
	// CredentialHash keeps entries about this card (Credential.Hash).
	CredentialHash string `json:"credential_hash,omitempty"`
	// CredentialId keeps entries about a credential of this type, including
	// cards that were deleted since.
	CredentialId string `json:"credential_id,omitempty"`
	// ClaimPaths keeps entries that included any of these attributes.
	// Combine it with CredentialHash or CredentialId. A path matches the
	// attribute it names and everything under it, so ["address"] matches
	// every address field. Array positions do not matter: an integer or null
	// matches any item, so ["degrees", null, "name"] is the name of any degree.
	ClaimPaths [][]any `json:"claim_paths,omitempty"`
	// ClaimPath is one more path for ClaimPaths.
	//
	// Deprecated: use ClaimPaths.
	ClaimPath []any `json:"claim_path,omitempty"`
	// Roles keeps entries where the credential had one of these roles.
	Roles []LogRole `json:"roles,omitempty"`
	// PartyKey keeps entries with this party, as PartySummary.Key gives it.
	PartyKey string `json:"party_key,omitempty"`
	// Text keeps entries whose names, attribute values or signed message
	// contain every word of it, ignoring case and accents.
	Text string `json:"text,omitempty"`
	// TextOrTypes also keeps entries of these types when Text does not match.
	// The app matches its own translated type labels and passes the types here.
	TextOrTypes []LogType `json:"text_or_types,omitempty"`
	// From and To keep entries at or after From, and strictly before To.
	From *time.Time `json:"from,omitempty"`
	To   *time.Time `json:"to,omitempty"`
	// IncludeHidden also returns the entries the activity log hides, such as
	// the keyshare enrollment.
	IncludeHidden bool `json:"include_hidden,omitempty"`
}

// LogQuery asks for a page of log entries, newest first.
type LogQuery struct {
	Filter LogFilter `json:"filter"`
	// Cursor continues after the previous page; empty for the first page.
	Cursor string `json:"cursor,omitempty"`
	// Limit is the page size. Zero or less means DefaultLogPageSize.
	Limit int `json:"limit,omitempty"`
	// WithCounts also returns how many entries match, per type.
	WithCounts bool `json:"with_counts,omitempty"`
}

const DefaultLogPageSize = 20

// LogPage is one page of log entries, newest first.
type LogPage struct {
	Entries []LogInfo `json:"entries"`
	// NextCursor continues with the next page; empty when there is none.
	NextCursor string     `json:"next_cursor,omitempty"`
	Counts     *LogCounts `json:"counts,omitempty"`
}

// LogCounts counts the entries that match a filter.
type LogCounts struct {
	// Total counts all matches.
	Total int `json:"total"`
	// ByType counts per type while ignoring the filter's Types, so the app can
	// show a count on every type chip whichever is selected.
	ByType map[LogType]int `json:"by_type"`
}

// CredentialActivity sums up the activity of one card.
type CredentialActivity struct {
	Hash string `json:"hash"`
	// LastUsed is the last time the card was disclosed, nil if never.
	LastUsed *time.Time `json:"last_used,omitempty"`
	// LastReceived is the last time the card was issued.
	LastReceived *time.Time `json:"last_received,omitempty"`
	// ShareCount counts the entries in which the card was disclosed, matched
	// exactly; InferredShareCount counts those matched afterwards.
	ShareCount         int `json:"share_count"`
	InferredShareCount int `json:"inferred_share_count"`
	// EventCount counts all entries about the card.
	EventCount int `json:"event_count"`
}

// PartySummary sums up the entries with one party.
type PartySummary struct {
	// Key is what LogFilter.PartyKey takes.
	Key string `json:"key"`
	// Party is the party as the newest entry with it has it.
	Party    TrustedParty    `json:"party"`
	LastTime time.Time       `json:"last_time"`
	Count    int             `json:"count"`
	ByType   map[LogType]int `json:"by_type"`
}
