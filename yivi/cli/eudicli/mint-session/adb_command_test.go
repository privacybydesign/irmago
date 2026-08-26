package main

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// adbCommand builds a command a human is expected to paste into a shell, from a
// link that arrived in another party's HTTP response. Nothing here executes it, so
// a quote surviving into the string is not an injection in this process — it is an
// injection in the shell the user pastes into, which is worse for being invisible
// from here.
func TestAdbCommand_AcceptsARealLink(t *testing.T) {
	// Shaped like what the verifier actually returns: percent-encoded, with the
	// reserved characters a URL legitimately carries.
	link := "eudi-openid4vp://?client_id=x509_san_dns%3Alocalhost" +
		"&request_uri=http%3A%2F%2Flocalhost%3A8090%2Fwallet%2Frequest.jwt%2FabC-_9xyz" +
		"&request_uri_method=get&transaction_id=aB3-_xY"

	command, err := adbCommand(link)

	require.NoError(t, err, "an ordinary percent-encoded link must be accepted")
	require.Contains(t, command, link)
	require.True(t, strings.HasPrefix(command, `adb shell "am start -a android.intent.action.VIEW -d '`),
		"the shape of the printed command must not change: it is copied by hand")
	require.True(t, strings.HasSuffix(command, `'"`))
}

func TestAdbCommand_RefusesQuotingBreakers(t *testing.T) {
	tests := []struct {
		name string
		link string
	}{
		{
			// Closes the inner quoting the device's own shell re-parses.
			name: "a single quote closes the inner quoting",
			link: "eudi-openid4vp://?x=a'b",
		},
		{
			// Closes the outer quoting the local shell parses.
			name: "a double quote closes the outer quoting",
			link: `eudi-openid4vp://?x=a"b`,
		},
		{
			// Still live inside double quotes, so it would substitute rather than
			// print.
			name: "a backtick would substitute a command",
			link: "eudi-openid4vp://?x=a`id`b",
		},
		{
			name: "a dollar would expand",
			link: "eudi-openid4vp://?x=a$HOME",
		},
		{
			name: "a backslash would escape the next character",
			link: `eudi-openid4vp://?x=a\b`,
		},
		{
			// The realistic hostile shape: end the URL, close the quoting, chain a
			// second command that the paste would run.
			name: "a chained command is refused rather than printed",
			link: "eudi-openid4vp://?x=1'; rm -rf ~; echo '",
		},
		{
			name: "a newline would split the pasted command in two",
			link: "eudi-openid4vp://?x=a\nrm -rf ~",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command, err := adbCommand(test.link)

			require.Error(t, err, "a link that cannot be quoted safely must be refused")
			require.Empty(t, command, "no partial command may be returned alongside the error")
		})
	}
}

// The reason the refusal above never fires in practice, pinned so it stays true:
// every link reaching adbCommand has been through url.Values.Encode or
// url.QueryEscape, and both percent-encode all five quoting breakers. If that
// ever stops holding, this fails here rather than at a user's shell prompt.
func TestPercentEncodingRemovesEveryQuotingBreaker(t *testing.T) {
	hostile := "a'b\"c`d$e\\f"

	t.Run("url.QueryEscape, as the offer link uses", func(t *testing.T) {
		escaped := url.QueryEscape(hostile)
		require.NotContains(t, escaped, "'")
		require.Equal(t, -1, strings.IndexAny(escaped, quotingBreakers))

		_, err := adbCommand("openid-credential-offer://?credential_offer=" + escaped)
		require.NoError(t, err)
	})

	t.Run("url.Values.Encode, as the presentation link uses", func(t *testing.T) {
		query := url.Values{}
		query.Add("transaction_id", hostile)
		encoded := query.Encode()
		require.Equal(t, -1, strings.IndexAny(encoded, quotingBreakers))

		_, err := adbCommand("eudi-openid4vp://?" + encoded)
		require.NoError(t, err)
	})
}
