package benign

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadTakesOnlyTheStagesThatForbidARule(t *testing.T) {
	requests, skipped, err := Load("testdata")
	require.NoError(t, err)

	require.Len(t, requests, 2, "the expect_ids stage is not part of this corpus")
	assert.Equal(t, 1, skipped, "encoded_request cannot be replayed faithfully")

	assert.Equal(t, "941100-1", requests[0].Title, "named the way go-ftw names it, so failures can be compared")
	assert.Equal(t, []int{941100, 941110}, requests[0].Forbid)
	assert.Equal(t, "GET", requests[0].Method)
	assert.Equal(t, "/get?foo=bar", requests[0].URI)
	assert.Equal(t, 1, requests[0].ID)
	assert.Equal(t, 2, requests[1].ID, "ids must be unique so the audit log can be joined")
}

func TestBytesPreservesHeaderOrderAndAddsOnlyWhatIsMissing(t *testing.T) {
	requests, _, err := Load("testdata")
	require.NoError(t, err)

	plain := string(requests[0].Bytes("waf:8080"))
	assert.True(t, strings.HasPrefix(plain, "GET /get?foo=bar HTTP/1.1\r\n"))
	assert.Less(t, strings.Index(plain, "User-Agent"), strings.Index(plain, "Accept"),
		"some CRS rules care about header order")
	assert.NotContains(t, plain, "Content-Length", "no body, no length")
	assert.NotContains(t, plain, "Content-Type", "no body, no type")
	assert.Contains(t, plain, "Host: localhost", "the test's own Host must win")
	assert.Contains(t, plain, MarkerHeader+": 1")

	// 920340 is a paranoia-1 rule, so a body with no Content-Type trips it and the stage
	// would look like a failure caused by the replay rather than by the ruleset.
	withBody := string(requests[1].Bytes("waf:8080"))
	assert.Contains(t, withBody, "Content-Length: 7")
	assert.Contains(t, withBody, "Content-Type: application/x-www-form-urlencoded")
	assert.True(t, strings.HasSuffix(withBody, "\r\n\r\nfoo=bar"))
}

func TestBytesSuppliesAHostWhenTheTestOmitsOne(t *testing.T) {
	request := Request{ID: 7, Method: "GET", URI: "/", Version: "HTTP/1.1"}

	assert.Contains(t, string(request.Bytes("waf:8080")), "Host: waf:8080")
}

// 920350 scores a numeric Host at PL1 and 920300 a missing Accept at PL3. Both land on
// traffic the false-positive pass is asserting is benign, and either is enough to carry a
// stage over the blocking threshold on its own.
func TestBytesFillsInHeadersThatWouldScoreAgainstBenignTraffic(t *testing.T) {
	bare := Request{Method: "GET", URI: "/", Version: "HTTP/1.1"}

	raw := string(bare.Bytes("127.0.0.1:8080"))
	assert.Contains(t, raw, "Host: localhost\r\n", "a numeric target must not become a numeric Host")
	assert.NotContains(t, raw, "127.0.0.1", "the dial address must not leak into the request")
	assert.Contains(t, raw, "Accept: */*\r\n")

	named := string(bare.Bytes("crs:8080"))
	assert.Contains(t, named, "Host: crs:8080\r\n", "a named target is kept as sent")

	// A stage that sets these keeps them: the corpus decides, not us.
	own := Request{Method: "GET", URI: "/", Version: "HTTP/1.1", Headers: []Header{
		{Name: "Host", Value: "example.com"}, {Name: "Accept", Value: "text/html"},
	}}
	kept := string(own.Bytes("127.0.0.1:8080"))
	assert.Contains(t, kept, "Host: example.com\r\n")
	assert.Contains(t, kept, "Accept: text/html\r\n")
	assert.NotContains(t, kept, "Accept: */*")
	assert.Equal(t, 1, strings.Count(kept, "Host:"), "exactly one Host header")
}
