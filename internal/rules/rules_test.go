package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func auditLog(t *testing.T, transactions ...[]string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "audit.json")
	contents := ""
	for _, messages := range transactions {
		encoded, err := json.Marshal(map[string]any{
			"audit_data": map[string]any{"messages": messages},
		})
		require.NoError(t, err)
		contents += string(encoded) + "\n"
	}
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))

	return path
}

func message(rule int) string {
	return fmt.Sprintf(`Warning. Pattern match at ARGS. [file "x"] [id %q] [msg "something"]`,
		strconv.Itoa(rule))
}

// 949110 is what marks a transaction as blocked, which is why no join with the trace
// files is needed to tell blocked from allowed.
func TestReadSplitsContributingRulesFromNearMisses(t *testing.T) {
	path := auditLog(
		t,
		[]string{message(942100), message(949110), message(980170)}, // blocked
		[]string{message(941100), message(920300), message(949110)}, // blocked
		[]string{message(942432)},                                   // fired, not blocked
		[]string{message(920300)},                                   // hygiene, not an attack
	)

	summary, err := Read(path)
	require.NoError(t, err)

	assert.Equal(t, 4, summary.Transactions)
	assert.Equal(t, 2, summary.Blocked)

	assert.Equal(t, map[int]int{942100: 1, 941100: 1, 920300: 1}, summary.Contributing,
		"920300 fired in a blocked transaction, so it contributed")
	assert.Equal(t, map[int]int{942432: 1}, summary.NearMiss,
		"only attack families count as near misses; a missing Accept header is not one")
}

// Counting the blocking rule among the causes would say only that blocked requests were
// blocked.
func TestBookkeepingRulesAreNotCauses(t *testing.T) {
	path := auditLog(t, []string{message(949110), message(980170), message(959100)})

	summary, err := Read(path)
	require.NoError(t, err)

	assert.Equal(t, 1, summary.Blocked)
	assert.Empty(t, summary.Contributing)
	assert.Empty(t, summary.NearMiss)
}

func TestAttackFamilies(t *testing.T) {
	for _, rule := range []int{930130, 941100, 942432, 944100} {
		assert.True(t, attack(rule), "%d looks for an attack", rule)
	}
	for _, rule := range []int{911100, 920300, 949110, 980170} {
		assert.False(t, attack(rule), "%d is protocol hygiene or bookkeeping", rule)
	}
}

func TestStringRanksByCountThenRule(t *testing.T) {
	path := auditLog(
		t,
		[]string{message(942100), message(949110)},
		[]string{message(942100), message(949110)},
		[]string{message(941100), message(949110)},
	)

	summary, err := Read(path)
	require.NoError(t, err)

	rendered := summary.String()
	assert.Contains(t, rendered, "3 transactions, 3 blocked")
	assert.Less(t, strings.Index(rendered, "942100"), strings.Index(rendered, "941100"),
		"the rule behind more blocks comes first")
}
