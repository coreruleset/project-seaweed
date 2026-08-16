package reader

// NucleiTraceOutput is what one CVE's trace files say about the WAF.
//
// TotalRequests is the sum of the four counters. BlockedRequests and NotBlockedRequests
// are verdicts the WAF reached about a payload. ErroredRequests are answers the reverse
// proxy gave about itself, and RejectedRequests are ones it refused before the backend
// saw them; neither says anything about the payload either way.
//
// Exercised is false when the template never sent anything but a bare `GET /`, which
// means its payload step never ran and the WAF was never asked about this CVE at all.
type NucleiTraceOutput struct {
	CVENumber          string
	TotalRequests      uint
	BlockedRequests    uint
	NotBlockedRequests uint
	ErroredRequests    uint
	RejectedRequests   uint
	Exercised          bool
}
