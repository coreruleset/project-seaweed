package reader

// NucleiTraceOutput is what one CVE's trace files say about the WAF.
//
// TotalRequests is the sum of the three counters. BlockedRequests and NotBlockedRequests
// are verdicts the WAF reached about a payload; ErroredRequests are answers the reverse
// proxy gave about itself, which say nothing about the payload either way.
type NucleiTraceOutput struct {
	CVENumber          string
	TotalRequests      uint
	BlockedRequests    uint
	NotBlockedRequests uint
	ErroredRequests    uint
}
