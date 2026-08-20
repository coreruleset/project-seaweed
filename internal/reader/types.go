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
//
// MetadataProbes counts requests that only fetched a file describing the application, such
// as a plugin's readme. They are how a template decides whether a target is worth attacking,
// so a trace of nothing but these did not test the WAF either.
type NucleiTraceOutput struct {
	CVENumber          string
	TotalRequests      uint
	BlockedRequests    uint
	NotBlockedRequests uint
	ErroredRequests    uint
	RejectedRequests   uint
	MetadataProbes     uint

	// UnblockedPayloads counts requests that carried an attack and were not refused. Zero,
	// alongside a block, means the WAF stopped everything the template actually threw at it.
	//
	// BlockedAttacks counts refusals of something other than a plain sign-in, so that a WAF
	// which only refused the template's login step is not credited with stopping the exploit
	// that login was leading up to.
	UnblockedPayloads uint
	BlockedAttacks    uint
	Exercised         bool
}
