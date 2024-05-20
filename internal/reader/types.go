package reader

type NucleiTraceOutput struct {
	CVENumber        string
	StatusCode       int
	TotalRequests    uint
	BlockedRequests    uint
	NotBlockedRequests uint
}
