package ip_whitelist

// Event data reported via metrics EventContext Extras
// when the ip_whitelist plugin executes.

type IPWhitelistData struct {
	Matched     bool   `json:"matched"`
	IP          string `json:"ip"`
	AllowedIP   string `json:"allowed_ip,omitempty"`
	AllowedCIDR string `json:"allowed_cidr,omitempty"`
}
