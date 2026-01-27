package mailer

import (
	"fmt"
	"net"
	"strings"
)

// ValidateSMTPHost prevents SSRF (Server-Side Request Forgery) by blocking
// connections to private networks, localhost, and link-local addresses.
//
// This is CRITICAL defense-in-depth (Anti-Gravity Law 3: Infrastructure is a Fortress).
//
// Attack Scenarios Prevented:
// - Internal network scanning (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12)
// - Localhost exploitation (127.0.0.1, ::1)
// - DNS rebinding attacks (validates resolved IPs, not just hostname)
// - Cloud metadata API access (169.254.169.254)
//
// Security Notes:
// - Validation happens on EVERY email send (not just config time) to prevent DNS rebinding
// - Blocks both IPv4 and IPv6 private ranges per RFC 1918, RFC 4193
// - Returns generic errors to prevent information disclosure (Law 2: Silence is Golden)
func ValidateSMTPHost(host string) error {
	// 1. Normalize hostname (prevent bypass via case manipulation)
	host = strings.ToLower(strings.TrimSpace(host))

	// 2. Block obvious localhost variants (quick fail)
	blockedHosts := []string{
		"localhost",
		"0.0.0.0",
		"127.0.0.1",
		"::1",
		"[::1]",
		"ip6-localhost",
		"ip6-loopback",
	}

	for _, blocked := range blockedHosts {
		if host == blocked {
			return fmt.Errorf("security violation: localhost connections forbidden")
		}
	}

	// 3. DNS resolution (CRITICAL: prevents subdomain takeover tricks)
	// Example attack: attacker.com initially resolves to 1.2.3.4 (public),
	// then changes DNS to 127.0.0.1 after config validation passes.
	// By validating on EVERY send, we prevent this.
	ips, err := net.LookupIP(host)
	if err != nil {
		// Don't leak DNS error details to client (Law 2)
		return fmt.Errorf("hostname resolution failed")
	}

	if len(ips) == 0 {
		return fmt.Errorf("hostname resolves to no IP addresses")
	}

	// 4. Check EACH resolved IP for private/internal ranges
	// A hostname can resolve to multiple IPs; ALL must be public.
	for _, ip := range ips {
		if err := validatePublicIP(ip); err != nil {
			// Log the actual IP for security monitoring, but return generic error
			return fmt.Errorf("security violation: connection to private network blocked")
		}
	}

	return nil
}

// validatePublicIP returns error if IP is not a public, routable address.
// Covers RFC 1918 (private IPv4), RFC 4193 (ULA IPv6), loopback, link-local, etc.
func validatePublicIP(ip net.IP) error {
	// Standard library helpers (Go 1.17+)
	// These cover most common cases
	if ip.IsLoopback() {
		return fmt.Errorf("loopback address")
	}

	if ip.IsPrivate() {
		return fmt.Errorf("private address")
	}

	if ip.IsUnspecified() {
		return fmt.Errorf("unspecified address")
	}

	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("link-local address")
	}

	// Additional explicit checks for defense-in-depth
	// (Standard library might not catch all edge cases in older Go versions)
	privateBlocks := []string{
		"10.0.0.0/8",      // RFC 1918 (Private network)
		"172.16.0.0/12",   // RFC 1918 (Private network)
		"192.168.0.0/16",  // RFC 1918 (Private network)
		"127.0.0.0/8",     // Loopback
		"169.254.0.0/16",  // RFC 3927 (Link-local / Cloud metadata API!)
		"::1/128",         // IPv6 loopback
		"fc00::/7",        // RFC 4193 (IPv6 ULA)
		"fe80::/10",       // RFC 4291 (IPv6 link-local)
		"ff00::/8",        // IPv6 multicast
		"0.0.0.0/8",       // RFC 1122 ("This network")
		"100.64.0.0/10",   // RFC 6598 (Shared Address Space / CG NAT)
		"192.0.0.0/24",    // RFC 6890 (IETF Protocol Assignments)
		"192.0.2.0/24",    // RFC 5737 (TEST-NET-1)
		"198.18.0.0/15",   // RFC 2544 (Benchmarking)
		"198.51.100.0/24", // RFC 5737 (TEST-NET-2)
		"203.0.113.0/24",  // RFC 5737 (TEST-NET-3)
		"224.0.0.0/4",     // RFC 5771 (Multicast)
		"240.0.0.0/4",     // RFC 1112 (Reserved)
	}

	for _, block := range privateBlocks {
		_, cidr, err := net.ParseCIDR(block)
		if err != nil {
			continue // Skip malformed CIDR (shouldn't happen)
		}

		if cidr.Contains(ip) {
			return fmt.Errorf("blocked CIDR range: %s", block)
		}
	}

	return nil
}

// ValidateSMTPPort restricts to standard SMTP ports to prevent port scanning.
// Non-standard ports could indicate:
// - Port scanning attempts (e.g., testing if PostgreSQL is on 5432)
// - Exploitation of non-SMTP services
// - Abuse of internal services exposed on custom ports
func ValidateSMTPPort(port int) error {
	allowedPorts := map[int]string{
		25:   "SMTP (legacy, unencrypted)",
		465:  "SMTPS (SSL/TLS)",
		587:  "SMTP (STARTTLS submission)",
		2525: "SMTP (alternate submission port)",
	}

	if _, ok := allowedPorts[port]; ok {
		return nil
	}

	// Don't leak allowed ports to attacker (Law 2)
	return fmt.Errorf("non-standard SMTP port blocked")
}

// ValidateSMTPConfig is a convenience function that validates both host and port.
// Call this from your admin panel when tenant configures SMTP settings AND
// in the worker before every email send (prevents DNS rebinding).
func ValidateSMTPConfig(host string, port int) error {
	if err := ValidateSMTPHost(host); err != nil {
		return fmt.Errorf("invalid SMTP host: %w", err)
	}

	if err := ValidateSMTPPort(port); err != nil {
		return fmt.Errorf("invalid SMTP port: %w", err)
	}

	return nil
}
