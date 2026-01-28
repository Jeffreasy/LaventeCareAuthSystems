package mailer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateSMTPHost_BlockedHosts(t *testing.T) {
	tests := []struct {
		name  string
		host  string
		error string // Expected error substring
	}{
		{"Localhost String", "localhost", "localhost connections forbidden"},
		{"IPv4 Loopback", "127.0.0.1", "localhost connections forbidden"},
		{"IPv6 Loopback Short", "::1", "localhost connections forbidden"},
		{"IPv6 Loopback Full", "0:0:0:0:0:0:0:1", "security violation: connection to private network blocked"},
		{"Private Class A", "10.0.0.1", "security violation: connection to private network blocked"},
		{"Private Class B", "172.16.0.1", "security violation: connection to private network blocked"},
		{"Private Class C", "192.168.1.1", "security violation: connection to private network blocked"},
		{"Cloud Metadata", "169.254.169.254", "security violation: connection to private network blocked"},
		{"Broadcast", "255.255.255.255", "security violation: connection to private network blocked"},
		{"Test Net 1", "192.0.2.1", "security violation: connection to private network blocked"},
		{"Any", "0.0.0.0", "localhost connections forbidden"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSMTPHost(tt.host)
			assert.Error(t, err)
			if err != nil {
				assert.Contains(t, err.Error(), tt.error)
			}
		})
	}
}

func TestValidateSMTPHost_AllowedHosts(t *testing.T) {
	// Note: These tests require internet access and DNS resolution.
	// We use well-known public IPs to avoid flaky DNS.
	tests := []struct {
		name string
		host string
	}{
		{"Google DNS TCP", "8.8.8.8"},
		{"Cloudflare DNS TCP", "1.1.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSMTPHost(tt.host)
			assert.NoError(t, err)
		})
	}
}

func TestValidateSMTPPort(t *testing.T) {
	tests := []struct {
		name      string
		port      int
		shouldErr bool
	}{
		{"Standard SMTP", 25, false},
		{"SMTPS", 465, false},
		{"Submission", 587, false},
		{"Alt Submission", 2525, false},
		{"HTTP", 80, true},
		{"HTTPS", 443, true},
		{"SSH", 22, true},
		{"Postgres", 5432, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSMTPPort(tt.port)
			if tt.shouldErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
