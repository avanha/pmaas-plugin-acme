package config

import "time"

// PluginConfig configures the acme plugin. Domains[0] becomes the issued certificate's
// CommonName; any additional entries are included as Subject Alternative Names.
//
// Only DNS-01 validation is supported today, via lego's Porkbun DNS provider (see PorkbunConfig).
// HTTP-01 support could be added later as an alternative Challenge selection, but that requires
// the server to accept plain (non-TLS) requests on port 80, which this deployment deliberately
// does not do.
type PluginConfig struct {
	Domains []string
	Email   string

	// DirectoryURL is the ACME server's directory endpoint. Empty selects Let's Encrypt's
	// production directory (lego.LEDirectoryProduction) - use lego.LEDirectoryStaging while
	// testing, to avoid burning production issuance rate limits.
	DirectoryURL string

	// RenewBeforeExpiry is how long before the current certificate's expiry a renewal is
	// attempted. Zero selects a default of 30 days.
	RenewBeforeExpiry time.Duration

	// RenewalCheckInterval is how often the background loop checks whether the current
	// certificate is within RenewBeforeExpiry of expiring. Zero selects a default of 12 hours.
	RenewalCheckInterval time.Duration

	// RenewalRetryInterval is how often the background loop retries after a failed renewal
	// attempt (or before the very first certificate has ever been obtained), which is expected
	// to be much shorter than RenewalCheckInterval. Zero selects a default of 5 minutes.
	RenewalRetryInterval time.Duration

	Porkbun PorkbunConfig
}

// PorkbunConfig holds the credentials lego's Porkbun DNS provider uses to create and clean up
// the _acme-challenge TXT record during DNS-01 validation. These are the same API
// key/secret used by pmaas-plugin-porkbun.
type PorkbunConfig struct {
	ApiKey    string
	ApiSecret string

	// PropagationTimeout bounds how long lego waits for the TXT record to become visible
	// before giving up. Zero selects a default of 2 minutes.
	PropagationTimeout time.Duration

	// PollingInterval is how often lego re-checks the TXT record while waiting for it to
	// propagate. Zero selects a default of 5 seconds.
	PollingInterval time.Duration
}

func NewPluginConfig() PluginConfig {
	return PluginConfig{}
}
