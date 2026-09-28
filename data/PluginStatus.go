package data

import "time"

// PluginStatus is the acme plugin's status-page data: the ACME account it's registered under,
// the currently held certificate, and the most recent error encountered obtaining/renewing it.
type PluginStatus struct {
	Domains         []string
	Email           string
	RegistrationURI string

	CommonName    string
	RefreshedTime time.Time
	ExpiresTime   time.Time

	LastErrorMessage string
	LastErrorTime    time.Time
}
