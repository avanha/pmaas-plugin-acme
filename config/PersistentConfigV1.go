package config

import "time"

// PersistentConfigV1 is the plugin's state persisted across restarts via
// IPMAASContainer.SaveConfig/LoadConfig.
//
// The account key/registration URI are kept so the plugin reuses its existing ACME account
// instead of registering a new one on every restart, which would eventually trip Let's
// Encrypt's new-account rate limit. The certificate/key are kept so a restart doesn't
// re-issue a still-valid certificate, which would count against the per-domain issuance rate
// limit.
type PersistentConfigV1 struct {
	AccountPrivateKeyPEM []byte
	RegistrationURI      string

	CertificatePEM    []byte
	CertificateKeyPEM []byte
	IssuedAt          time.Time
	NotAfter          time.Time
}
