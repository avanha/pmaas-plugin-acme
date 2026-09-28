package certmanager

import (
	"crypto"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/porkbun"
	"github.com/go-acme/lego/v4/registration"

	"github.com/avanha/pmaas-plugin-acme/internal/acmeuser"
)

const (
	defaultRenewBeforeExpiry     = 30 * 24 * time.Hour
	defaultPropagationTimeout    = 2 * time.Minute
	defaultPropagationPollPeriod = 5 * time.Second
	accountKeyType               = certcrypto.EC256
	certificateKeyType           = certcrypto.EC256
)

// State is the manager's full ACME account + certificate state - exactly what a caller needs
// to persist across restarts and to hand back in as Config.InitialState to resume without
// re-registering the account or re-issuing a still-valid certificate.
type State struct {
	AccountPrivateKeyPEM []byte
	RegistrationURI      string

	CertificatePEM    []byte
	CertificateKeyPEM []byte
	NotAfter          time.Time
}

type Config struct {
	Domains      []string
	Email        string
	DirectoryURL string

	RenewBeforeExpiry time.Duration

	PorkbunAPIKey             string
	PorkbunAPISecret          string
	PorkbunPropagationTimeout time.Duration
	PorkbunPollingInterval    time.Duration

	// InitialState resumes a previously persisted account/certificate. Its zero value is a
	// valid "nothing persisted yet" starting point.
	InitialState State
}

// Manager owns an ACME account and the currently valid certificate for Config.Domains,
// obtaining and renewing it via lego, using DNS-01 challenges answered through Porkbun.
type Manager struct {
	domains           []string
	renewBeforeExpiry time.Duration

	user   *acmeuser.User
	client *lego.Client

	mu       sync.RWMutex
	tlsCert  *tls.Certificate
	certPEM  []byte
	keyPEM   []byte
	notAfter time.Time
}

func NewManager(cfg Config) (*Manager, error) {
	if len(cfg.Domains) == 0 {
		return nil, errors.New("certmanager: at least one domain is required")
	}

	if cfg.PorkbunAPIKey == "" || cfg.PorkbunAPISecret == "" {
		return nil, errors.New("certmanager: Porkbun API key/secret are required for DNS-01 challenges")
	}

	privateKey, err := loadOrGenerateAccountKey(cfg.InitialState.AccountPrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("certmanager: account private key: %w", err)
	}

	user := &acmeuser.User{Email: cfg.Email, PrivateKey: privateKey}
	if cfg.InitialState.RegistrationURI != "" {
		user.Registration = &registration.Resource{URI: cfg.InitialState.RegistrationURI}
	}

	legoConfig := lego.NewConfig(user)
	if cfg.DirectoryURL != "" {
		legoConfig.CADirURL = cfg.DirectoryURL
	}
	legoConfig.Certificate.KeyType = certificateKeyType

	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return nil, fmt.Errorf("certmanager: creating ACME client: %w", err)
	}

	dnsProviderConfig := porkbun.NewDefaultConfig()
	dnsProviderConfig.APIKey = cfg.PorkbunAPIKey
	dnsProviderConfig.SecretAPIKey = cfg.PorkbunAPISecret
	dnsProviderConfig.PropagationTimeout = orDefault(cfg.PorkbunPropagationTimeout, defaultPropagationTimeout)
	dnsProviderConfig.PollingInterval = orDefault(cfg.PorkbunPollingInterval, defaultPropagationPollPeriod)

	dnsProvider, err := porkbun.NewDNSProviderConfig(dnsProviderConfig)
	if err != nil {
		return nil, fmt.Errorf("certmanager: creating Porkbun DNS-01 provider: %w", err)
	}

	if err := client.Challenge.SetDNS01Provider(dnsProvider); err != nil {
		return nil, fmt.Errorf("certmanager: registering DNS-01 provider: %w", err)
	}

	m := &Manager{
		domains:           cfg.Domains,
		renewBeforeExpiry: orDefault(cfg.RenewBeforeExpiry, defaultRenewBeforeExpiry),
		user:              user,
		client:            client,
	}

	if len(cfg.InitialState.CertificatePEM) > 0 && len(cfg.InitialState.CertificateKeyPEM) > 0 {
		tlsCert, err := tls.X509KeyPair(cfg.InitialState.CertificatePEM, cfg.InitialState.CertificateKeyPEM)

		if err != nil {
			fmt.Printf("certmanager: discarding persisted certificate, unable to parse: %v\n", err)
		} else {
			m.tlsCert = &tlsCert
			m.certPEM = cfg.InitialState.CertificatePEM
			m.keyPEM = cfg.InitialState.CertificateKeyPEM
			m.notAfter = cfg.InitialState.NotAfter
		}
	}

	return m, nil
}

func loadOrGenerateAccountKey(pemBytes []byte) (crypto.PrivateKey, error) {
	if len(pemBytes) > 0 {
		return certcrypto.ParsePEMPrivateKey(pemBytes)
	}

	return certcrypto.GeneratePrivateKey(accountKeyType)
}

func orDefault(value, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}

	return fallback
}

// NeedsRenewal reports whether the current certificate is missing or within
// renewBeforeExpiry of its expiry.
func (m *Manager) NeedsRenewal() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.tlsCert == nil || time.Until(m.notAfter) <= m.renewBeforeExpiry
}

// EnsureCertificate registers the ACME account if needed, then obtains a new certificate if
// the current one is missing or nearing expiry. It's a no-op (returning nil) if the current
// certificate is still comfortably valid.
func (m *Manager) EnsureCertificate() error {
	if !m.NeedsRenewal() {
		return nil
	}

	if err := m.ensureRegistered(); err != nil {
		return err
	}

	resource, err := m.client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: m.domains,
		Bundle:  true,
	})

	if err != nil {
		return fmt.Errorf("certmanager: obtaining certificate: %w", err)
	}

	x509Cert, err := certcrypto.ParsePEMCertificate(resource.Certificate)
	if err != nil {
		return fmt.Errorf("certmanager: parsing issued certificate: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(resource.Certificate, resource.PrivateKey)
	if err != nil {
		return fmt.Errorf("certmanager: building TLS certificate: %w", err)
	}

	m.mu.Lock()
	m.tlsCert = &tlsCert
	m.certPEM = resource.Certificate
	m.keyPEM = resource.PrivateKey
	m.notAfter = x509Cert.NotAfter
	m.mu.Unlock()

	return nil
}

// ensureRegistered registers the ACME account if user.Registration isn't already set (either
// from a prior call in this process, or resumed from Config.InitialState.RegistrationURI).
// Running the plugin with a configured Email is this deployment's acceptance of the ACME
// server's terms of service - there's no interactive prompt in a headless service.
func (m *Manager) ensureRegistered() error {
	if m.user.Registration != nil {
		return nil
	}

	reg, err := m.client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})

	if err != nil {
		return fmt.Errorf("certmanager: registering ACME account: %w", err)
	}

	m.user.Registration = reg

	return nil
}

// GetCertificate matches tls.Config.GetCertificate's shape (see
// IPMAASContainer.ProvideTLSCertificate) and is safe for concurrent use, since it's invoked
// fresh on every incoming TLS handshake.
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.tlsCert == nil {
		return nil, errors.New("certmanager: no certificate available yet")
	}

	return m.tlsCert, nil
}

// State returns a snapshot of the manager's current account/certificate state, suitable for
// persisting via Config.InitialState on the next restart. CertificatePEM/CertificateKeyPEM are
// empty if no certificate has been obtained yet.
func (m *Manager) State() State {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state := State{
		AccountPrivateKeyPEM: certcrypto.PEMEncode(m.user.PrivateKey),
		CertificatePEM:       m.certPEM,
		CertificateKeyPEM:    m.keyPEM,
		NotAfter:             m.notAfter,
	}

	if m.user.Registration != nil {
		state.RegistrationURI = m.user.Registration.URI
	}

	return state
}
