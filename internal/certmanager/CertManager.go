package certmanager

import (
	"context"
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
	defaultRenewalCheckInterval  = 12 * time.Hour
	defaultRenewalRetryInterval  = 5 * time.Minute
	defaultPropagationTimeout    = 2 * time.Minute
	defaultPropagationPollPeriod = 5 * time.Second
	accountKeyType               = certcrypto.EC256
	certificateKeyType           = certcrypto.EC256
)

// State is the manager's account registration + certificate data, handed to Config.OnStateChanged
// whenever it changes (see Run) - both the raw material a caller needs to persist across restarts
// (AccountPrivateKeyPEM/CertificatePEM/CertificateKeyPEM) and the fields worth showing on a status
// page (RegistrationURI/CommonName/IssuedAt/NotAfter).
type State struct {
	AccountPrivateKeyPEM []byte
	RegistrationURI      string

	CertificatePEM    []byte
	CertificateKeyPEM []byte
	CommonName        string
	IssuedAt          time.Time
	NotAfter          time.Time
}

// StateChangedFunc is called, from Run's own goroutine, whenever the account registration
// and/or certificate changes - mirroring how pmaas-plugin-nestthermostat's poller reports data
// it fetches back to its plugin via callback, rather than the plugin polling for it.
type StateChangedFunc func(State)

// ErrorFunc is called, from Run's own goroutine, whenever registering the account or
// obtaining/renewing the certificate fails.
type ErrorFunc func(error)

// ParseCommonName returns certPEM's leaf certificate's Subject.CommonName, or "" if certPEM is
// empty or can't be parsed. Exported so a caller resuming from persisted State (which carries
// CertificatePEM but not the CommonName the certificate manager derived from it last time it was
// obtained - see State) can recover it without duplicating certificate-parsing logic.
func ParseCommonName(certPEM []byte) string {
	if len(certPEM) == 0 {
		return ""
	}

	cert, err := certcrypto.ParsePEMCertificate(certPEM)
	if err != nil {
		return ""
	}

	return cert.Subject.CommonName
}

type Config struct {
	Domains      []string
	Email        string
	DirectoryURL string

	RenewBeforeExpiry    time.Duration
	RenewalCheckInterval time.Duration
	RenewalRetryInterval time.Duration

	PorkbunAPIKey             string
	PorkbunAPISecret          string
	PorkbunPropagationTimeout time.Duration
	PorkbunPollingInterval    time.Duration

	// InitialState resumes a previously persisted account/certificate. Its zero value is a
	// valid "nothing persisted yet" starting point.
	InitialState State

	OnStateChanged StateChangedFunc
	OnError        ErrorFunc
}

// Manager owns an ACME account and, once Run is started, the currently valid certificate for
// Config.Domains, obtaining and renewing it via lego, using DNS-01 challenges answered through
// Porkbun.
type Manager struct {
	domains              []string
	renewBeforeExpiry    time.Duration
	renewalCheckInterval time.Duration
	renewalRetryInterval time.Duration
	onStateChanged       StateChangedFunc
	onError              ErrorFunc

	user   *acmeuser.User
	client *lego.Client

	// certPEM/keyPEM/commonName/issuedAt are only ever read or written from Run's own
	// goroutine - the sole caller of obtainCertificate and currentState - so, unlike
	// tlsCert/notAfter, they need no locking.
	certPEM    []byte
	keyPEM     []byte
	commonName string
	issuedAt   time.Time

	// mu guards tlsCert and notAfter, since GetCertificate/needsRenewal read them concurrently
	// from arbitrary goroutines (one per incoming TLS handshake - see
	// IPMAASContainer.ProvideTLSCertificate) while Run's own goroutine writes them.
	mu       sync.RWMutex
	tlsCert  *tls.Certificate
	notAfter time.Time
}

func NewManager(cfg Config) (*Manager, error) {
	if len(cfg.Domains) == 0 {
		return nil, errors.New("certmanager: at least one domain is required")
	}

	if cfg.PorkbunAPIKey == "" || cfg.PorkbunAPISecret == "" {
		return nil, errors.New("certmanager: Porkbun API key/secret are required for DNS-01 challenges")
	}

	if cfg.OnStateChanged == nil || cfg.OnError == nil {
		return nil, errors.New("certmanager: OnStateChanged and OnError callbacks are required")
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
		domains:              cfg.Domains,
		renewBeforeExpiry:    orDefault(cfg.RenewBeforeExpiry, defaultRenewBeforeExpiry),
		renewalCheckInterval: orDefault(cfg.RenewalCheckInterval, defaultRenewalCheckInterval),
		renewalRetryInterval: orDefault(cfg.RenewalRetryInterval, defaultRenewalRetryInterval),
		onStateChanged:       cfg.OnStateChanged,
		onError:              cfg.OnError,
		user:                 user,
		client:               client,
	}

	if len(cfg.InitialState.CertificatePEM) > 0 && len(cfg.InitialState.CertificateKeyPEM) > 0 {
		tlsCert, err := tls.X509KeyPair(cfg.InitialState.CertificatePEM, cfg.InitialState.CertificateKeyPEM)

		if err != nil {
			fmt.Printf("certmanager: discarding persisted certificate, unable to parse: %v\n", err)
		} else {
			m.tlsCert = &tlsCert
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

// Run keeps the certificate renewed until ctx is done, reporting every attempt's outcome via
// Config.OnStateChanged/OnError - mirroring how pmaas-plugin-nestthermostat's poller reports back
// to its plugin via callback rather than the plugin polling it. Unlike that poller, which can
// afford an initial delay before its first fetch, the first renewal check here happens immediately:
// a brand new deployment has no certificate at all yet, so there's no reason to wait.
func (m *Manager) Run(ctx context.Context) {
	for {
		if m.needsRenewal() {
			if err := m.obtainCertificate(); err != nil {
				m.onError(err)
			} else {
				m.onStateChanged(m.currentState())
			}
		}

		interval := m.renewalCheckInterval
		if m.needsRenewal() {
			interval = m.renewalRetryInterval
		}

		timer := time.NewTimer(interval)

		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// needsRenewal reports whether the current certificate is missing or within renewBeforeExpiry
// of its expiry.
func (m *Manager) needsRenewal() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.tlsCert == nil || time.Until(m.notAfter) <= m.renewBeforeExpiry
}

// obtainCertificate registers the ACME account if needed, then unconditionally obtains a new
// certificate - it's Run's job to call this only when needsRenewal is true.
func (m *Manager) obtainCertificate() error {
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

	m.certPEM = resource.Certificate
	m.keyPEM = resource.PrivateKey
	m.commonName = x509Cert.Subject.CommonName
	m.issuedAt = time.Now()

	m.mu.Lock()
	m.tlsCert = &tlsCert
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

// currentState snapshots the manager's account/certificate data for Config.OnStateChanged.
// Called only from Run's own goroutine, same as every field it reads except notAfter.
func (m *Manager) currentState() State {
	state := State{
		AccountPrivateKeyPEM: certcrypto.PEMEncode(m.user.PrivateKey),
		CertificatePEM:       m.certPEM,
		CertificateKeyPEM:    m.keyPEM,
		CommonName:           m.commonName,
		IssuedAt:             m.issuedAt,
	}

	m.mu.RLock()
	state.NotAfter = m.notAfter
	m.mu.RUnlock()

	if m.user.Registration != nil {
		state.RegistrationURI = m.user.Registration.URI
	}

	return state
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
