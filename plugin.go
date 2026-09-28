package acme

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"

	spi "github.com/avanha/pmaas-spi"

	"github.com/avanha/pmaas-plugin-acme/config"
	"github.com/avanha/pmaas-plugin-acme/data"
	"github.com/avanha/pmaas-plugin-acme/internal/certmanager"
	"github.com/avanha/pmaas-plugin-acme/internal/http"
)

const (
	defaultRenewalCheckInterval = 12 * time.Hour
	defaultRenewalRetryInterval = 5 * time.Minute
)

type plugin struct {
	config      config.PluginConfig
	container   spi.IPMAASContainer
	certManager *certmanager.Manager
	httpHandler *http.Handler

	cancelFn  context.CancelFunc
	workersWg sync.WaitGroup
}

type Plugin interface {
	spi.IPMAASPlugin
}

func NewPluginConfig() config.PluginConfig {
	return config.NewPluginConfig()
}

func NewPlugin(conf config.PluginConfig) Plugin {
	return &plugin{config: conf, httpHandler: http.NewHandler()}
}

func (p *plugin) ShortName() string {
	return "acme"
}

func (p *plugin) Init(container spi.IPMAASContainer) {
	p.container = container

	initialState := p.loadPersistedState()

	certManager, err := certmanager.NewManager(certmanager.Config{
		Domains:                   p.config.Domains,
		Email:                     p.config.Email,
		DirectoryURL:              p.config.DirectoryURL,
		RenewBeforeExpiry:         p.config.RenewBeforeExpiry,
		PorkbunAPIKey:             p.config.Porkbun.ApiKey,
		PorkbunAPISecret:          p.config.Porkbun.ApiSecret,
		PorkbunPropagationTimeout: p.config.Porkbun.PropagationTimeout,
		PorkbunPollingInterval:    p.config.Porkbun.PollingInterval,
		InitialState:              initialState,
	})

	if err != nil {
		panic(fmt.Errorf("%T failed to create certificate manager: %w", p, err))
	}

	p.certManager = certManager
	p.httpHandler.Init(container, p)

	// Must happen during Init or Start, before Start returns - see
	// IPMAASContainer.ProvideTLSCertificate. GetCertificate itself returns an error for any
	// handshake that arrives before the first certificate has been obtained (see Start).
	if err := container.ProvideTLSCertificate(p.certManager.GetCertificate); err != nil {
		panic(fmt.Errorf("%T failed to register as the TLS certificate provider: %w", p, err))
	}
}

// GetStatus implements internal/http.StatusProvider, for the plugin's status page.
func (p *plugin) GetStatus() data.PluginStatus {
	status := p.certManager.Status()

	return data.PluginStatus{
		Domains:          status.Domains,
		Email:            status.Email,
		RegistrationURI:  status.RegistrationURI,
		CommonName:       status.CommonName,
		RefreshedTime:    status.RefreshedTime,
		ExpiresTime:      status.ExpiresTime,
		LastErrorMessage: status.LastErrorMessage,
		LastErrorTime:    status.LastErrorTime,
	}
}

func (p *plugin) loadPersistedState() certmanager.State {
	persistentConfig, err := p.container.LoadConfig(func(typeName string) any {
		v1Type := reflect.TypeFor[config.PersistentConfigV1]()
		v1TypeName := v1Type.PkgPath() + "/" + v1Type.Name()

		if typeName == v1TypeName {
			return &config.PersistentConfigV1{}
		}

		return nil
	})

	if err != nil || persistentConfig == nil {
		return certmanager.State{}
	}

	persisted := persistentConfig.(*config.PersistentConfigV1)

	return certmanager.State{
		AccountPrivateKeyPEM: persisted.AccountPrivateKeyPEM,
		RegistrationURI:      persisted.RegistrationURI,
		CertificatePEM:       persisted.CertificatePEM,
		CertificateKeyPEM:    persisted.CertificateKeyPEM,
		IssuedAt:             persisted.IssuedAt,
		NotAfter:             persisted.NotAfter,
	}
}

// Start makes one attempt to obtain a certificate synchronously - so that, so long as it
// succeeds, the HTTP server (which only starts listening once every plugin has finished
// starting) never begins serving TLS without a certificate in hand - then starts a
// background loop that keeps the certificate renewed. If the initial attempt fails, it's
// logged and left to the background loop to keep retrying rather than blocking startup
// forever; GetCertificate errors out any handshake that arrives before it succeeds.
func (p *plugin) Start() {
	if err := p.obtainAndPersist(); err != nil {
		fmt.Printf("%T initial certificate acquisition failed, will keep retrying in the background: %v\n", p, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	p.cancelFn = cancel
	p.workersWg.Go(func() { p.renewalLoop(ctx) })
}

func (p *plugin) Stop() chan func() {
	p.cancelFn()
	callbackCh := make(chan func())

	go func() {
		p.workersWg.Wait()
		close(callbackCh)
	}()

	return callbackCh
}

func (p *plugin) renewalLoop(ctx context.Context) {
	for {
		interval := p.renewalCheckInterval()
		if p.certManager.NeedsRenewal() {
			interval = p.renewalRetryInterval()
		}

		timer := time.NewTimer(interval)

		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		if err := p.obtainAndPersist(); err != nil {
			fmt.Printf("%T certificate renewal attempt failed, will retry: %v\n", p, err)
		}
	}
}

func (p *plugin) renewalCheckInterval() time.Duration {
	if p.config.RenewalCheckInterval > 0 {
		return p.config.RenewalCheckInterval
	}

	return defaultRenewalCheckInterval
}

func (p *plugin) renewalRetryInterval() time.Duration {
	if p.config.RenewalRetryInterval > 0 {
		return p.config.RenewalRetryInterval
	}

	return defaultRenewalRetryInterval
}

// obtainAndPersist asks the certificate manager to (re)obtain a certificate if needed, then
// persists its current state regardless of whether a new certificate was actually issued -
// registering the ACME account can itself change persistable state (the registration URI)
// even on a call where certificate issuance goes on to fail.
func (p *plugin) obtainAndPersist() error {
	ensureErr := p.certManager.EnsureCertificate()

	state := p.certManager.State()
	saveErr := p.container.SaveConfig(config.PersistentConfigV1{
		AccountPrivateKeyPEM: state.AccountPrivateKeyPEM,
		RegistrationURI:      state.RegistrationURI,
		CertificatePEM:       state.CertificatePEM,
		CertificateKeyPEM:    state.CertificateKeyPEM,
		IssuedAt:             state.IssuedAt,
		NotAfter:             state.NotAfter,
	})

	if saveErr != nil {
		fmt.Printf("%T failed to persist certificate state: %v\n", p, saveErr)
	}

	return ensureErr
}
