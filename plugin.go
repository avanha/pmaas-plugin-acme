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

type plugin struct {
	config      config.PluginConfig
	container   spi.IPMAASContainer
	certManager *certmanager.Manager
	httpHandler *http.Handler

	cancelFn  context.CancelFunc
	workersWg sync.WaitGroup

	// registrationURI/commonName/refreshedTime/expiresTime/lastErrorMessage/lastErrorTime are
	// for status-page display (see GetStatus). They're updated only via
	// onCertificateStateChanged/onCertificateError, which always run on this plugin's own
	// mailbox goroutine (see Init/handleCertificateStateChanged/recordError), so reading them
	// safely requires going through that same goroutine too - see getStatus.
	registrationURI  string
	commonName       string
	refreshedTime    time.Time
	expiresTime      time.Time
	lastErrorMessage string
	lastErrorTime    time.Time
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

	persisted := p.loadPersistedState()
	p.registrationURI = persisted.RegistrationURI
	p.commonName = certmanager.ParseCommonName(persisted.CertificatePEM)
	p.refreshedTime = persisted.IssuedAt
	p.expiresTime = persisted.NotAfter

	certManager, err := certmanager.NewManager(certmanager.Config{
		Domains:                   p.config.Domains,
		Email:                     p.config.Email,
		DirectoryURL:              p.config.DirectoryURL,
		RenewBeforeExpiry:         p.config.RenewBeforeExpiry,
		RenewalCheckInterval:      p.config.RenewalCheckInterval,
		RenewalRetryInterval:      p.config.RenewalRetryInterval,
		PorkbunAPIKey:             p.config.Porkbun.ApiKey,
		PorkbunAPISecret:          p.config.Porkbun.ApiSecret,
		PorkbunPropagationTimeout: p.config.Porkbun.PropagationTimeout,
		PorkbunPollingInterval:    p.config.Porkbun.PollingInterval,
		InitialState:              persisted,
		OnStateChanged:            p.onCertificateStateChanged,
		OnError:                   p.onCertificateError,
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

func (p *plugin) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancelFn = cancel
	p.workersWg.Go(func() { p.certManager.Run(ctx) })
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

// onCertificateStateChanged is certManager's OnStateChanged callback (see Init): called from its
// own background goroutine (see Start) whenever the ACME registration and/or certificate
// changes, mirroring how pmaas-plugin-nestthermostat's poller reports data it fetches back to
// its plugin via callback.
func (p *plugin) onCertificateStateChanged(state certmanager.State) {
	err := p.container.EnqueueOnPluginGoRoutine(func() { p.handleCertificateStateChanged(state) })

	if err != nil {
		fmt.Printf("%T Failed to enqueue certificate state update: %v\n", p, err)
	}
}

// handleCertificateStateChanged updates status-page state and persists it. Runs on the plugin's
// own mailbox goroutine (see onCertificateStateChanged).
func (p *plugin) handleCertificateStateChanged(state certmanager.State) {
	p.registrationURI = state.RegistrationURI
	p.commonName = state.CommonName
	p.refreshedTime = state.IssuedAt
	p.expiresTime = state.NotAfter

	err := p.container.SaveConfig(config.PersistentConfigV1{
		AccountPrivateKeyPEM: state.AccountPrivateKeyPEM,
		RegistrationURI:      state.RegistrationURI,
		CertificatePEM:       state.CertificatePEM,
		CertificateKeyPEM:    state.CertificateKeyPEM,
		IssuedAt:             state.IssuedAt,
		NotAfter:             state.NotAfter,
	})

	if err != nil {
		fmt.Printf("%T failed to persist certificate state: %v\n", p, err)
	}
}

// onCertificateError is certManager's OnError callback (see Init): called from its own
// background goroutine (see Start) whenever registering the account or obtaining/renewing the
// certificate fails.
func (p *plugin) onCertificateError(certErr error) {
	err := p.container.EnqueueOnPluginGoRoutine(func() { p.recordError(certErr) })

	if err != nil {
		fmt.Printf("%T Failed to enqueue certificate error (%v): %v\n", p, certErr, err)
	}
}

// recordError records err as the plugin's most recent error, for status-page display. Runs on
// the plugin's own mailbox goroutine (see onCertificateError).
func (p *plugin) recordError(err error) {
	p.lastErrorMessage = err.Error()
	p.lastErrorTime = time.Now()
	fmt.Printf("%T Error: %v\n", p, err)
}

// GetStatus implements internal/http.StatusProvider, for the plugin's status page. HTTP
// requests come in on arbitrary goroutines, so it reads status fields on the plugin's own
// mailbox goroutine to get them all atomically.
func (p *plugin) GetStatus() (data.PluginStatus, error) {
	return spi.ExecValueFunctionOnPluginGoRoutine(
		p.container,
		p.getStatus,
		func() data.PluginStatus { return data.PluginStatus{} },
		"unable to get status")
}

func (p *plugin) getStatus() data.PluginStatus {
	return data.PluginStatus{
		Domains:          p.config.Domains,
		Email:            p.config.Email,
		RegistrationURI:  p.registrationURI,
		CommonName:       p.commonName,
		RefreshedTime:    p.refreshedTime,
		ExpiresTime:      p.expiresTime,
		LastErrorMessage: p.lastErrorMessage,
		LastErrorTime:    p.lastErrorTime,
	}
}
