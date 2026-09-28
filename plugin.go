package acme

import spi "github.com/avanha/pmaas-spi"

type plugin struct {
	container spi.IPMAASContainer
}

func (p plugin) ShortName() string {
	return "acme"
}

func (p plugin) Init(container spi.IPMAASContainer) {
	p.container = container
}

func (p plugin) Start() {
}

func (p plugin) Stop() chan func() {
	return p.container.ClosedCallbackChannel()
}
