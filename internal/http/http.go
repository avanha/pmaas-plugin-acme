package http

import (
	"embed"
	"fmt"
	"net/http"
	"reflect"

	"github.com/avanha/pmaas-plugin-acme/data"
	spi "github.com/avanha/pmaas-spi"
)

//go:embed content/static content/templates
var contentFS embed.FS

var statusTemplate = spi.TemplateInfo{
	Name:   "acme_status",
	Paths:  []string{"templates/acme_status.htmlt"},
	Styles: []string{"css/acme_status.css"},
}

// StatusProvider is implemented by the plugin itself, to keep this package from depending on
// it directly (which would be an import cycle, since the plugin package depends on this one).
type StatusProvider interface {
	GetStatus() data.PluginStatus
}

type Handler struct {
	container spi.IPMAASContainer
	status    StatusProvider
}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) Init(container spi.IPMAASContainer, status StatusProvider) {
	h.container = container
	h.status = status
	container.ProvideContentFS(&contentFS, "content")
	container.EnableStaticContent("static")
	container.AddRoute("", h.handleHttpStatusRequest)
	container.RegisterEntityRenderer(
		reflect.TypeOf((*data.PluginStatus)(nil)).Elem(),
		h.statusDataRendererFactory)
}

func (h *Handler) handleHttpStatusRequest(writer http.ResponseWriter, request *http.Request) {
	status := h.status.GetStatus()

	h.container.RenderList(
		writer,
		request,
		spi.RenderListOptions{
			Title:  "acme",
			Header: &status,
		},
		[]interface{}{})
}

func (h *Handler) statusDataRendererFactory() (spi.EntityRenderer, error) {
	return spi.TemplateBasedRendererFactory(
		h.container,
		&statusTemplate,
		func(entity any) bool {
			_, ok := entity.(*data.PluginStatus)
			return ok
		},
		fmt.Sprintf("%T", (*data.PluginStatus)(nil)))
}
