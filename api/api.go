package api

import (
	"context"
	"fmt"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/sirupsen/logrus"
	"net/http"
	"time"
)

type API struct {
	config *Config
	server *http.Server
	router *chi.Mux
}

func (api *API) Start() {
	logrus.Infof("starting with httpPort: %d", api.config.Port)

	addr := fmt.Sprintf(":%d", api.config.Port)
	api.server = &http.Server{Addr: addr, Handler: api.router}

	err := api.server.ListenAndServe() // blocks

	if err != http.ErrServerClosed {
		logrus.WithError(err).Error("Http server stopped unexpected")
	} else {
		logrus.WithError(err).Info("Http server stopped")
	}
}

func (api *API) Shutdown() {
	if api.server != nil {
		logrus.Info("Shutting down the server")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err := api.server.Shutdown(ctx); err != nil {
			logrus.WithError(err).Error("Failed to shutdown the server")

		}
		api.server = nil
	}
}

func New(config *Config) *API {

	api := &API{
		config: config,
	}

	api.router = api.Router()

	return api
}

// Router sets up the Api with a stack of middleware and a basic rootHandler
// Every request has a requestID
// Panics get recovered and logged
// Json is the default content type
func (api *API) Router() *chi.Mux {
	// configure the router
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(NewStructuredLogger(api.config.Logger))
	r.Use(middleware.Recoverer)
	r.Use(contentTypeMiddlewareFn("application/json"))
	r.Get("/", rootHandler)
	return r
}

func (api *API) Mount(pattern string, handler http.Handler) {
	api.router.Mount(pattern, handler)
}

func rootHandler(writer http.ResponseWriter, _ *http.Request) {
	_, _ = writer.Write([]byte("Welcome Nuts proxy!!"))
}

func contentTypeMiddlewareFn(contentType string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", contentType)
			next.ServeHTTP(w, r)
		}

		return http.HandlerFunc(fn)
	}
}
