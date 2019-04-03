package api

import (
	"context"
	"fmt"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/nuts-foundation/nuts-proxy/api/auth"
	"github.com/sirupsen/logrus"
	"net/http"
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

	if err := api.server.ListenAndServe(); err != nil {
		logrus.Panicf("Could not start server: %s", err)
	}
}

func (api *API) Shutdown(context context.Context) error {
	logrus.Info("Shutting down the server")
	return api.server.Shutdown(context)
}

func New(config *Config) *API {

	api := &API{
		config: config,
	}

	// configure the router
	api.router = chi.NewRouter()
	api.router.Use(middleware.RequestID)
	api.router.Use(NewStructuredLogger(api.config.Logger))
	api.router.Use(ContentTypeMiddleware)
	api.router.Get("/", func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte("Welcome Nuts proxy!!"))
	})

	api.router.Mount("/auth", auth.New().AuthHandler())

	return api
}

func ContentTypeMiddleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}
