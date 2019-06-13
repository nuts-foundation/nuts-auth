package api

import (
	"context"
	"fmt"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/cors"
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
	addr := fmt.Sprintf(":%d", api.config.Port)
	api.server = &http.Server{Addr: addr, Handler: api.router}

	return api
}

// Router sets up the Api with a stack of middleware and a basic rootHandler
// Every request has a requestID
// Panics get recovered and logged
// Json is the default content type
func (api *API) Router() *chi.Mux {
	// configure the router
	r := chi.NewRouter()

	// Basic CORS
	// TODO: make this a option
	// for more ideas, see: https://developer.github.com/v3/#cross-origin-resource-sharing
	cors := cors.New(cors.Options{
		// AllowedOrigins: []string{"https://foo.com"}, // Use this to allow specific origin hosts
		AllowedOrigins:   []string{"*"},
		// AllowOriginFunc:  func(r *http.Request, origin string) bool { return true },
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	})
	r.Use(cors.Handler)

	r.Use(middleware.RequestID)
	r.Use(newStructuredLogger(api.config.Logger))
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
