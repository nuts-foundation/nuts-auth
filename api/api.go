package api

import (
	"context"
	"fmt"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/cors"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-auth/pkg"
	"github.com/sirupsen/logrus"
	"net/http"
	"time"
)

type ApiWrapper struct {
	config *Config
	server *http.Server
	router *chi.Mux
	Auth *pkg.Auth
}

func (api *ApiWrapper) NutsAuthCreateSession(ctx echo.Context) error {
	panic("implement me")
}

func (api *ApiWrapper) NutsAuthSessionRequestStatus(ctx echo.Context, id string) error {
	panic("implement me")
}

func (api *ApiWrapper) NutsAuthValidateContract(ctx echo.Context) error {
	panic("implement me")
}

func (api *ApiWrapper) NutsAuthGetContractByType(ctx echo.Context, contractType string, params NutsAuthGetContractByTypeParams) error {
	panic("implement me")
}

func (api *ApiWrapper) Start() {
	logrus.Infof("starting with httpPort: %d", api.config.Port)

	err := api.server.ListenAndServe() // blocks

	if err != http.ErrServerClosed {
		logrus.WithError(err).Error("Http server stopped unexpected")
	} else {
		logrus.WithError(err).Info("Http server stopped")
	}
}

func (api *ApiWrapper) Shutdown() {
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

func New(config *Config) *ApiWrapper {

	api := &ApiWrapper{
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
func (api *ApiWrapper) Router() *chi.Mux {
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

func (api *ApiWrapper) Mount(pattern string, handler http.Handler) {
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
