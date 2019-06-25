package api

import (
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-auth/pkg"
	"net/http"
)

type ApiWrapper struct {
	Auth *pkg.Auth
}

func (api *ApiWrapper) NutsAuthCreateSession(ctx echo.Context) (err error) {
	params := new(ContractSigningRequest)
	if err = ctx.Bind(params); err != nil {
		return
	}

	sessionRequest := pkg.ContractSigningRequest{
		Type: pkg.Type(params.Type),
		Version: pkg.Version(params.Version),
		Language: pkg.Language(params.Language),
		//ValidFrom: *params.ValidFrom,
		//ValidTo: *params.ValidTo,
	}

	actingParty := "Fixme: fetch acting party from config or http-session"

	result, err := api.Auth.CreateContractSession(sessionRequest, actingParty)
	if err != nil {
		return
	}

	return ctx.JSON(http.StatusCreated, result)
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

//func (api *ApiWrapper) Start() {
//	logrus.Infof("starting with httpPort: %d", api.config.Port)
//
//	err := api.server.ListenAndServe() // blocks
//
//	if err != http.ErrServerClosed {
//		logrus.WithError(err).Error("Http server stopped unexpected")
//	} else {
//		logrus.WithError(err).Info("Http server stopped")
//	}
//}
//
//func (api *ApiWrapper) Shutdown() {
//	if api.server != nil {
//		logrus.Info("Shutting down the server")
//		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
//		defer cancel()
//		if err := api.server.Shutdown(ctx); err != nil {
//			logrus.WithError(err).Error("Failed to shutdown the server")
//
//		}
//		api.server = nil
//	}
//}

//func New(config *Config) *ApiWrapper {
//
//	api := &ApiWrapper{
//		config: config,
//	}
//
//	api.router = api.Router()
//	addr := fmt.Sprintf(":%d", api.config.Port)
//	api.server = &http.Server{Addr: addr, Handler: api.router}
//
//	return api
//}

//// Router sets up the Api with a stack of middleware and a basic rootHandler
//// Every request has a requestID
//// Panics get recovered and logged
//// Json is the default content type
//func (api *ApiWrapper) Router() *chi.Mux {
//	// configure the router
//	r := chi.NewRouter()
//
//	// Basic CORS
//	// TODO: make this a option
//	// for more ideas, see: https://developer.github.com/v3/#cross-origin-resource-sharing
//	cors := cors.New(cors.Options{
//		// AllowedOrigins: []string{"https://foo.com"}, // Use this to allow specific origin hosts
//		AllowedOrigins:   []string{"*"},
//		// AllowOriginFunc:  func(r *http.Request, origin string) bool { return true },
//		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
//		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
//		ExposedHeaders:   []string{"Link"},
//		AllowCredentials: true,
//		MaxAge:           300, // Maximum value not ignored by any of major browsers
//	})
//	r.Use(cors.Handler)
//
//	r.Use(middleware.RequestID)
//	r.Use(newStructuredLogger(api.config.Logger))
//	r.Use(middleware.Recoverer)
//	r.Use(contentTypeMiddlewareFn("application/json"))
//	return r
//}

//func (api *ApiWrapper) Mount(pattern string, handler http.Handler) {
//	api.router.Mount(pattern, handler)
//}
//
//func contentTypeMiddlewareFn(contentType string) func(http.Handler) http.Handler {
//	return func(next http.Handler) http.Handler {
//		fn := func(w http.ResponseWriter, r *http.Request) {
//			w.Header().Set("Content-Type", contentType)
//			next.ServeHTTP(w, r)
//		}
//
//		return http.HandlerFunc(fn)
//	}
//}
