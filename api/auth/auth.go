// Package auth provides API handlers for all authentication related operations
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi"
	"github.com/nuts-foundation/nuts-auth/auth"
	"github.com/nuts-foundation/nuts-auth/configuration"
	"github.com/nuts-foundation/nuts-auth/pkg"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"time"
)

type API struct {
	contractValidator      pkg.ContractValidator
	contractSessionHandler pkg.ContractSessionHandler
	configuration          *configuration.NutsProxyConfiguration
}

func New(config *configuration.NutsProxyConfiguration, validator pkg.ContractValidator, handler pkg.ContractSessionHandler) *API {
	api := &API{
		contractValidator:      validator,
		contractSessionHandler: handler,
		configuration:          config,
	}
	return api
}

func (api API) Handler() http.Handler {
	r := chi.NewRouter()
	r.Route("/contract", func(r chi.Router) {
		r.Use(ServiceProviderCtxFn(api.configuration))
		r.Get("/session/{sessionId}", api.GetSessionStatusHandler)
		r.Get("/{type}", api.GetContractHandler)
	})
	r.Post("/contract/validate", api.ValidateContractHandler)
	return r
}

// ActingPartyKey is the key that holds the common name of the current acting party in the request context.
const ActingPartyKey = "actingParty"

// ServiceProviderCtxFn returns the middleware that puts the acting party from the config into the http context.
// In every http handler it can be used like this:
//  func (api API) FooHandler(writer http.ResponseWriter, r *http.Request) {
//	  ctx := r.Context()
//	  actingParty, ok := ctx.Value(ActingPartyKey).(string)
//  }
func ServiceProviderCtxFn(config *configuration.NutsProxyConfiguration) func(http.Handler) http.Handler {
	actingParty := config.ActingPartyCN

	return func(next http.Handler) http.Handler {

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if actingParty == "" {
				http.Error(w, "Unknown acting party", http.StatusForbidden)
				return
			}
			ctx := context.WithValue(r.Context(), ActingPartyKey, actingParty)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (api API) GetSessionStatusHandler(writer http.ResponseWriter, r *http.Request) {
	sessionId := pkg.SessionId(chi.URLParam(r, "sessionId"))
	sessionResult := api.contractSessionHandler.SessionStatus(sessionId)
	if sessionResult == nil {
		http.Error(writer, "Session not found", http.StatusNotFound)
		return
	}
	statusJson, _ := json.Marshal(sessionResult)
	logrus.Info("statusJson:", statusJson)
	_, _ = writer.Write(statusJson)
}

func (api API) GetContractHandler(writer http.ResponseWriter, request *http.Request) {
	contractType := auth.Type(chi.URLParam(request, "type"))

	contractLanguage := auth.Language(request.URL.Query().Get("language"))
	if contractLanguage == "" {
		contractLanguage = auth.Language("NL")
	}

	contractVersion := auth.Version(request.URL.Query().Get("version"))

	contract := auth.ContractByType(contractType, contractLanguage, contractVersion)
	if contract == nil {
		http.Error(writer, "could not find contract with this type, language and version", http.StatusNotFound)
		return
	}
	contractJson, _ := json.Marshal(contract)
	_, _ = writer.Write(contractJson)
}


func (api API) ValidateContractHandler(writer http.ResponseWriter, r *http.Request) {
	var validationRequest ValidationRequest

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logrus.WithError(err).Error("Could not validate contract. Unable to read body")
		http.Error(writer, "Could not read body", http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(body, &validationRequest); err != nil {
		logMsg := fmt.Sprint("Could not decode json payload")
		logrus.WithError(err).Info(logMsg)
		http.Error(writer, logMsg, http.StatusBadRequest)
		return
	}
	logrus.Debug(validationRequest)
	var validationResponse *pkg.ValidationResponse

	if validationRequest.ContractFormat == "irma" {
		validationResponse, err = api.contractValidator.ValidateContract(validationRequest.ContractString, pkg.ContractFormat(validationRequest.ContractFormat), validationRequest.ActingPartyCN)
	} else if validationRequest.ContractFormat == "jwt" {
		validationResponse, err = api.contractValidator.ValidateJwt(validationRequest.ContractString, validationRequest.ActingPartyCN)
	}

	if err != nil {
		//logMsg := "Unable to verify contract"
		logrus.WithError(err).Info(err.Error())
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	jsonResult, err := json.Marshal(validationResponse)
	if err != nil {
		logrus.WithError(err).Error("Could not marshall json response in ValidateContractHandler")
	}
	_, _ = writer.Write(jsonResult)
}
