// Package auth provides API handlers for all authentication related operations
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi"
	"github.com/nuts-foundation/nuts-auth/auth"
	"github.com/nuts-foundation/nuts-auth/configuration"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"time"
)

type API struct {
	contractValidator      auth.ContractValidator
	contractSessionHandler auth.ContractSessionHandler
	configuration          *configuration.NutsProxyConfiguration
}

func New(config *configuration.NutsProxyConfiguration, validator auth.ContractValidator, handler auth.ContractSessionHandler) *API {
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
		r.Post("/session", api.CreateSessionHandler)
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
	sessionId := auth.SessionId(chi.URLParam(r, "sessionId"))
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

// CreateSessionHandler Initiates an IRMA signing session with the correct correct.
// It reads auth.ContractSigningRequest from the body and writes auth.CreateSessionResult to the response
func (api API) CreateSessionHandler(writer http.ResponseWriter, r *http.Request) {
	var sessionRequest ContractSigningRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&sessionRequest); err != nil {
		logMsg := fmt.Sprintf("Could not decode json request parameters %v", r.Body)
		logrus.Info(logMsg)
		http.Error(writer, logMsg, http.StatusBadRequest)
		return
	}
	contract := auth.ContractByType(sessionRequest.Type, sessionRequest.Language, sessionRequest.Version)
	if contract == nil {
		logMsg := fmt.Sprintf("Could not find contract with type %v", sessionRequest.Type)
		logrus.Info(logMsg)
		http.Error(writer, logMsg, http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	actingParty, ok := ctx.Value(ActingPartyKey).(string)
	if !ok {
		// This should not happen since the context provides us with the value and does its own error handling
		http.Error(writer, http.StatusText(422), 422)
		return
	}

	message, err := contract.RenderTemplate(map[string]string{
		"acting_party": actingParty,
	}, 0, 60*time.Minute)
	logrus.Infof("contractMessage: %v", message)
	if err != nil {
		logMsg := fmt.Sprintf("Could not render contract template of type %v: %v", contract.Type, err)
		logrus.Error(logMsg)
		http.Error(writer, logMsg, http.StatusBadRequest)
		return
	}
	// TODO: put this in a separate service
	signatureRequest := &irma.SignatureRequest{
		Message: message,
		DisclosureRequest: irma.DisclosureRequest{
			BaseRequest: irma.BaseRequest{
				Type: irma.ActionSigning,
			},
			Content: irma.AttributeDisjunctionList([]*irma.AttributeDisjunction{{
				Label:      "AGB-Code",
				Attributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier(contract.SignerAttributes[0])},
			}}),
		},
	}

	sessionPointer, token, err := api.contractSessionHandler.StartSession(signatureRequest, func(result *server.SessionResult) {
		logrus.Infof("session done, result: %s", server.ToJson(result))
	})
	if err != nil {
		logrus.Panic("error while creating session: ", err)
		http.Error(writer, "Could not create a new session", http.StatusInternalServerError)
	}

	logrus.Infof("session created with token: %s", token)

	//jsonSessionPointer, _ := json.Marshal(sessionPointer)
	createSessionResult := CreateSessionResult{
		QrCodeInfo: *sessionPointer,
		SessionId:  token,
	}
	createSessionResultJson, _ := json.Marshal(createSessionResult)
	writer.WriteHeader(http.StatusCreated)
	_, err = writer.Write(createSessionResultJson)
	if err != nil {
		logrus.Panicf("Write failed: %v", err)
	}
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
	var validationResponse *auth.ValidationResponse

	if validationRequest.ContractFormat == "irma" {
		validationResponse, err = api.contractValidator.ValidateContract(validationRequest.ContractString, auth.ContractFormat(validationRequest.ContractFormat), validationRequest.ActingPartyCN)
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
