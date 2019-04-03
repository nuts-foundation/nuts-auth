package auth

import (
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/sirupsen/logrus"
	"net/http"
	"time"
)

type API struct {
}

func (api API) InitIRMA() {
	configuration := &server.Configuration{
		//TODO: Make IRMA client URL a config variable
		URL:    "https://d7ca041d.ngrok.io/auth/irmaclient",
		Logger: logrus.StandardLogger(),
	}

	logrus.Info("Initializing IRMA library...")
	if err := irmaserver.Initialize(configuration); err != nil {
		logrus.Panic("Could not initialize IRMA library:", err)
	}
}

func New() *API {
	api := &API{}
	api.InitIRMA()
	return api
}

func (api API) AuthHandler() http.Handler {
	r := chi.NewRouter()
	r.Post("/contract/session", api.CreateSessionHandler)
	r.Get("/contract/{type}", api.GetContractHandler)
	r.Mount("/irmaclient", irmaserver.HandlerFunc())
	return r
}

func (api API) GetContractHandler(writer http.ResponseWriter, request *http.Request) {
	contractType := chi.URLParam(request, "type")
	contract := ContractByType(contractType, "NL")
	contractJson, _ := json.Marshal(contract)
	_, _ = writer.Write(contractJson)
}

func (api API) CreateSessionHandler(writer http.ResponseWriter, r *http.Request) {
	var sessionRequest ContractSigningRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&sessionRequest); err != nil {
		logMsg := fmt.Sprintf("Could not decode json request parameters %v", r.Body)
		logrus.Info(logMsg)
		http.Error(writer, logMsg, http.StatusBadRequest)
		return
	}
	contract := ContractByType(sessionRequest.Type, sessionRequest.Language)
	if contract == nil {
		logMsg := fmt.Sprintf("Could not find contract with type %v", sessionRequest.Type)
		logrus.Info(logMsg)
		http.Error(writer, logMsg, http.StatusBadRequest)
		return
	}
	message, err := contract.renderTemplate(map[string]string{"acting_party": "Helder", "valid_from": time.Now().Format(time.RFC850), "valid_to": time.Now().Add(time.Minute * 60).Format(time.RFC850)})
	logrus.Infof("contractMessage: %v", message)
	if err != nil {
		logMsg := fmt.Sprintf("Could not render contract template of type %v: %v", contract.Type, err)
		logrus.Error(logMsg)
		http.Error(writer, logMsg, http.StatusBadRequest)
		return
	}
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

	sessionPointer, token, err := irmaserver.StartSession(signatureRequest, func(result *server.SessionResult) {
		logrus.Infof("session done, result: %s", server.ToJson(result))
	})

	if err != nil {
		logrus.Panic("error while creating session: ", err)
	}

	logrus.Infof("session created with token: %s", token)

	jsonSessionPointer, _ := json.Marshal(sessionPointer)
	writer.WriteHeader(http.StatusCreated)
	_, err = writer.Write(jsonSessionPointer)
	if err != nil {
		logrus.Panicf("Write failed: %v", err)
	}
}
