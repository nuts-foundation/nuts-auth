package auth

import (
	"encoding/json"
	"github.com/go-chi/chi"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/sirupsen/logrus"
	"net/http"
)

type AuthAPI struct {
}

func (api AuthAPI) InitIRMA() {
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

func New() *AuthAPI {
	api := &AuthAPI{}
	api.InitIRMA()
	return api
}

func (api AuthAPI) AuthHandler() http.Handler {
	r := chi.NewRouter()
	r.Post("/contract/session", api.CreateSessionHandler)
	r.Get("/contract/{type}", api.GetContractHandler)
	r.Mount("/irmaclient", irmaserver.HandlerFunc())
	return r
}

func (api AuthAPI) GetContractHandler(writer http.ResponseWriter, request *http.Request) {
	contractType := chi.URLParam(request, "type")
	contract := ContractByType(contractType, "NL")
	contractJson, _ := json.Marshal(contract)
	writer.Write(contractJson)
}

func (api AuthAPI) CreateSessionHandler(writer http.ResponseWriter, _ *http.Request) {
	signatureRequest := &irma.SignatureRequest{
		Message: "Ga je akkoord?",
		DisclosureRequest: irma.DisclosureRequest{
			BaseRequest: irma.BaseRequest{
				Type: irma.ActionSigning,
			},
			Content: irma.AttributeDisjunctionList([]*irma.AttributeDisjunction{{
				Label:      "AGB-Code",
				Attributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier("irma-demo.nuts.agb.agbcode")},
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
