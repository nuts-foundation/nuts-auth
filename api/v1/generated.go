// Package v1 provides primitives to interact the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen DO NOT EDIT.
package v1

import (
	"fmt"
	"net/http"

	"github.com/deepmap/oapi-codegen/pkg/runtime"
	"github.com/labstack/echo/v4"
	externalRef0 "github.com/nuts-foundation/nuts-auth/api"
)

// VerifyAccessTokenV1Params defines parameters for VerifyAccessTokenV1.
type VerifyAccessTokenV1Params struct {
	Authorization string `json:"Authorization"`
}

// DrawUpContractV1JSONBody defines parameters for DrawUpContractV1.
type DrawUpContractV1JSONBody externalRef0.DrawUpContractRequest

// GetContractTemplateV1Params defines parameters for GetContractTemplateV1.
type GetContractTemplateV1Params struct {

	// The version of this contract. If omitted, the most recent version will be returned
	Version *string `json:"version,omitempty"`
}

// CreateSignSessionV1JSONBody defines parameters for CreateSignSessionV1.
type CreateSignSessionV1JSONBody externalRef0.CreateSignSessionRequest

// VerifySignatureV1JSONBody defines parameters for VerifySignatureV1.
type VerifySignatureV1JSONBody externalRef0.SignatureVerificationRequest

// DrawUpContractV1RequestBody defines body for DrawUpContractV1 for application/json ContentType.
type DrawUpContractV1JSONRequestBody DrawUpContractV1JSONBody

// CreateSignSessionV1RequestBody defines body for CreateSignSessionV1 for application/json ContentType.
type CreateSignSessionV1JSONRequestBody CreateSignSessionV1JSONBody

// VerifySignatureV1RequestBody defines body for VerifySignatureV1 for application/json ContentType.
type VerifySignatureV1JSONRequestBody VerifySignatureV1JSONBody

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Verifies the access token given in the Authorization header (as bearer token). If it's a valid access token issued by this server, it'll return a 200 status code.
	// If it cannot be verified it'll return 403. Note that it'll not return the contents of the access token. The introspection API is for that.
	// (HEAD /internal/auth/v1/accesstoken/verify)
	VerifyAccessTokenV1(ctx echo.Context, params VerifyAccessTokenV1Params) error
	// Draw up a contract using a specified contract template, language and version
	// (PUT /internal/auth/v1/contract/drawup)
	DrawUpContractV1(ctx echo.Context) error
	// Get the contract template by version, and type
	// (GET /internal/auth/v1/contract/template/{language}/{contractType})
	GetContractTemplateV1(ctx echo.Context, language string, contractType string, params GetContractTemplateV1Params) error
	// Create a signing session for a supported means.
	// (POST /internal/auth/v1/signature/session)
	CreateSignSessionV1(ctx echo.Context) error
	// Get the current status of a signing session
	// (GET /internal/auth/v1/signature/session/{sessionPtr})
	GetSignSessionStatusV1(ctx echo.Context, sessionPtr string) error
	// Verify a signature in the form of a verifiable credential
	// (PUT /internal/auth/v1/signature/verify)
	VerifySignatureV1(ctx echo.Context) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// VerifyAccessTokenV1 converts echo context to params.
func (w *ServerInterfaceWrapper) VerifyAccessTokenV1(ctx echo.Context) error {
	var err error

	// Parameter object where we will unmarshal all parameters from the context
	var params VerifyAccessTokenV1Params

	headers := ctx.Request().Header
	// ------------- Required header parameter "Authorization" -------------
	if valueList, found := headers[http.CanonicalHeaderKey("Authorization")]; found {
		var Authorization string
		n := len(valueList)
		if n != 1 {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Expected one value for Authorization, got %d", n))
		}

		err = runtime.BindStyledParameter("simple", false, "Authorization", valueList[0], &Authorization)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter Authorization: %s", err))
		}

		params.Authorization = Authorization
	} else {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Header parameter Authorization is required, but not found"))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.VerifyAccessTokenV1(ctx, params)
	return err
}

// DrawUpContractV1 converts echo context to params.
func (w *ServerInterfaceWrapper) DrawUpContractV1(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.DrawUpContractV1(ctx)
	return err
}

// GetContractTemplateV1 converts echo context to params.
func (w *ServerInterfaceWrapper) GetContractTemplateV1(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "language" -------------
	var language string

	err = runtime.BindStyledParameter("simple", false, "language", ctx.Param("language"), &language)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter language: %s", err))
	}

	// ------------- Path parameter "contractType" -------------
	var contractType string

	err = runtime.BindStyledParameter("simple", false, "contractType", ctx.Param("contractType"), &contractType)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter contractType: %s", err))
	}

	// Parameter object where we will unmarshal all parameters from the context
	var params GetContractTemplateV1Params
	// ------------- Optional query parameter "version" -------------

	err = runtime.BindQueryParameter("form", true, false, "version", ctx.QueryParams(), &params.Version)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter version: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.GetContractTemplateV1(ctx, language, contractType, params)
	return err
}

// CreateSignSessionV1 converts echo context to params.
func (w *ServerInterfaceWrapper) CreateSignSessionV1(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.CreateSignSessionV1(ctx)
	return err
}

// GetSignSessionStatusV1 converts echo context to params.
func (w *ServerInterfaceWrapper) GetSignSessionStatusV1(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "sessionPtr" -------------
	var sessionPtr string

	err = runtime.BindStyledParameter("simple", false, "sessionPtr", ctx.Param("sessionPtr"), &sessionPtr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter sessionPtr: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.GetSignSessionStatusV1(ctx, sessionPtr)
	return err
}

// VerifySignatureV1 converts echo context to params.
func (w *ServerInterfaceWrapper) VerifySignatureV1(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.VerifySignatureV1(ctx)
	return err
}

// This is a simple interface which specifies echo.Route addition functions which
// are present on both echo.Echo and echo.Group, since we want to allow using
// either of them for path registration
type EchoRouter interface {
	CONNECT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	DELETE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	GET(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	HEAD(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	OPTIONS(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PATCH(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	POST(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PUT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	TRACE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
}

// RegisterHandlers adds each server route to the EchoRouter.
func RegisterHandlers(router EchoRouter, si ServerInterface) {
	RegisterHandlersWithBaseURL(router, si, "")
}

// Registers handlers, and prepends BaseURL to the paths, so that the paths
// can be served under a prefix.
func RegisterHandlersWithBaseURL(router EchoRouter, si ServerInterface, baseURL string) {

	wrapper := ServerInterfaceWrapper{
		Handler: si,
	}

	router.HEAD(baseURL+"/internal/auth/v1/accesstoken/verify", wrapper.VerifyAccessTokenV1)
	router.PUT(baseURL+"/internal/auth/v1/contract/drawup", wrapper.DrawUpContractV1)
	router.GET(baseURL+"/internal/auth/v1/contract/template/:language/:contractType", wrapper.GetContractTemplateV1)
	router.POST(baseURL+"/internal/auth/v1/signature/session", wrapper.CreateSignSessionV1)
	router.GET(baseURL+"/internal/auth/v1/signature/session/:sessionPtr", wrapper.GetSignSessionStatusV1)
	router.PUT(baseURL+"/internal/auth/v1/signature/verify", wrapper.VerifySignatureV1)

}

