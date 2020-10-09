package services

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-auth/pkg/contract"
)

type ExampleAuthenticationTokenService struct{}
type ExampleSignedToken struct {
	rawAuthToken string
}

var _ AuthenticationTokenService = (*ExampleAuthenticationTokenService)(nil)

func (e ExampleSignedToken) SignerAttributes() map[string]string {
	parts := strings.Split(e.rawAuthToken, ":")
	return map[string]string{parts[0]: parts[1]}
}

func (e ExampleSignedToken) Contract() contract.Contract {
	return contract.Contract{
		RawContractText: "",
		Template:        nil,
		Params:          nil,
	}
}

func (e ExampleAuthenticationTokenService) Parse(rawAuthToken string) (SignedToken, error) {
	data, err := base64.StdEncoding.DecodeString(rawAuthToken)
	if err != nil {
		return nil, err
	}
	signedToken := ExampleSignedToken{rawAuthToken: string(data)}
	return signedToken, nil
}

func (e ExampleAuthenticationTokenService) Verify(token SignedToken) error {
	panic("implement me")
}

func (e ExampleAuthenticationTokenService) Encode(token SignedToken) (string, error) {
	attrs := token.SignerAttributes()
	var res string
	for key, val := range attrs {
		res = res + strings.Join([]string{key, val}, ":")
	}
	return base64.StdEncoding.EncodeToString([]byte(res)), nil
}

func TestExampleAuthenticationTokenService_Parse(t *testing.T) {
	token := "foo:bar"
	rawToken := base64.StdEncoding.EncodeToString([]byte(token))

	tokenService := ExampleAuthenticationTokenService{}
	signedToken, err := tokenService.Parse(rawToken)
	assert.NoError(t, err)
	assert.Equal(t, signedToken.SignerAttributes(), map[string]string{"foo": "bar"})

	tokenString, err := tokenService.Encode(signedToken)
	assert.NoError(t, err)
	assert.Equal(t, rawToken, tokenString)
}
