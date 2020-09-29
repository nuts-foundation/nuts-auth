package pkg

// JwtBearerGrantType defines the grant-type to use in the access token request
const JwtBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// AuthConfig holds all the configuration params
type AuthConfig struct {
	Mode string
	// Address to bind the http server to. Default localhost:1323
	Address                   string
	PublicUrl                 string
	IrmaConfigPath            string
	IrmaSchemeManager         string
	SkipAutoUpdateIrmaSchemas bool
	ActingPartyCn             string
	EnableCORS                bool
	GenerateOAuthKeys         bool
	OAuthSigningKey           string
}
