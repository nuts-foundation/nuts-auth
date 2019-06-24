package pkg

import "sync"

const ConfAddress = "address"

type Auth struct {
	Config     AuthConfig
	configOnce sync.Once
	configDone bool
}

type AuthConfig struct {
	// TODO: Add config params
	Address string
}

var instance *Auth
var oneBackend sync.Once

func AuthInstance() *Auth {
	oneBackend.Do(func() {
		instance = &Auth{
			Config: AuthConfig{
				// TODO: add default values
			},
		}
	})

	return instance
}

func (auth *Auth) Configure() (err error) {
	auth.configOnce.Do(func() {

		// TODO: Add more initialization here

		auth.configDone = true
	})

	return err
}
