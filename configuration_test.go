package main

import (
	"reflect"
	"testing"
)

func TestConfiguration(t *testing.T) {
	type testValues struct {
		Name     string
		Expected interface{}
	}

	testValue := func(t *testing.T, config *NutsProxyConfiguration, test *testValues) {
		t.Helper()

		r := reflect.ValueOf(config)
		got := reflect.Indirect(r).FieldByName(test.Name)

		if test.Expected != got.Interface() {
			t.Errorf("config.%s has the wrong value. Expected: %v, got %v", test.Name, test.Expected, got)
		}

	}
	t.Run("load from file", func(t *testing.T) {
		var config NutsProxyConfiguration

		if err := config.LoadFromFile("./testdata/", "testconfig"); err != nil {
			t.Errorf("Could not load value from file: %v", err)
		}

		for _, v := range []*testValues{
			{"HttpPort", 3001},
			{"HttpAddress", "https://nuts.helder.health"},
			{"IrmaConfigPath", "/etc/nuts/irma"},
		} {
			testValue(t, &config, v)
		}
	})

	t.Run("test defaults", func(t *testing.T) {
		var config NutsProxyConfiguration

		config.SetDefaults()

		for _, v := range []*testValues{
			{"HttpPort", 3000},
			{"HttpAddress", "localhost:3000"},
			{"IrmaConfigPath", "."},
		} {
			testValue(t, &config, v)
		}

	})

}
