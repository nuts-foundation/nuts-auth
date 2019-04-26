package configuration

import (
	"reflect"
	"testing"
)

func TestGetInstance(t *testing.T) {
	t.Run("it panics when no instance is set", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected a panic")
			}
		}()

		GetInstance()
	})

	t.Run("returns the instance if set", func(t *testing.T) {
		config = &NutsProxyConfiguration{}

		instance := GetInstance()

		if instance != config {
			t.Errorf("expected intance to be the config intead of: %v", instance)
		}
	})

}

func TestInitialize(t *testing.T) {
	t.Run("it initializes the global config", func(t *testing.T) {
		err := Initialize("../testdata", "testconfig")
		if config == nil {
			t.Error("expected global config to be set")
		}
		if err != nil {
			t.Errorf("expected error to be nil instead of %v", err)
		}
	})

	t.Run("it throws an error on failure", func(t *testing.T) {
		err := Initialize("unknown", "path")
		if err == nil {
			t.Error("expected an error")
		}
	})
}

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

		if err := config.LoadFromFile("../testdata/", "testconfig"); err != nil {
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
