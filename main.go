package main

import (
	"github.com/nuts-foundation/nuts-proxy/cmd"
	"github.com/sirupsen/logrus"
	"os"
)

func main() {
	logrus.SetOutput(os.Stdout)
	logrus.SetFormatter(&logrus.TextFormatter{
		DisableColors: false,
		ForceColors:   true,
	})
	cmd.Execute()
}
