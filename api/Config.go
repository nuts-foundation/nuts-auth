package api

import (
	"github.com/sirupsen/logrus"
	"net/url"
)

type Config struct {
	Port          int
	IrmaClientUrl url.URL
	Logger        *logrus.Logger
}
