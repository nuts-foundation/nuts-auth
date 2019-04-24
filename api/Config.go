package api

import (
	"github.com/sirupsen/logrus"
	"net/url"
)

type Config struct {
	Port    int
	BaseUrl *url.URL
	Logger  *logrus.Logger
}
