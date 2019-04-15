# inspired by this blog post: https://le-gall.bzh/post/makefile-based-ci-chain-for-go/
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
DEP_ENSURE=dep ensure

BINARY_NAME=nuts_service_proxy

SHELL := $(shell which bash) # set default shell
# OS / Arch we will build our binaries for
OSARCH := "linux/amd64 linux/386 windows/amd64 windows/386 darwin/amd64 darwin/386"
ENV = /usr/bin/env

.SHELLFLAGS = -c # Run commands in a -c flag
.SILENT: ;
.ONESHELL: ;
.NOTPARALLEL: ;
.EXPORT_ALL_VARIABLES: ; # send all vars to shell
.PHONY: all # All targets are accessible for user
.DEFAULT: help # Running Make will run the help target

help: ## Show Help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

all: dep test build

dep: ## Get build dependencies
	go get -v -u github.com/golang/dep/cmd/dep

build: ## Build the app
	$(DEP_ENSURE) && $(GOBUILD) -o $(BINARY_NAME)

test: ## Run tests
	$(GOTEST) ./...

clean: ## Remove all produced artifacts
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
