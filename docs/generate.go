package main

import (
	"github.com/nuts-foundation/nuts-auth/engine"
	"github.com/nuts-foundation/nuts-go-core/docs"
)

func main() {
	docs.GenerateConfigOptionsDocs("README_options.rst", engine.NewAuthEngine().FlagSet)
}
