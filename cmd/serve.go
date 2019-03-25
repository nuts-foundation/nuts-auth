// Copyright © 2019 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"log"
	"net/http"

	"github.com/spf13/cobra"
)

const DefaultHttpPort = 3000

var httpPort int

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the service proxy",
	Long:  `Start the service proxy.`,
	Run: func(cmd *cobra.Command, args []string) {

		InitIRMA()

		//httpPort := viper.Get("httpPort")
		log.Printf("starting with httpPort: %d", httpPort)

		r := chi.NewRouter()
		r.Use(middleware.Logger)
		r.Get("/", func(writer http.ResponseWriter, request *http.Request) {
			writer.Write([]byte("Welcome"))
		})

		r.Post("/auth/contract/session", CreateSessionHandler)

		addr := fmt.Sprintf(":%d", httpPort)
		err := http.ListenAndServe(addr, r)
		if err != nil {
			log.Panicf("Could not start server: %s", err)
		}
	},
}

func InitIRMA()  {
	configuration := &server.Configuration{
		URL: "http://localhost:1234/irma",
	}

	log.Print("Initializing IRMA library...")
	if err := irmaserver.Initialize(configuration); err != nil {
		log.Panic("Could not initialize IRMA library:", err)
	}
}

func CreateSessionHandler(writer http.ResponseWriter, request *http.Request) {
	requestDefenition := `{
			"type": "disclosing",
			"content": [{ "label": "Full name", "attributes": [ "pbdf.nijmegen.personalData.fullname" ]}]
		}`

	sessionPointer, token, err := irmaserver.StartSession(requestDefenition, func(result *server.SessionResult) {
		log.Printf("session done, result: %s", server.ToJson(result))
	})

	if err != nil {
		log.Print("error while creating session: ", err)
	}

	log.Printf("session created with token: %s", token)

	jsonSessionPointer, _ := json.Marshal(sessionPointer)
	writer.WriteHeader(http.StatusCreated)
	_, err = writer.Write(jsonSessionPointer)
	if err != nil {
		log.Printf("Write failed: %v", err)
	}
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().IntVarP(&httpPort, "httpPort", "p", DefaultHttpPort, "The port the http server should bind to")
}
