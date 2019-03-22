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
	"fmt"
	"github.com/go-chi/chi"
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
	Long: `Start the service proxy.`,
	Run: func(cmd *cobra.Command, args []string) {

		//httpPort := viper.Get("httpPort")
		log.Printf("starting with httpPort: %d", httpPort)

		r := chi.NewRouter()
		r.Get("/", func(writer http.ResponseWriter, request *http.Request) {
			writer.Write([]byte("Welcome"))
		})

		addr := fmt.Sprintf(":%d", httpPort)
		err := http.ListenAndServe(addr, r)
		if err != nil {
			log.Panicf("Could not start server: %s", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().IntVarP(&httpPort, "httpPort","p", DefaultHttpPort, "The port the http server should bind to")
}
