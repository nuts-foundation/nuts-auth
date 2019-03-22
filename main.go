package main

import (
	"github.com/nuts-foundation/nuts-proxy/cmd"
	"log"
	"os"
	"os/signal"
	"syscall"
)


func main() {


	// Handle ctrl-c and allow for cleanup
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Print("Shutting down...")
		os.Exit(0)
	}()

	cmd.Execute()
}
