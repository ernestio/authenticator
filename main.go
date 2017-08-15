package main

import (
	"log"
	"os"
	"runtime"

	"github.com/ernestio/authenticator/authenticator"
	"github.com/ernestio/ernest-config-client"
	"github.com/nats-io/nats"
)

var (
	nc   *nats.Conn
	ec   *ernest_config_client.Config
	auth *authenticator.Authenticator
)

func main() {
	// NATS
	ec = ernest_config_client.NewConfig(os.Getenv("NATS_URI"))
	nc = ec.Nats()

	// JWT
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Println("Unable to set JWT secret")
	}

	// Authenticator
	auth = &authenticator.Authenticator{Conn: nc}
	err := ec.GetConfig("authenticator", &auth)
	if err != nil {
		log.Println(err)
	}

	_, err = nc.Subscribe("authentication.get", handler)
	if err != nil {
		log.Println("Unable to subscribe to NATS 'authentication.get'")
	}

	runtime.Goexit()
}
