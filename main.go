package main

import (
	"log"
	"os"
	"runtime"
	"time"

	"github.com/ernestio/authenticator/authenticator"
	ecc "github.com/ernestio/ernest-config-client"
	"github.com/nats-io/nats"
)

var (
	nc   *nats.Conn
	ec   *ecc.Config
	auth *authenticator.Authenticator
)

func main() {
	// NATS
	ec = ecc.NewConfig(os.Getenv("NATS_URI"))
	nc = ec.Nats()

	// JWT
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Println("Unable to set JWT secret")
	}

	// Authenticator
	auth = &authenticator.Authenticator{
		Conn:   nc,
		Secret: secret,
		Expiry: 24 * time.Hour,
	}
	err := ec.GetConfig("authenticator", &auth)
	if err != nil {
		log.Println(err)
	}

	_, err = nc.Subscribe("authentication.get", authenticationGetHandler)
	if err != nil {
		log.Println("Unable to subscribe to NATS 'authentication.get'")
	}

	runtime.Goexit()
}
