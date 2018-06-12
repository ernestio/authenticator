/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"os"
	"runtime"

	"github.com/ernestio/authenticator/pkg/authenticator"
	ecc "github.com/ernestio/ernest-config-client"
	"github.com/nats-io/go-nats"
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
		panic("Unable to set JWT secret")
	}

	// Authenticator
	auth = &authenticator.Authenticator{
		Conn:   nc,
		Secret: secret,
	}
	err := ec.GetConfig("authenticator", &auth)
	if err != nil {
		panic(err)
	}

	_, err = nc.Subscribe("authentication.get", authenticationGetHandler)
	if err != nil {
		panic(err)
	}

	_, err = nc.Subscribe("config.set.authenticator", getConfig)
	if err != nil {
		panic(err)
	}

	runtime.Goexit()
}
