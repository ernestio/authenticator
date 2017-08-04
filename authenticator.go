/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package authenticator

import (
	"errors"
)

type Credentials map[string]interface{}

type Authenticator struct {
	Providers []string
}

func (a *Authenticator) Authenticate(c Credentials) error {
	var err error

	for _, provider := range a.Providers {
		err = a.auth(provider, c)
		if err == nil {
			break
		}
	}

	if err != nil {
		return errors.New("Authentication failed")
	}

	// check if user exists in user store
	// u, err := getUser(c["username"])
	// if err != nil {
	// 	return err
	// }

	// if u == nil {
	// 	// create user
	// }

	return err
}

func (a *Authenticator) auth(provider string, c Credentials) error {
	switch provider {
	case "local":
		return a.authLocal(c)
	case "fake":
		return a.authFake(c)
	default:
		return errors.New("Unknown provider type")
	}
}

func (a *Authenticator) authLocal(c Credentials) error {
	// remove
	if c["username"] == "john" {
		return nil
	} else {
		return errors.New("User not found")
	}
}

func (a *Authenticator) authFake(c Credentials) error {
	// remove
	return errors.New("User not found")
}
