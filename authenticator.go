/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package authenticator

import (
	"encoding/json"
	"errors"
	"time"
)

var ErrUnauthorized = errors.New("Authentication failed")

type AuthResponse struct {
	Ok bool `json:"ok"`
}

type Credentials map[string]interface{}

type Authenticator struct {
	Conn      Connector
	Providers []string
}

func New(providers []string) *Authenticator {
	return &Authenticator{
		Providers: providers,
	}
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
		return ErrUnauthorized
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
	case "local", "fake":
		return a.authGeneric(provider, c)
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

func (a *Authenticator) authGeneric(provider string, c Credentials) error {
	var ar AuthResponse

	data, err := json.Marshal(c)
	if err != nil {
		return err
	}

	resp, err := a.Conn.Request(provider+".auth", data, time.Second)
	if err != nil {
		return err
	}

	err = json.Unmarshal(resp.Data, &ar)
	if err != nil {
		return err
	}

	if !ar.Ok {
		return errors.New("authentication failed!")
	}

	return nil
}
