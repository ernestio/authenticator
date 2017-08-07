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

type UserResponse struct {
	Id int `json:"id"`
}

type Credentials map[string]interface{}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

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

	// check if user exists
	var ur UserResponse

	data, err = json.Marhsal(c)
	if err != nil {
		return err
	}

	resp, err := a.Conn.Request("user.get", data, time.Second)
	if err != nil {
		return err
	}

	json.Unmarshal(resp.Data, &ur)
	if err != nil {
		return err
	}

	// create user if missing
	if ur.Id == 0 {
		resp, err := a.Conn.Request("user.set", data, time.Second)
		if err != nil {
			return err
		}
	}

	return err
}

func (a *Authenticator) auth(provider string, c Credentials) error {
	var ar AuthResponse

	if !a.validProvider(provider) {
		return errors.New("unknown provider type")
	}

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
		return ErrUnauthorized
	}

	return nil
}

func (a *Authenticator) validProvider(provider string) bool {
	for _, p := range a.Providers {
		if p == provider {
			return true
		}
	}
	return false
}
