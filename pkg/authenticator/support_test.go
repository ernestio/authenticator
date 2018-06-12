/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package authenticator

import (
	"encoding/json"
	"time"

	"github.com/nats-io/go-nats"
)

type FakeConnector struct {
	Events map[string][]*nats.Msg
}

func NewFakeConnector() *FakeConnector {
	return &FakeConnector{
		Events: make(map[string][]*nats.Msg),
	}
}

func (f *FakeConnector) Request(subj string, data []byte, timeout time.Duration) (*nats.Msg, error) {
	f.Events[subj] = append(f.Events[subj], &nats.Msg{Subject: subj, Data: data})

	switch subj {
	case "federation.auth":
		return federationAuth(data)
	case "user.get":
		return userGet(data)
	case "user.set":
		return userSet(data)
	case "mfa.auth":
		return mfaAuth(data)
	default:
		return &nats.Msg{Data: []byte(`{"ok": false, "message": "Unknown subject type"}`)}, nil
	}
}

func testSetup() (*Authenticator, *FakeConnector) {
	auth := Authenticator{
		Conn:      NewFakeConnector(),
		Secret:    "secret",
		Providers: Providers{Provider{Type: "local"}, Provider{Type: "federation"}},
	}

	return &auth, auth.Conn.(*FakeConnector)
}

func federationAuth(data []byte) (*nats.Msg, error) {
	var u User

	err := json.Unmarshal(data, &u)
	if err != nil {
		return &nats.Msg{Data: []byte(`{"ok": false, "message": "Could not load credentials"}`)}, nil
	}

	switch {
	case u.Username == "valid-federation-new-user" && u.Password == "secret":
		return &nats.Msg{Data: []byte(`{"ok": true, "admin": false}`)}, nil
	case u.Username == "valid-federation-new-admin-user" && u.Password == "secret":
		return &nats.Msg{Data: []byte(`{"ok": true, "admin": true}`)}, nil
	case u.Username == "valid-federation-existing-user" && u.Password == "secret":
		return &nats.Msg{Data: []byte(`{"ok": true, "admin": false}`)}, nil
	case u.Username == "valid-federation-existing-admin-user" && u.Password == "secret":
		return &nats.Msg{Data: []byte(`{"ok": true, "admin": true}`)}, nil
	default:
		return &nats.Msg{Data: []byte(`{"ok": false, "message": "Authentication Failed"}`)}, nil
	}
}

func userGet(data []byte) (*nats.Msg, error) {
	var u User

	err := json.Unmarshal(data, &u)
	if err != nil {
		return &nats.Msg{Data: []byte(`{"_error": "Not found", "_code": "404"}`)}, nil
	}

	if u.Username == "valid-local-user" {
		return &nats.Msg{Data: []byte(`{"id": 1, "username": "valid-local-user", "password": "Jy7mfxUKTb2GtL+tFWQ6iXHh14SSMU7OhaAtZhrkaIUZPFhxi6CYryTIRAN2W7BCnfpWUxsVcLcqAEFcQXYzng==", "salt": "cU1rR2JBeWJTVExRQWhCQVhNN3p1aVNVdkluMkZ4VEtGb05FU3prZFRPUT0="}`)}, nil
	}

	if u.Username == "valid-federation-existing-user" {
		return &nats.Msg{Data: []byte(`{"id": 1, "username": "valid-federation-existing-user", "password": ""}`)}, nil
	}

	return &nats.Msg{Data: []byte(`{"_error": "Not found", "_code": "404"}`)}, nil
}

func userSet(data []byte) (*nats.Msg, error) {
	var u User

	err := json.Unmarshal(data, &u)
	if err != nil {
		return &nats.Msg{Data: []byte(`{"id": 0}`)}, nil
	}

	return &nats.Msg{Data: []byte(`{"username": "` + u.Username + `"}`)}, nil
}

func mfaAuth(data []byte) (*nats.Msg, error) {
	var c Credentials

	err := json.Unmarshal(data, &c)
	if err != nil {
		return nil, err
	}

	if c.Username == "john" && c.VerificationCode == "secret" {
		return &nats.Msg{Data: []byte(`{"ok": true}`)}, nil
	}

	return &nats.Msg{Data: []byte(`{"ok": false, "message": "verification failed"}`)}, nil
}
