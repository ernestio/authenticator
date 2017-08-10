package authenticator

import (
	"encoding/json"
	"time"

	"github.com/nats-io/nats"
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
	default:
		return &nats.Msg{Data: []byte(`{"ok": false, "message": "Unknown subject type"}`)}, nil
	}
}

func federationAuth(data []byte) (*nats.Msg, error) {
	var u User

	err := json.Unmarshal(data, &u)
	if err != nil {
		return &nats.Msg{Data: []byte(`{"ok": false, "message": "Could not load credentials"}`)}, nil
	}

	if u.Username == "valid-federation-new-user" && u.Password == "secret" ||
		u.Username == "valid-federation-existing-user" && u.Password == "secret" {
		return &nats.Msg{Data: []byte(`{"ok": true}`)}, nil
	}

	return &nats.Msg{Data: []byte(`{"ok": false, "message": "Authentication Failed"}`)}, nil
}

func userGet(data []byte) (*nats.Msg, error) {
	var u User

	err := json.Unmarshal(data, &u)
	if err != nil {
		return &nats.Msg{Data: []byte(`{"_error": "Not found", "_code": "404"}`)}, nil
	}

	if u.Username == "valid-local-user" {
		return &nats.Msg{Data: []byte(`{"id": 1, "username": "valid-local-user", "password": "secret"}`)}, nil
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
