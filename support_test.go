package authenticator

import (
	"encoding/json"
	"fmt"
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
	case "fake.auth":
		return fakeAuth(data)
	case "user.get":
		return userGet(data)
	case "user.create":
		return userCreate(data)
	default:
		return &nats.Msg{Data: []byte(`{"ok": false, "message": "Unknown subject type"}`)}, nil
	}
}

func fakeAuth(data []byte) (*nats.Msg, error) {
	var c Credentials

	err := json.Unmarshal(data, &c)
	if err != nil {
		return &nats.Msg{Data: []byte(`{"ok": false, "message": "Could not load credentials"}`)}, nil
	}

	if c["username"] == "john" && c["password"] == "secret" ||
		c["username"] == "jane" && c["password"] == "secret" {
		return &nats.Msg{Data: []byte(`{"ok": true, "token": "xxxx"}`)}, nil
	}

	return &nats.Msg{Data: []byte(`{"ok": false, "message": "Authentication Failed"}`)}, nil
}

func userGet(data []byte) (*nats.Msg, error) {
	var u User

	err := json.Unmarshal(data, &u)
	if err != nil {
		return &nats.Msg{Data: []byte(`{"_error": "Not found", "_code": "404"}`)}, nil
	}

	if u.Username == "john" {
		return &nats.Msg{Data: []byte(`{"username": "john", "password": "xxxx"}`)}, nil
	}

	return &nats.Msg{Data: []byte(`{"_error": "Not found", "_code": "404"}`)}, nil
}

func userCreate(data []byte) (*nats.Msg, error) {
	var u User

	err := json.Unmarshal(data, &u)
	if err != nil {
		return &nats.Msg{Data: []byte(`{"id": 0}`)}, nil
	}

	msg := fmt.Sprintf("{\"username\": \"%s\"}", u.Username)
	return &nats.Msg{Data: []byte(msg)}, nil
}
