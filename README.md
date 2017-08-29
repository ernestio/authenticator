# Authenticator

[![CircleCI](https://circleci.com/gh/ernestio/authenticator.svg?style=shield)](https://circleci.com/gh/ernestio/authenticator)

Authenticator provides authentication services for the Ernest application.

## Installation

```
go get github.com/ernestio/authenticator
```

## Example

### Configuration (config.json)

```
{
  "authenticator": {
    "providers": [
      {
        "type": "local"
      },
      {
        "type": "federation",
        "config": {
          "url": "https://federation.example.com",
          "scope": "https://ernest.example.com"
        }
      }
    ]
  }
}
```

### Request

```
nats.Request("authentication.get", []byte(`{"username": "john", "password": "secret"}`), time.Second)
```

### Response

Successful
```
{
  "ok": true,
  "token": "xxxx"
}
```

Unsuccessful
```
{
  "ok": false,
  "message": "Authentication failed"
}
```
