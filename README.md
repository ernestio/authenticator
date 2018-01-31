# Authenticator

master:  [![CircleCI](https://circleci.com/gh/ernestio/authenticator/tree/master.svg?style=shield)](https://circleci.com/gh/ernestio/authenticator/tree/master)  
develop: [![CircleCI](https://circleci.com/gh/ernestio/authenticator/tree/develop.svg?style=shield)](https://circleci.com/gh/ernestio/authenticator/tree/develop)

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
          "scope": "https://ernest.example.com",
          "domain": "CORP"
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

## Contributing

Please read through our
[contributing guidelines](CONTRIBUTING.md).
Included are directions for opening issues, coding standards, and notes on
development.

Moreover, if your pull request contains patches or features, you must include
relevant unit tests.

## Versioning

For transparency into our release cycle and in striving to maintain backward
compatibility, this project is maintained under [the Semantic Versioning guidelines](http://semver.org/).

## Copyright and License

Code and documentation copyright since 2015 ernest.io authors.

Code released under
[the Mozilla Public License Version 2.0](LICENSE).
