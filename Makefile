install:
	go install -v

build:
	go build -v ./...

deps:
	go get github.com/nats-io/nats

dev-deps: deps
	go get github.com/stretchr/testify/suite
	go get github.com/alecthomas/gometalinter
	gometalinter --install

test:
	go test -v ./... -cover

lint:
	gometalinter --config .linter.conf

