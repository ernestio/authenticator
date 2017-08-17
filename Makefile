pkgs = $(shell go list ./... | grep -v /vendor/)

#install:
#	go install -v

#build:
#	go build -v ./...

deps:
	dep ensure

test:
	go test -v -cover $(pkgs)

#lint:
#	gometalinter --config .linter.conf
