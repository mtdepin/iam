PWD:=$(shell pwd)
GOPATH := $(shell go env GOPATH)
PKGNAME = mt-iam
VERSION=$(shell git describe --tags --always)
GO_LDFLAGS = $(patsubst %,-X $(PKGNAME)/cmd.%,$(METADATA_VAR))
# Builds mt-iam locally.
build:
	rm -rf mt-iam
	go build -ldflags "-X main.Version=$(VERSION)"

.PHONY: docker

# build
docker:
	go build -ldflags "-X main.Version=$(VERSION)"
	docker build  -t 192.168.1.214:443/iam/mt-iam:latest .