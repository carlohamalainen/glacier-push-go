#!/bin/bash

set -e
set -x

go build .
go build ./cmd/list-vault
