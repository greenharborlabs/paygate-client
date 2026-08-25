#!/usr/bin/env sh
set -eu

exec /usr/bin/protoc --experimental_allow_proto3_optional "$@"
