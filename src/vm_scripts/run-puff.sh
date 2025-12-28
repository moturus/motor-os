#!/bin/sh

WD="$(dirname $0)"

cd "$WD"

puff -c puff-vm.toml

