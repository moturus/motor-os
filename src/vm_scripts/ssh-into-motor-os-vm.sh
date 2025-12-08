#!/bin/bash

WD="$(dirname $0)"

ssh -p 2222 -o IdentitiesOnly=yes -i "$WD/test.key" motor@192.168.4.2

