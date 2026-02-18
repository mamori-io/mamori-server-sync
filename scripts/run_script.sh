#!/bin/sh

cd /app
source ./scripts/env.sh

yarn run ts-node ./scripts/$1
