#!/bin/bash

source ./config.sh

API_URL=${HOST}/api/sync

TOKEN=$(./login.sh | jq -r .access_token)

curl -sS -X GET $API_URL -H "Authorization: Bearer $TOKEN"
