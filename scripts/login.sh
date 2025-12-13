#!/bin/bash

source ./config.sh

URL=${HOST}/identity/connect/token

curl -sS -X POST $URL \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        -d "grant_type=client_credentials&scope=api&client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&device_identifier=1&device_name=ok&device_type=1"
