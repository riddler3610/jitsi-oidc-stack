#!/usr/bin/env bash

function generatePassword() {
    openssl rand -hex 16
}

function generateAppId() {
    openssl rand -hex 8
}

function generateAppSecret() {
    openssl rand -hex 32
}

JWT_APP_ID=$(generateAppId)
JWT_APP_SECRET=$(generateAppSecret)
JICOFO_AUTH_PASSWORD=$(generatePassword)
JVB_AUTH_PASSWORD=$(generatePassword)
JIGASI_XMPP_PASSWORD=$(generatePassword)
JIBRI_RECORDER_PASSWORD=$(generatePassword)
JIBRI_XMPP_PASSWORD=$(generatePassword)
JIGASI_TRANSCRIBER_PASSWORD=$(generatePassword)

sed -i.bak \
    -e "s#JWT_APP_ID=.*#JWT_APP_ID=${JWT_APP_ID}#g" \
    -e "s#JWT_APP_SECRET=.*#JWT_APP_SECRET=${JWT_APP_SECRET}#g" \
    -e "s#JICOFO_AUTH_PASSWORD=.*#JICOFO_AUTH_PASSWORD=${JICOFO_AUTH_PASSWORD}#g" \
    -e "s#JVB_AUTH_PASSWORD=.*#JVB_AUTH_PASSWORD=${JVB_AUTH_PASSWORD}#g" \
    -e "s#JIGASI_XMPP_PASSWORD=.*#JIGASI_XMPP_PASSWORD=${JIGASI_XMPP_PASSWORD}#g" \
    -e "s#JIBRI_RECORDER_PASSWORD=.*#JIBRI_RECORDER_PASSWORD=${JIBRI_RECORDER_PASSWORD}#g" \
    -e "s#JIBRI_XMPP_PASSWORD=.*#JIBRI_XMPP_PASSWORD=${JIBRI_XMPP_PASSWORD}#g" \
    -e "s#JIGASI_TRANSCRIBER_PASSWORD=.*#JIGASI_TRANSCRIBER_PASSWORD=${JIGASI_TRANSCRIBER_PASSWORD}#g" \
    "$(dirname "$0")/.env"
