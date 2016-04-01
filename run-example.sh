#!/bin/sh

export LISTEN=127.0.0.1:1500
export PUBLIC_URL=http://exampls.com/
export IDP_METADATA_URL=https://example-idp.com/app/VWjJo6aBvCWTFGeI8oVT5cENCrWIvoW4/sso/saml/metadata
export SESSION_EXPIRE_AFTER=600
export SESSION_MEMCACHE_SERVERS=127.0.0.1:11211
export AUTHENTICATION_REQUIRED=no
export ATTRIBUTES=email:mail:s:login::s:groups::m
export CERTIFICATE=/etc/nginx/saml/sp.crt
export PRIVATE_KEY=/etc/nginx/saml/sp.key
export SLO_DISABLED=yes

./nginx_saml_authenticator
