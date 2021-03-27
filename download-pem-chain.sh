#!/bin/bash

#
# This script downloads a certificate chain for given CAS service. This chain may be used for server verification.
# The certificates in PEM format are dumped to stdout. Messages and other output is dumped to stderr.
#
# Usage: ./download-pem-chain.sh [ <CAS-server-domain> [ <port> ] ]
# If no domain is specified, the script attempts to load it from config/config.yaml
# If no port is specified, 443 (HTTPS) is used.
#

HOST="$1"
PORT="$2"

cd `dirname "$0"` || exit 242


if [[ "$HOST" == "" ]]; then
	if [[ ! -f './config/config.yaml' ]]; then
		>&2 echo "No host given and config.yaml does not exist."
		exit 1
	fi
	
	HOST=`grep 'server:' './config/config.yaml' | sed -E 's/^\s*server:\s*["]?//' | sed -E 's/["]\s*$//' | tr -d "'"`
	if [[ "$HOST" == "" ]]; then
		>&2 echo "No host name specified in config.yaml"
		exit 1
	fi
fi

if [[ "$PORT" == "" ]]; then
	PORT=443
fi

>&2 echo "Downloading chain from $HOST:$PORT ..."

CERTS=`openssl s_client -showcerts -connect "$HOST:$PORT" <<< ''`
RES=$?
if [[ $RES != 0 ]]; then
	>&2 echo "Certificate chain download failed ($RES)."
	exit $RES;
fi

echo "$CERTS" | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'
exit 0

#echo -n | openssl s_client -showcerts -connect "$HOST" | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'
#echo -n | openssl s_client -connect "$HOST" | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'
