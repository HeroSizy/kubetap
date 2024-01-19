#!/bin/sh

set -o errexit
set -o nounset

# HACK: this fixes permission issues
cp /home/mitmproxy/config/config.yaml /home/mitmproxy/.mitmproxy/config.yaml

prog=${1}
if [ "$prog" = 'mitmdump' ] || [ "$prog" = 'mitmproxy' ] || [ "$prog" = 'mitmweb' ]; then
  MITMPROXY_PATH='/home/mitmproxy/.mitmproxy'
  exec "${@}" --set "confdir=${MITMPROXY_PATH}"
else
  exec "${@}"
fi