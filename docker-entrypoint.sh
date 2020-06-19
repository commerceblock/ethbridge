#!/bin/bash
set -e

if [ -f /run/secrets/ocean_user ] && [ -f /run/secrets/ocean_pass ]; then
    creds=("--rpcuser=$(cat /run/secrets/ocean_user)" \
           "--rpcpassword=$(cat /run/secrets/ocean_pass)")
elif [ -f /run/secrets/ocean_pass ] && \
     [ -f /run/secrets/eth_priv_key ] && \
     [ -f /run/secrets/ocean_priv_key ] ; then
    creds=("--rpcpassword=$(cat /run/secrets/ocean_pass)" \
           "--ethkey=$(cat /run/secrets/eth_priv_key)" \
           "--oceankey=$(cat /run/secrets/ocean_priv_key)")
elif [ -f /run/secrets/ocean_pass ]; then
    creds=("--rpcpassword=$(cat /run/secrets/ocean_pass)")
fi

command="$@ ${creds[@]}"

bash -c "${command}"
