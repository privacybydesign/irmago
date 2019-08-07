#!/usr/bin/env bash
set -euxo pipefail

dir=$(cd -P -- "$(dirname -- "$0")" && pwd -P)

rm -rf ${dir}/irma_configuration_invalid/*
rm -rf ${dir}/irma_configuration_updated/*

cp -r ${dir}/irma_configuration/irma-demo ${dir}/irma_configuration_invalid/
cp -r ${dir}/irma_configuration/irma-demo ${dir}/irma_configuration_updated/

irma scheme sign ${dir}/irma_configuration/irma-demo/sk.pem ${dir}/irma_configuration/irma-demo

# ensure the changed schemes receive a higher timestamp
sleep 1

# restore changes to studentCard credtype, then resign
git checkout -- ${dir}/irma_configuration_updated/irma-demo/RU/Issues/studentCard/description.xml
irma scheme sign ${dir}/irma_configuration/irma-demo/sk.pem ${dir}/irma_configuration_updated/irma-demo

# resign, then restore changes to studentCard credtype, invalidating the scheme
irma scheme sign ${dir}/irma_configuration/irma-demo/sk.pem ${dir}/irma_configuration_invalid/irma-demo
git checkout -- ${dir}/irma_configuration_invalid/irma-demo/RU/Issues/studentCard/description.xml
