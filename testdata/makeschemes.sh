#!/usr/bin/env bash
set -euxo pipefail

dir=$(cd -P -- "$(dirname -- "$0")" && pwd -P)

rm -rf ${dir}/irma_configuration_invalid/irma-demo
rm -rf ${dir}/irma_configuration_updated/irma-demo
rm -rf ${dir}/irma_configuration_updated/test-requestors

cp -r ${dir}/irma_configuration/irma-demo ${dir}/irma_configuration_invalid/
cp -r ${dir}/irma_configuration/irma-demo ${dir}/irma_configuration_updated/
cp -r ${dir}/irma_configuration/test-requestors ${dir}/irma_configuration_updated/

irma scheme sign ${dir}/irma_configuration/irma-demo/sk.pem ${dir}/irma_configuration/irma-demo
irma scheme sign ${dir}/irma_configuration/test/sk.pem ${dir}/irma_configuration/test
irma scheme sign ${dir}/irma_configuration/test2/sk.pem ${dir}/irma_configuration/test2
irma scheme sign ${dir}/irma_configuration/test-requestors/sk.pem ${dir}/irma_configuration/test-requestors

# ensure the changed schemes receive a higher timestamp
sleep 1

# restore changes to studentCard and stempas credtype, then resign
git diff \
  HEAD:testdata/irma_configuration/irma-demo/RU/Issues/studentCard/description.xml \
  HEAD:testdata/irma_configuration_updated/irma-demo/RU/Issues/studentCard/description.xml \
   | git apply -p3 --directory "testdata/irma_configuration_updated"
git diff \
  HEAD:testdata/irma_configuration/irma-demo/stemmen/Issues/stempas/description.xml \
  HEAD:testdata/irma_configuration_updated/irma-demo/stemmen/Issues/stempas/description.xml \
   | git apply -p3 --directory "testdata/irma_configuration_updated"
irma scheme sign ${dir}/irma_configuration_updated/irma-demo/sk.pem ${dir}/irma_configuration_updated/irma-demo

# restore changes to requestor scheme, then resign
git diff \
  HEAD:testdata/irma_configuration/test-requestors/requestors.json \
  HEAD:testdata/irma_configuration_updated/test-requestors/requestors.json \
   | git apply -p3 --directory "testdata/irma_configuration_updated"
irma scheme sign ${dir}/irma_configuration_updated/test-requestors/sk.pem ${dir}/irma_configuration_updated/test-requestors

# resign, then restore changes to studentCard credtype, invalidating the scheme
irma scheme sign ${dir}/irma_configuration_invalid/irma-demo/sk.pem ${dir}/irma_configuration_invalid/irma-demo
git diff \
  HEAD:testdata/irma_configuration/irma-demo/RU/Issues/studentCard/description.xml \
  HEAD:testdata/irma_configuration_invalid/irma-demo/RU/Issues/studentCard/description.xml \
   | git apply -p3 --directory "testdata/irma_configuration_invalid"

