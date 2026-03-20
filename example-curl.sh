#!/usr/bin/env bash

curl -v \
  --cacert ./certs/root/ca.crt \
  --cert ./certs/clients/client_cert_1.crt \
  --key ./certs/clients/client_certpk_1.key \
  --get \
  --data-urlencode "sql=show tables" \
  "https://localhost:8443/query"