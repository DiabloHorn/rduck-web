# rduck-web

A simple project to remotely query duckdb databases via HTTP to quickly access them using mTLS and perform raw SQL queries. Mainly to understand vibe coding better as well as learn some more golang.

## Features
* expose a `/query?sql=` endpoint
* expose a minimal web application on `/`
* protect all access with mTLS
* generate ca, server & 10 client certs on first run
  * load existing certs if present
* revoke client certs

# Building
You can build the binary with:  
* `go build -o rduck-web cmd/rduck-web/main.go`

# Running
You can it on the specified DuckDB database with:  
* `./rduck-web <duckdb_location.db>`

# Setting up client access
Since we implement mTLS we need to provide the client with the right cryptographic material.

## Browser access
To be able to access the minimal web application you need to setup the browser by importing the CA certificate and the client certificate, private key that you provide to your user.

The CA certificate can be found in:
* `./certs/root/ca.crt`

The client material can be exported as follow, whereby the client number is a number between 1 and 10:
* `./export-client.sh <client number>`

Then just provide the `client_<client number>.p12` file that was created together with the CA certificate to your client.

After they import the cryptographic material into their browser or operating system they should be able to access the minimal web application.

## CLI access
for example if you want to just send SQL statements and get NDJSON results, you can use the `/query?sql=` endpoint. For example with curl:

```
curl -v \
  --cacert ./certs/root/ca.crt \
  --cert ./certs/clients/client_cert_1.crt \
  --key ./certs/clients/client_certpk_1.key \
  --get \
  --data-urlencode "sql=show tables" \
  "https://localhost:8443/query"
```

You can also execute the provided example script, provided the `certs` folder exist, like this `./example-curl.sh`.

# Revoking client access
It can happen that one of your sort of trusted parties needs their access revoked. You can use the following steps for this:

* Get client certificate serial number `./revoke-client.sh <client number>`
* Update `./certs/revoked.txt` with the **decimal** output of the previous step
* Restart the server

# Exposing to the internet
Since this is mainly intended to learn some golang, play with AI and vibe coding, there are hard coded items. For example for the certificate generation `localhost` is hardcoded. Which means that if you expose this, you need to update it to the domain that you use.

Also, **do review** the code before exposting to the internet.  

# Security
Minimal effort has been invested in the security aspect of this project, since it is mostly intended for learning purposes as well as use it with sort of trusted parties.  
The main security features is the implementation of mTLS functionality.

Basically use at your **own risk**.