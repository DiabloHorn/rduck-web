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

## ai first review of authenticated path

Scope and assumptions:
* this review only covers requests that already passed mTLS authentication
* full SQL is intentionally allowed
* clients are allowed to read any data in the opened DuckDB database

Basically use at your **own risk**.

Findings:
* ~~**High**: read-only database mode is not a full SQL sandbox.~~
  * ~~Opening DuckDB with `?access_mode=read_only` protects the DB file from writes, but may still allow SQL features that interact with host files, extensions, or network depending on DuckDB/runtime configuration.~~
* **Medium**: authenticated query-based denial of service is possible.
  * A valid client can submit computationally expensive queries with no explicit per-query timeout, result size limit, memory budget, or concurrency limit.
* **Medium**: `/query` accepts SQL via GET query string.
  * This can enable browser-based request triggering (CSRF-style workload abuse) and query leakage in browser history or intermediary logs.
* **Medium**: UI-side XSS risk if schema metadata is untrusted.
  * Table/column names are injected into HTML using `innerHTML`; if names are attacker-controlled, script injection in the authenticated browser session may be possible.

Recommended mitigations (while preserving full SQL intent):
* run this service in a strongly sandboxed environment (container/VM with minimal filesystem and no sensitive host access)
* configure DuckDB runtime hardening where possible (limit extension loading/network/file access)
* add server-side resource controls: query timeout, max rows streamed, concurrency caps, and memory limits
* move SQL submission to POST body for normal use (keep GET only if explicitly needed), and reduce logging of raw query strings
* avoid `innerHTML` for schema rendering in the UI; render via DOM APIs and `textContent`

### DuckDB hardening verification queries

Use the following SQL statements to verify each hardening measure at runtime.

* Verify active hardening settings (should return the expected values):

```sql
SELECT name, value
FROM duckdb_settings()
WHERE name IN (
  'access_mode',
  'enable_external_access',
  'autoload_known_extensions',
  'autoinstall_known_extensions',
  'allow_community_extensions',
  'allow_unsigned_extensions',
  'lock_configuration'
)
ORDER BY name;
```

Expected values:
* `access_mode = read_only`
* `enable_external_access = false`
* `autoload_known_extensions = false`
* `autoinstall_known_extensions = false`
* `allow_community_extensions = false`
* `allow_unsigned_extensions = false`
* `lock_configuration = true`

* Verify extension install is blocked (should fail):

```sql
INSTALL httpfs;
```

* Verify extension load is blocked unless built-in and permitted (should fail for unknown/not-available modules):

```sql
LOAD httpfs;
```

* Verify local file reads are blocked by external access hardening (should fail):

```sql
SELECT * FROM read_csv_auto('/etc/passwd') LIMIT 1;
```

* Verify network-based reads are blocked (should fail):

```sql
SELECT * FROM read_parquet('https://example.com/data.parquet') LIMIT 1;
```

* Verify configuration cannot be weakened at runtime (should fail):

```sql
SET enable_external_access = true;
```

* Verify normal query execution still works (should succeed):

```sql
SELECT 42 AS ok;
```
