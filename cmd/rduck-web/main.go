// Package main implements rduck-web, a secure HTTP API for querying DuckDB databases.
// It provides mTLS-protected endpoints for SQL queries and a web interface.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	_ "github.com/duckdb/duckdb-go/v2"
)

var (
	// db is the connection pool to the read-only DuckDB database
	db *sql.DB
	// revokedSerials maps revoked certificate serial numbers to true for quick lookup
	revokedSerials = make(map[string]bool)
)

func main() {
	// Parse command-line arguments and validate database path
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./rduck-web <path_to_db_file>")
		os.Exit(1)
	}

	// Initialize PKI: generates or loads CA, server, and client certificates
	tlsConfig, err := setupPKI()
	if err != nil {
		log.Fatal(err)
	}

	dbPath := os.Args[1]
	// Open DuckDB with read-only mode and hardened runtime options.
	dsn := buildDuckDBDSN(dbPath)
	log.Printf("Loading database from: %s", dsn)
	db, err = sql.Open("duckdb", dsn)
	if err != nil {
		traceError(err)
	}
	if err := db.Ping(); err != nil {
		traceError(err)
	}
	if err := applyDuckDBHardening(db); err != nil {
		traceError(err)
	}
	defer db.Close()

	// Register HTTP handlers with mTLS-protected endpoints
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleUI)         // Minimal web UI for browser access
	mux.HandleFunc("/query", handleQuery) // SQL query endpoint returning NDJSON

	// Configure HTTPS server with mTLS certificate validation
	server := &http.Server{
		Addr:      "127.0.0.1:8443",
		Handler:   mux,
		TLSConfig: tlsConfig,
		// Basic transport-level hardening against slow-client/connection exhaustion.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MiB
	}

	log.Println("Server running on https://127.0.0.1:8443")
	log.Fatal(server.ListenAndServeTLS("", ""))

	/*
		plainserver := &http.Server{
			Addr: "127.0.0.1:8080",
		}

		log.Println("Server starting on :8080...")
		log.Fatal(plainserver.ListenAndServe())
	*/
}

// buildDuckDBDSN returns a DSN that applies a baseline security posture for untrusted SQL.
func buildDuckDBDSN(dbPath string) string {
	params := url.Values{}
	params.Set("access_mode", "read_only")
	params.Set("enable_external_access", "false")
	params.Set("autoload_known_extensions", "false")
	params.Set("autoinstall_known_extensions", "false")
	params.Set("allow_community_extensions", "false")
	params.Set("allow_unsigned_extensions", "false")

	return fmt.Sprintf("%s?%s", dbPath, params.Encode())
}

// applyDuckDBHardening locks configuration to avoid runtime weakening after startup.
func applyDuckDBHardening(db *sql.DB) error {
	_, err := db.Exec("SET lock_configuration = true")
	if err != nil {
		return fmt.Errorf("failed to lock DuckDB configuration: %w", err)
	}

	return nil
}

// traceError logs a fatal error with stack trace information (function name, file, line number)
// for better debugging. It only logs if err is not nil.
func traceError(err error) {
	if err != nil {
		pc, file, line, _ := runtime.Caller(1)
		fn := runtime.FuncForPC(pc).Name()
		log.Fatalf("CRITICAL ERROR in %s [%s:%d]: %v", fn, file, line, err)
	}
}

// setupPKI initializes the Public Key Infrastructure for mTLS.
// It generates CA, server, and client certificates on first run, or loads existing ones.
// It also loads the revocation list and configures certificate validation.
func setupPKI() (*tls.Config, error) {
	// Locate the certs directory relative to the binary location
	exePath, _ := os.Executable()
	baseDir := filepath.Dir(exePath)
	certDir := filepath.Join(baseDir, "certs")
	revocationFile := filepath.Join(certDir, "revoked.txt")

	// Generate all certificates if this is the first run
	if _, err := os.Stat(certDir); os.IsNotExist(err) {
		log.Println("Generating PKI in:", certDir)
		if err := generateAllCerts(certDir); err != nil {
			return nil, err
		}
		// Initialize empty revocation list file with instructions
		os.WriteFile(revocationFile, []byte("# Add serial numbers here to revoke (one per line)\n"), 0644)
	}

	// Load revoked certificate serial numbers into memory for fast validation lookups
	log.Printf("Loading revocation list from: %s", revocationFile)
	content, _ := os.ReadFile(revocationFile)
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		// Skip empty lines and comments
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			revokedSerials[trimmed] = true
		}
	}

	// Load CA certificate for client certificate verification
	log.Printf("Loading CA certificate from: %s", filepath.Join(certDir, "root", "ca.crt"))
	caCert, _ := os.ReadFile(filepath.Join(certDir, "root", "ca.crt"))
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Load server cert and key
	serverCertPath := filepath.Join(certDir, "server", "server.crt")
	serverKeyPath := filepath.Join(certDir, "server", "server.key")

	// Load the keypair into a tls.Certificate object
	serverCert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %v", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// Check the leaf certificate's serial number against our list
			for _, chain := range verifiedChains {
				serial := chain[0].SerialNumber.String()
				if revokedSerials[serial] {
					log.Printf("Rejected revoked certificate with serial: %s", serial)
					return fmt.Errorf("certificate %s has been revoked", serial)
				}
			}
			return nil
		},
	}, nil
}

// generateAllCerts creates the complete PKI: a root CA, one server certificate, and 10 client certificates.
// All certificates are stored in PEM format in the base directory structure.
func generateAllCerts(base string) error {
	os.MkdirAll(filepath.Join(base, "root"), 0755)
	os.MkdirAll(filepath.Join(base, "server"), 0755)
	os.MkdirAll(filepath.Join(base, "clients"), 0755)

	// 1. Generate Root Certificate Authority (CA)
	// The CA signs all other certificates and is trusted by clients for verification
	caPriv, _ := rsa.GenerateKey(rand.Reader, 4096)
	caserialLimit := new(big.Int).Lsh(big.NewInt(1), 128) // 128-bit limit
	caserial, err := rand.Int(rand.Reader, caserialLimit)
	if err != nil {
		return fmt.Errorf("failed to generate random serial: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          caserial,
		Subject:               pkix.Name{CommonName: "rduck-web-CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10-year validity
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caBytes, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caPriv.PublicKey, caPriv)
	savePEM(filepath.Join(base, "root", "ca.crt"), "CERTIFICATE", caBytes)
	saveKey(filepath.Join(base, "root", "ca.key"), caPriv)

	// 2. Generate Server Certificate
	// Used by the HTTPS server to prove its identity to clients
	srvPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	serverserialLimit := new(big.Int).Lsh(big.NewInt(1), 128) // 128-bit limit
	serverserial, err := rand.Int(rand.Reader, serverserialLimit)
	if err != nil {
		return fmt.Errorf("failed to generate random serial: %v", err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: serverserial,
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"}, // Note: hardcoded for localhost; change for production
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0), // 1-year validity
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	srvBytes, _ := x509.CreateCertificate(rand.Reader, srvTmpl, caTmpl, &srvPriv.PublicKey, caPriv)
	savePEM(filepath.Join(base, "server", "server.crt"), "CERTIFICATE", srvBytes)
	saveKey(filepath.Join(base, "server", "server.key"), srvPriv)

	// 3. Generate 10 Client Certificates
	// Each client certificate can be exported and distributed to users for mTLS authentication
	for i := 1; i <= 10; i++ {
		cPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
		serialLimit := new(big.Int).Lsh(big.NewInt(1), 128) // 128-bit limit
		serial, err := rand.Int(rand.Reader, serialLimit)
		if err != nil {
			return fmt.Errorf("failed to generate random serial: %v", err)
		}
		cTmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: fmt.Sprintf("client_%d", i)},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().AddDate(1, 0, 0), // 1-year validity
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		cBytes, _ := x509.CreateCertificate(rand.Reader, cTmpl, caTmpl, &cPriv.PublicKey, caPriv)

		certPath := filepath.Join(base, "clients", fmt.Sprintf("client_cert_%d.crt", i))
		keyPath := filepath.Join(base, "clients", fmt.Sprintf("client_certpk_%d.key", i))

		savePEM(certPath, "CERTIFICATE", cBytes)
		saveKey(keyPath, cPriv)

		log.Printf("Generated Client %d (Serial: %s)", i, serial.String())
	}
	return nil
}

// savePEM writes certificate bytes to a PEM-encoded file
func savePEM(path, t string, b []byte) {
	f, _ := os.Create(path)
	pem.Encode(f, &pem.Block{Type: t, Bytes: b})
}

// saveKey saves an RSA private key to a PEM-encoded file
func saveKey(path string, k *rsa.PrivateKey) {
	f, _ := os.Create(path)
	pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
}

// handleQuery executes SQL queries and streams results as newline-delimited JSON (NDJSON).
// This enables real-time result streaming for large result sets.
func handleQuery(w http.ResponseWriter, r *http.Request) {
	// Extract SQL query from URL parameter
	query := r.URL.Query().Get("sql")
	if query == "" {
		http.Error(w, "Missing 'sql' parameter", 400)
		return
	}

	// Execute the query with the request context for cancellation support
	rows, err := db.QueryContext(r.Context(), query)
	if err != nil {
		// Return SQL errors as a JSON error response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": err.Error(),
		})
		return
	}
	defer rows.Close()

	// Configure response for streaming NDJSON (one JSON object per line)
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)

	encoder := json.NewEncoder(w)
	cols, _ := rows.Columns()

	// Stream each result row as a JSON object
	for rows.Next() {
		// Use dynamic scanning into a map to handle arbitrary column types and counts
		columns := make([]interface{}, len(cols))
		columnPointers := make([]interface{}, len(cols))
		for i := range columns {
			columnPointers[i] = &columns[i]
		}

		if err := rows.Scan(columnPointers...); err != nil {
			return
		}

		// Build a map of column names to values
		m := make(map[string]interface{})
		for i, colName := range cols {
			m[colName] = columns[i]
		}

		// Immediately encode and flush each row for real-time streaming
		encoder.Encode(m)
		if f, ok := w.(http.Flusher); ok {
			f.Flush() // Push data to client immediately
		}
	}
}

// handleUI returns a minimal HTML/CSS/JavaScript web interface for querying DuckDB.
// It automatically loads the schema (tables and columns) in the sidebar and provides
// a SQL editor with live results.
// handleUI returns a minimal HTML/CSS/JavaScript web interface for querying DuckDB.
// It automatically loads the schema (tables and columns) in the sidebar and provides
// a SQL editor with live results.
func handleUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `
			<!DOCTYPE html>
			<html>
			<head>
				<title>DuckDB Explorer</title>
				<style>
					body { display: flex; height: 100vh; margin: 0; font-family: -apple-system, sans-serif; background: #f4f7f6; }
					#sidebar { width: 260px; background: #1e293b; color: #f8fafc; padding: 20px; overflow-y: auto; border-right: 1px solid #334155; }
					#main { flex: 1; display: flex; flex-direction: column; padding: 20px; overflow: hidden; }
					
					h3 { margin-top: 0; font-size: 14px; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8; border-bottom: 1px solid #334155; padding-bottom: 10px; }
					.table-group { margin-bottom: 15px; }
					.table-name { cursor: pointer; font-weight: 600; padding: 5px 0; display: block; color: #38bdf8; text-decoration: none; }
					.table-name:hover { color: #7dd3fc; }
					.column-name { font-size: 12px; color: #94a3b8; padding-left: 12px; margin-bottom: 2px; font-family: monospace; }

					textarea { width: 100%; height: 140px; padding: 12px; border: 1px solid #cbd5e1; border-radius: 6px; font-family: monospace; font-size: 14px; margin-bottom: 10px; box-sizing: border-box; resize: none; }
					button { background: #0ea5e9; color: white; border: none; padding: 10px 24px; border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 14px; }
					button:hover { background: #0284c7; }

					.results-container { flex: 1; overflow: auto; margin-top: 20px; background: white; border: 1px solid #e2e8f0; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
					table { border-collapse: collapse; width: 100%; font-size: 13px; }
					th { background: #f8fafc; position: sticky; top: 0; padding: 12px; text-align: left; border-bottom: 2px solid #e2e8f0; color: #475569; z-index: 10; }
					td { padding: 10px 12px; border-bottom: 1px solid #f1f5f9; color: #1e293b; white-space: nowrap; }
					tr:hover { background-color: #f8fafc; }
				</style>
			</head>
			<body>
				<div id="sidebar">
					<h3>User Tables</h3>
					<div id="schema-list">Loading...</div>
				</div>

				<div id="main">
					<textarea id="sql" placeholder="Enter SQL query..."></textarea>
					<div><button onclick="runQuery()">Run Query</button></div>
					<div id="error-container" style="color: #721c24; background-color: #f8d7da; border: 1px solid #f5c6cb; padding: 10px; display: none; margin-bottom: 10px; border-radius: 4px;">
						<strong>SQL Status:</strong> <span id="error-message"></span>
					</div>
					<div class="results-container">
						<table id="results">
							<thead id="thead"></thead>
							<tbody id="tbody"></tbody>
						</table>
					</div>
				</div>

				<script>
					async function loadSchema() {
						const list = document.getElementById('schema-list');
						try {
							// Filter for user tables in 'main' schema that are not internal
							const q = encodeURIComponent("SELECT table_name, column_name FROM duckdb_columns() WHERE schema_name = 'main' AND internal = false ORDER BY table_name, column_index");
							const resp = await fetch('/query?sql=' + q);
							const reader = resp.body.getReader();
							const decoder = new TextDecoder();
							let currentTable = "";
							let html = "";
							let buffer = "";

							while (true) {
								const { done, value } = await reader.read();
								if (done) break;
								buffer += decoder.decode(value);
								const lines = buffer.split("\n");
								buffer = lines.pop();

								lines.forEach(line => {
									if (!line.trim()) return;
									const row = JSON.parse(line);
									if (row.table_name !== currentTable) {
										currentTable = row.table_name;
										html += '<div class="table-group"><span class="table-name" onclick="setQuery(\''+currentTable+'\')">' + currentTable + '</span>';
									}
									html += '<div class="column-name">' + row.column_name + '</div>';
									if (lines.indexOf(line) === lines.length - 1) html += '</div>';
								});
							}
							list.innerHTML = html || "No user tables.";
						} catch (e) { list.innerHTML = "Error loading schema."; }
					}

					function setQuery(t) { document.getElementById('sql').value = "SELECT * FROM " + t + " LIMIT 100;"; }
					
					function showErrorMessage(msg) {
						const container = document.getElementById('error-container');
						const span = document.getElementById('error-message');
						
						span.textContent = msg;
						container.style.display = 'block';
					}

					async function runQuery() {
						const sql = document.getElementById('sql').value;
						const thead = document.getElementById('thead');
						const tbody = document.getElementById('tbody');
						thead.innerHTML = ""; tbody.innerHTML = "";
						
						let headersCreated = false;
						const resp = await fetch('/query?sql=' + encodeURIComponent(sql));
						if (!resp.ok) {
							const errorData = await resp.json();
							showErrorMessage(errorData.error); // Update a <div> on your page
							return;
						}
						
						// Success! Set the message to "OK" and the color to green
						showErrorMessage("SQL OK: If table empty, probably no results"); // Reusing the same text container
						document.getElementById('error-container').style.backgroundColor = '#d4edda';
						document.getElementById('error-container').style.color = '#155724';
						
						const reader = resp.body.getReader();
						const decoder = new TextDecoder();
						let buffer = "";

						while (true) {
							const { done, value } = await reader.read();
							if (done) break;
							buffer += decoder.decode(value);
							const lines = buffer.split("\n");
							buffer = lines.pop();

							for (const line of lines) {
								if (!line.trim()) continue;
								const row = JSON.parse(line);
								if (!headersCreated) {
									const hr = thead.insertRow();
									Object.keys(row).forEach(k => {
										const th = document.createElement('th');
										th.textContent = k;
										hr.appendChild(th);
									});
									headersCreated = true;
								}
								const r = tbody.insertRow();
								Object.values(row).forEach(v => {
									r.insertCell().textContent = v === null ? "NULL" : v;
								});
							}
						}
					}
					loadSchema();
				</script>
			</body>
			</html>
		`)
}
