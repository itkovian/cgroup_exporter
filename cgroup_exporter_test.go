// Copyright 2020 Trey Dockendorf
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	kingpin "github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/exporter-toolkit/web"
	"golang.org/x/crypto/bcrypt"
)

// The cgroup v1 fixtures are generated from fixtures.ttar (see .circleci/config.yml
// and the release workflow) into ./fixtures, which is git ignored.

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
}

func TestMain(m *testing.M) {
	// Populates the defaults of all kingpin flags.
	if _, err := kingpin.CommandLine.Parse([]string{}); err != nil {
		fmt.Fprintln(os.Stderr, "failed to parse flags:", err)
		os.Exit(1)
	}
	_, filename, _, _ := runtime.Caller(0)
	fixture := filepath.Join(filepath.Dir(filename), "fixtures")
	if _, err := os.Stat(fixture); err != nil {
		fmt.Fprintln(os.Stderr, "fixtures not found, extract them first with: ./ttar -x -f fixtures.ttar")
		os.Exit(1)
	}
	cgroupRoot = &fixture
	varTrue := true
	disableExporterMetrics = &varTrue
	os.Exit(m.Run())
}

func TestParseCpuSet(t *testing.T) {
	expected := []string{"0", "1", "2"}
	if cpus, err := parseCpuSet("0-2"); err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	} else if !reflect.DeepEqual(cpus, expected) {
		t.Errorf("Unexpected cpus, expected %v got %v", expected, cpus)
	}
	expected = []string{"0", "1", "4", "5", "8", "9"}
	if cpus, err := parseCpuSet("0-1,4-5,8-9"); err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	} else if !reflect.DeepEqual(cpus, expected) {
		t.Errorf("Unexpected cpus, expected %v got %v", expected, cpus)
	}
	expected = []string{"1", "3", "5", "7"}
	if cpus, err := parseCpuSet("1,3,5,7"); err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	} else if !reflect.DeepEqual(cpus, expected) {
		t.Errorf("Unexpected cpus, expected %v got %v", expected, cpus)
	}
	if _, err := parseCpuSet("a-b"); err == nil {
		t.Errorf("Expected an error for an invalid cpuset")
	}
}

func TestGetInfoV1(t *testing.T) {
	metric := CgroupMetric{}
	getInfoV1("/slurm/uid_20821/job_10", &metric, testLogger())
	if !metric.job || metric.uid != 20821 || metric.jobid != "10" || metric.step != "" || metric.task != "" {
		t.Errorf("Unexpected job info: %+v", metric)
	}

	metric = CgroupMetric{}
	getInfoV1("/slurm/uid_20821/job_10/step_batch/task_3", &metric, testLogger())
	if !metric.job || metric.jobid != "10" || metric.step != "batch" || metric.task != "3" {
		t.Errorf("Unexpected step/task info: %+v", metric)
	}

	metric = CgroupMetric{}
	getInfoV1("/user.slice/user-20821.slice", &metric, testLogger())
	if !metric.userslice || metric.job || metric.uid != 20821 {
		t.Errorf("Unexpected user slice info: %+v", metric)
	}
}

func TestGetInfoV2(t *testing.T) {
	metric := CgroupMetric{}
	getInfoV2(*slurmScope+"/job_211", &metric, testLogger())
	if !metric.job || metric.jobid != "211" || metric.uid != -1 || metric.step != "" {
		t.Errorf("Unexpected job info: %+v", metric)
	}

	metric = CgroupMetric{}
	getInfoV2(*slurmScope+"/job_211/step_batch/user/task_special", &metric, testLogger())
	if !metric.job || metric.jobid != "211" || metric.step != "batch" || metric.task != "special" {
		t.Errorf("Unexpected step/task info: %+v", metric)
	}

	metric = CgroupMetric{}
	getInfoV2("/not/a/slurm/cgroup", &metric, testLogger())
	if metric.job || metric.jobid != "" {
		t.Errorf("Unexpected info for a non-slurm cgroup: %+v", metric)
	}
}

func TestGetMetricsV1UserSlice(t *testing.T) {
	m, err := getMetricsV1(testLogger(), "/user.slice/user-20821.slice")
	if err != nil {
		t.Fatalf("Unexpected error: %s", err.Error())
	}
	if m.cpuUser != 0.41 {
		t.Errorf("Unexpected value for cpuUser, got %v", m.cpuUser)
	}
	if m.cpuSystem != 0.39 {
		t.Errorf("Unexpected value for cpuSystem, got %v", m.cpuSystem)
	}
	if m.cpuTotal != 0.831825022 {
		t.Errorf("Unexpected value for cpuTotal, got %v", m.cpuTotal)
	}
	if m.cpus != 0 {
		t.Errorf("Unexpected value for cpus, got %v", m.cpus)
	}
	if m.memoryRSS != 5378048 {
		t.Errorf("Unexpected value for memoryRSS, got %v", m.memoryRSS)
	}
	if m.memoryCache != 2322432 {
		t.Errorf("Unexpected value for memoryCache, got %v", m.memoryCache)
	}
	if m.memoryUsed != 8081408 {
		t.Errorf("Unexpected value for memoryUsed, got %v", m.memoryUsed)
	}
	if m.memoryTotal != 68719476736 {
		t.Errorf("Unexpected value for memoryTotal, got %v", m.memoryTotal)
	}
	if m.memoryFailCount != 0 {
		t.Errorf("Unexpected value for memoryFailCount, got %v", m.memoryFailCount)
	}
	if m.memswUsed != 8081408 {
		t.Errorf("Unexpected value for memswUsed, got %v", m.memswUsed)
	}
	if m.memswTotal != 9.223372036854772e+18 {
		t.Errorf("Unexpected value for memswTotal, got %v", m.memswTotal)
	}
	if m.memswFailCount != 0 {
		t.Errorf("Unexpected value for memswFailCount, got %v", m.memswFailCount)
	}
	if !m.userslice || m.uid != 20821 {
		t.Errorf("Unexpected user slice info: userslice=%v uid=%v", m.userslice, m.uid)
	}
}

func TestGetMetricsV1Torque(t *testing.T) {
	m, err := getMetricsV1(testLogger(), "/torque/1182724.batch")
	if err != nil {
		t.Fatalf("Unexpected error: %s", err.Error())
	}
	if m.cpuUser != 153146.31 {
		t.Errorf("Unexpected value for cpuUser, got %v", m.cpuUser)
	}
	if m.cpuSystem != 260.77 {
		t.Errorf("Unexpected value for cpuSystem, got %v", m.cpuSystem)
	}
	if m.cpuTotal != 152995.785583781 {
		t.Errorf("Unexpected value for cpuTotal, got %v", m.cpuTotal)
	}
	if m.cpus != 40 {
		t.Errorf("Unexpected value for cpus, got %v", m.cpus)
	}
	if m.memoryRSS != 82444320768 {
		t.Errorf("Unexpected value for memoryRSS, got %v", m.memoryRSS)
	}
	if m.memoryCache != 109678592 {
		t.Errorf("Unexpected value for memoryCache, got %v", m.memoryCache)
	}
	if m.memoryUsed != 82553999360 {
		t.Errorf("Unexpected value for memoryUsed, got %v", m.memoryUsed)
	}
	if m.memoryTotal != 196755132416 {
		t.Errorf("Unexpected value for memoryTotal, got %v", m.memoryTotal)
	}
	if m.memswUsed != 82553999360 {
		t.Errorf("Unexpected value for memswUsed, got %v", m.memswUsed)
	}
	if m.memswTotal != 196755132416 {
		t.Errorf("Unexpected value for memswTotal, got %v", m.memswTotal)
	}
}

func TestCollectSLURM(t *testing.T) {
	exporter := NewExporter(testLogger(), getMetricsV1)
	metrics, err := exporter.collect()
	if err != nil {
		t.Fatalf("Unexpected error: %s", err.Error())
	}
	if val := len(metrics); val != 2 {
		t.Fatalf("Unexpected number of metrics, got %d expected 2: %v", val, metrics)
	}
	m, ok := metrics["/slurm/uid_20821/job_10"]
	if !ok {
		t.Fatalf("Metrics for job_10 not found, got: %v", metrics)
	}
	if _, ok := metrics["/slurm/uid_20821/job_11"]; !ok {
		t.Errorf("Metrics for job_11 not found, got: %v", metrics)
	}
	if m.cpuUser != 0 {
		t.Errorf("Unexpected value for cpuUser, got %v", m.cpuUser)
	}
	if m.cpuSystem != 0 {
		t.Errorf("Unexpected value for cpuSystem, got %v", m.cpuSystem)
	}
	if m.cpuTotal != 0.007710215 {
		t.Errorf("Unexpected value for cpuTotal, got %v", m.cpuTotal)
	}
	if m.cpus != 2 {
		t.Errorf("Unexpected value for cpus, got %v", m.cpus)
	}
	if m.memoryRSS != 311296 {
		t.Errorf("Unexpected value for memoryRSS, got %v", m.memoryRSS)
	}
	if m.memoryCache != 4096 {
		t.Errorf("Unexpected value for memoryCache, got %v", m.memoryCache)
	}
	if m.memoryUsed != 356352 {
		t.Errorf("Unexpected value for memoryUsed, got %v", m.memoryUsed)
	}
	if m.memoryTotal != 2147483648 {
		t.Errorf("Unexpected value for memoryTotal, got %v", m.memoryTotal)
	}
	if m.memoryFailCount != 0 {
		t.Errorf("Unexpected value for memoryFailCount, got %v", m.memoryFailCount)
	}
	if m.memswUsed != 356352 {
		t.Errorf("Unexpected value for memswUsed, got %v", m.memswUsed)
	}
	if m.memswTotal != 2147483648 {
		t.Errorf("Unexpected value for memswTotal, got %v", m.memswTotal)
	}
	if m.memswFailCount != 0 {
		t.Errorf("Unexpected value for memswFailCount, got %v", m.memswFailCount)
	}
	if m.uid != 20821 {
		t.Errorf("Unexpected value for uid, got %v", m.uid)
	}
	if m.jobid != "10" {
		t.Errorf("Unexpected value for jobid, got %v", m.jobid)
	}
}

func TestMetricsHandler(t *testing.T) {
	srv := httptest.NewServer(metricsHandler(false, testLogger()))
	defer srv.Close()
	body, status := get(t, http.DefaultClient, srv.URL)
	if status != http.StatusOK {
		t.Fatalf("Unexpected status %d, body:\n%s", status, body)
	}
	for _, want := range []string{
		`cgroup_memory_used_bytes{jobid="10",step="",task=""} 356352`,
		`cgroup_cpus{jobid="10",step="",task=""} 2`,
		`cgroup_uid{jobid="10"} 20821`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Metric %q not found in:\n%s", want, body)
		}
	}
}

func TestMetricsHandlerBadRoot(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "dne")
	old := cgroupRoot
	cgroupRoot = &bad
	defer func() { cgroupRoot = old }()
	srv := httptest.NewServer(metricsHandler(false, testLogger()))
	defer srv.Close()
	body, status := get(t, http.DefaultClient, srv.URL)
	if status != http.StatusOK {
		t.Fatalf("Unexpected status %d, body:\n%s", status, body)
	}
	if strings.Contains(body, "cgroup_memory_used_bytes") {
		t.Errorf("Did not expect any cgroup metrics for a missing cgroup root, got:\n%s", body)
	}
}

// startWebServer serves the metrics handler through the exporter-toolkit, the
// same way main() does, and returns the base address. It listens on a free port.
func startWebServer(t *testing.T, configFile string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %s", err)
	}
	addr := l.Addr().String()
	noSystemd := false
	flags := &web.FlagConfig{
		WebListenAddresses: &[]string{addr},
		WebSystemdSocket:   &noSystemd,
		WebConfigFile:      &configFile,
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", metricsHandler(false, testLogger()))
	server := &http.Server{Handler: mux}
	go func() { _ = web.Serve(l, server, flags, testLogger()) }()
	t.Cleanup(func() { _ = server.Close() })
	return addr
}

func get(t *testing.T, client *http.Client, url string) (string, int) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s failed: %s", url, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Reading body failed: %s", err)
	}
	return string(b), resp.StatusCode
}

func getAuth(t *testing.T, client *http.Client, url, user, pass string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s failed: %s", url, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func bcryptHash(t *testing.T, password string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func TestBasicAuth(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "web.yml")
	content := "basic_auth_users:\n  prometheus: " + bcryptHash(t, "secret") + "\n"
	if err := os.WriteFile(cfg, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	url := "http://" + startWebServer(t, cfg) + "/metrics"
	client := &http.Client{Timeout: 5 * time.Second}

	if got := getAuth(t, client, url, "", ""); got != http.StatusUnauthorized {
		t.Errorf("No credentials: expected 401, got %d", got)
	}
	if got := getAuth(t, client, url, "prometheus", "wrong"); got != http.StatusUnauthorized {
		t.Errorf("Wrong password: expected 401, got %d", got)
	}
	if got := getAuth(t, client, url, "prometheus", "secret"); got != http.StatusOK {
		t.Errorf("Valid credentials: expected 200, got %d", got)
	}
}

// testIdentity is a certificate together with its private key.
type testIdentity struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// newIdentity creates a certificate signed by issuer, or self signed when issuer is nil.
func newIdentity(t *testing.T, tmpl *x509.Certificate, issuer *testIdentity, useRSA bool) *testIdentity {
	t.Helper()
	var key crypto.Signer
	var err error
	if useRSA {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	parent, signer := tmpl, key
	if issuer != nil {
		parent, signer = issuer.cert, issuer.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testIdentity{cert: cert, key: key}
}

func pemChain(ids ...*testIdentity) []byte {
	var out []byte
	for _, id := range ids {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: id.cert.Raw})...)
	}
	return out
}

func (id *testIdentity) keyPEM(t *testing.T) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(id.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// tlsCert returns the identity as a client certificate, presenting the given chain after it.
func (id *testIdentity) tlsCert(t *testing.T, chain ...*testIdentity) tls.Certificate {
	t.Helper()
	c, err := tls.X509KeyPair(pemChain(append([]*testIdentity{id}, chain...)...), id.keyPEM(t))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func caTemplate(serial int64, cn string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
}

func leafTemplate(serial int64, cn string, usage x509.ExtKeyUsage) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{usage},
		BasicConstraintsValid: true,
		DNSNames:              []string{"exporter.test"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
}

// serveTLS starts the exporter with a web config requiring TLS, a client certificate
// signed by the CA(s) in clientCAPEM, and basic auth (prometheus/secret). The
// certificates and keys are passed as PEM files, as in a real deployment.
func serveTLS(t *testing.T, certPEM, keyPEM, clientCAPEM []byte) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cfg := write("web.yml", []byte(fmt.Sprintf(`tls_server_config:
  cert_file: %s
  key_file: %s
  client_auth_type: RequireAndVerifyClientCert
  client_ca_file: %s
  min_version: TLS12
basic_auth_users:
  prometheus: %s
`, write("server.crt", certPEM), write("server.key", keyPEM), write("ca.crt", clientCAPEM), bcryptHash(t, "secret"))))
	return "https://" + startWebServer(t, cfg) + "/metrics"
}

func tlsClient(roots *x509.CertPool, serverName string, certs ...tls.Certificate) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				RootCAs:      roots,
				ServerName:   serverName,
				Certificates: certs,
				MinVersion:   tls.VersionTLS12,
			},
		},
	}
}

func poolOf(ids ...*testIdentity) *x509.CertPool {
	p := x509.NewCertPool()
	for _, id := range ids {
		p.AddCert(id.cert)
	}
	return p
}

// TestMutualTLSAndBasicAuth checks the full setup with a realistic PKI: root CA ->
// intermediate CA -> leaf certificates. The server (RSA) presents its full chain,
// the clients (ECDSA) must present a certificate that chains to the configured CA
// and the right key usage, and valid basic auth credentials are still required.
func TestMutualTLSAndBasicAuth(t *testing.T) {
	root := newIdentity(t, caTemplate(1, "root ca"), nil, false)
	inter := newIdentity(t, caTemplate(2, "intermediate ca"), root, false)
	server := newIdentity(t, leafTemplate(3, "server", x509.ExtKeyUsageServerAuth), inter, true)
	good := newIdentity(t, leafTemplate(4, "client", x509.ExtKeyUsageClientAuth), inter, false)

	expiredTmpl := leafTemplate(5, "expired client", x509.ExtKeyUsageClientAuth)
	expiredTmpl.NotBefore, expiredTmpl.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)
	expired := newIdentity(t, expiredTmpl, inter, false)
	wrongUsage := newIdentity(t, leafTemplate(6, "server cert used as client", x509.ExtKeyUsageServerAuth), inter, false)
	otherRoot := newIdentity(t, caTemplate(7, "other root ca"), nil, false)
	rogue := newIdentity(t, leafTemplate(8, "rogue client", x509.ExtKeyUsageClientAuth), otherRoot, false)

	// The server sends leaf + intermediate, and trusts clients chaining to the root.
	url := serveTLS(t, pemChain(server, inter), server.keyPEM(t), pemChain(root))
	trusting := poolOf(root)

	tests := []struct {
		name       string
		client     *http.Client
		user, pass string
		url        string
		wantErr    bool
		wantStatus int
	}{
		{name: "valid certificate chain and credentials", client: tlsClient(trusting, "", good.tlsCert(t, inter)), user: "prometheus", pass: "secret", wantStatus: http.StatusOK},
		{name: "valid certificate, no credentials", client: tlsClient(trusting, "", good.tlsCert(t, inter)), wantStatus: http.StatusUnauthorized},
		{name: "valid certificate, wrong password", client: tlsClient(trusting, "", good.tlsCert(t, inter)), user: "prometheus", pass: "wrong", wantStatus: http.StatusUnauthorized},
		{name: "valid certificate, unknown user", client: tlsClient(trusting, "", good.tlsCert(t, inter)), user: "nobody", pass: "secret", wantStatus: http.StatusUnauthorized},
		{name: "no client certificate", client: tlsClient(trusting, ""), user: "prometheus", pass: "secret", wantErr: true},
		{name: "client does not send its intermediate", client: tlsClient(trusting, "", good.tlsCert(t)), user: "prometheus", pass: "secret", wantErr: true},
		{name: "client certificate from another CA", client: tlsClient(trusting, "", rogue.tlsCert(t)), user: "prometheus", pass: "secret", wantErr: true},
		{name: "expired client certificate", client: tlsClient(trusting, "", expired.tlsCert(t, inter)), user: "prometheus", pass: "secret", wantErr: true},
		{name: "client certificate without clientAuth usage", client: tlsClient(trusting, "", wrongUsage.tlsCert(t, inter)), user: "prometheus", pass: "secret", wantErr: true},
		{name: "client does not trust the server CA", client: tlsClient(poolOf(otherRoot), "", good.tlsCert(t, inter)), user: "prometheus", pass: "secret", wantErr: true},
		{name: "server name mismatch", client: tlsClient(trusting, "other.example", good.tlsCert(t, inter)), user: "prometheus", pass: "secret", wantErr: true},
		{name: "server name matches the SAN", client: tlsClient(trusting, "exporter.test", good.tlsCert(t, inter)), user: "prometheus", pass: "secret", wantStatus: http.StatusOK},
		{name: "plain http", client: &http.Client{Timeout: 5 * time.Second}, url: strings.Replace(url, "https://", "http://", 1), user: "prometheus", pass: "secret", wantStatus: http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target := tc.url
			if target == "" {
				target = url
			}
			req, err := http.NewRequest(http.MethodGet, target, nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.user != "" {
				req.SetBasicAuth(tc.user, tc.pass)
			}
			resp, err := tc.client.Do(req)
			if tc.wantErr {
				if err == nil {
					resp.Body.Close()
					t.Fatalf("expected the request to fail, got status %d", resp.StatusCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				t.Errorf("expected status %d, got %d", tc.wantStatus, resp.StatusCode)
			}
		})
	}
}

// If the server only sends its leaf certificate, clients that do not already know the
// intermediate cannot verify it: the full chain has to be in cert_file.
func TestServerCertificateChain(t *testing.T) {
	root := newIdentity(t, caTemplate(1, "root ca"), nil, false)
	inter := newIdentity(t, caTemplate(2, "intermediate ca"), root, false)
	server := newIdentity(t, leafTemplate(3, "server", x509.ExtKeyUsageServerAuth), inter, true)
	client := newIdentity(t, leafTemplate(4, "client", x509.ExtKeyUsageClientAuth), inter, false)

	url := serveTLS(t, pemChain(server), server.keyPEM(t), pemChain(root))
	if got := getAuth(t, tlsClient(poolOf(root, inter), "", client.tlsCert(t, inter)), url, "prometheus", "secret"); got != http.StatusOK {
		t.Errorf("client knowing the intermediate: expected 200, got %d", got)
	}
	if _, err := tlsClient(poolOf(root), "", client.tlsCert(t, inter)).Get(url); err == nil {
		t.Errorf("expected a failure when neither the server nor the client provide the intermediate")
	}
}

// The exporter has to refuse to start with an unusable TLS configuration instead of
// silently serving plain HTTP.
func TestInvalidTLSConfig(t *testing.T) {
	root := newIdentity(t, caTemplate(1, "root ca"), nil, false)
	server := newIdentity(t, leafTemplate(2, "server", x509.ExtKeyUsageServerAuth), root, true)
	other := newIdentity(t, leafTemplate(3, "other", x509.ExtKeyUsageServerAuth), root, true)

	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	crt := write("server.crt", pemChain(server))
	key := write("server.key", server.keyPEM(t))
	wrongKey := write("other.key", other.keyPEM(t))
	ca := write("ca.crt", pemChain(root))
	garbage := write("garbage.crt", []byte("not a certificate"))

	tests := map[string]string{
		"key does not match certificate":     fmt.Sprintf("tls_server_config:\n  cert_file: %s\n  key_file: %s\n", crt, wrongKey),
		"missing certificate file":           fmt.Sprintf("tls_server_config:\n  cert_file: %s\n  key_file: %s\n", filepath.Join(dir, "missing.crt"), key),
		"missing key file":                   fmt.Sprintf("tls_server_config:\n  cert_file: %s\n  key_file: %s\n", crt, filepath.Join(dir, "missing.key")),
		"certificate is not PEM":             fmt.Sprintf("tls_server_config:\n  cert_file: %s\n  key_file: %s\n", garbage, key),
		"client CA without client_auth_type": fmt.Sprintf("tls_server_config:\n  cert_file: %s\n  key_file: %s\n  client_ca_file: %s\n", crt, key, ca),
		"missing client CA file":             fmt.Sprintf("tls_server_config:\n  cert_file: %s\n  key_file: %s\n  client_auth_type: RequireAndVerifyClientCert\n  client_ca_file: %s\n", crt, key, filepath.Join(dir, "missing-ca.crt")),
		"unknown client_auth_type":           fmt.Sprintf("tls_server_config:\n  cert_file: %s\n  key_file: %s\n  client_auth_type: Bogus\n  client_ca_file: %s\n", crt, key, ca),
		"unknown option":                     fmt.Sprintf("tls_server_config:\n  cert_file: %s\n  key_file: %s\n  no_such_option: 1\n", crt, key),
	}
	for name, cfgContent := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := write("web-"+strings.ReplaceAll(name, " ", "-")+".yml", []byte(cfgContent))
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			noSystemd := false
			flags := &web.FlagConfig{WebListenAddresses: &[]string{l.Addr().String()}, WebSystemdSocket: &noSystemd, WebConfigFile: &cfg}
			server := &http.Server{Handler: http.NewServeMux()}
			errCh := make(chan error, 1)
			go func() { errCh <- web.Serve(l, server, flags, testLogger()) }()
			select {
			case err := <-errCh:
				if err == nil {
					t.Errorf("expected an error")
				}
			case <-time.After(5 * time.Second):
				_ = server.Close()
				t.Errorf("the server started with an invalid TLS configuration")
			}
		})
	}
}

// The toolkit does not report a client CA file without any parsable certificate, it
// ends up with an empty pool. Make sure that fails closed: no client gets in.
func TestUnparsableClientCAFailsClosed(t *testing.T) {
	root := newIdentity(t, caTemplate(1, "root ca"), nil, false)
	server := newIdentity(t, leafTemplate(2, "server", x509.ExtKeyUsageServerAuth), root, true)
	client := newIdentity(t, leafTemplate(3, "client", x509.ExtKeyUsageClientAuth), root, false)

	url := serveTLS(t, pemChain(server), server.keyPEM(t), []byte("not a certificate"))
	if _, err := tlsClient(poolOf(root), "", client.tlsCert(t)).Get(url); err == nil {
		t.Errorf("expected every client to be rejected when the client CA file has no certificates")
	}
}
