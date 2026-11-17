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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

// testCert creates a certificate signed by parent (or self signed when parent is nil).
func testCert(t *testing.T, tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func testTemplate(serial int64, cn string, ca bool, usage x509.ExtKeyUsage) *x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	if ca {
		tmpl.IsCA = true
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{usage}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	return tmpl
}

func keyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// TestMutualTLSAndBasicAuth checks the full setup: the server presents a certificate
// the client verifies, the client has to present a certificate signed by the
// configured CA, and valid basic auth credentials are still required.
func TestMutualTLSAndBasicAuth(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	ca, caKey, caPEM := testCert(t, testTemplate(1, "test ca", true, 0), nil, nil)
	_, srvKey, srvPEM := testCert(t, testTemplate(2, "server", false, x509.ExtKeyUsageServerAuth), ca, caKey)
	_, cliKey, cliPEM := testCert(t, testTemplate(3, "client", false, x509.ExtKeyUsageClientAuth), ca, caKey)
	// A client certificate signed by a CA the server does not trust.
	otherCA, otherCAKey, _ := testCert(t, testTemplate(4, "other ca", true, 0), nil, nil)
	_, badKey, badPEM := testCert(t, testTemplate(5, "rogue client", false, x509.ExtKeyUsageClientAuth), otherCA, otherCAKey)

	cfg := write("web.yml", []byte(fmt.Sprintf(`tls_server_config:
  cert_file: %s
  key_file: %s
  client_auth_type: RequireAndVerifyClientCert
  client_ca_file: %s
  min_version: TLS12
basic_auth_users:
  prometheus: %s
`, write("server.crt", srvPEM), write("server.key", keyPEM(t, srvKey)), write("ca.crt", caPEM), bcryptHash(t, "secret"))))
	url := "https://" + startWebServer(t, cfg) + "/metrics"

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	clientFor := func(certs ...tls.Certificate) *http.Client {
		return &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				DisableKeepAlives: true,
				TLSClientConfig:   &tls.Config{RootCAs: roots, Certificates: certs, MinVersion: tls.VersionTLS12},
			},
		}
	}
	goodCert, err := tls.X509KeyPair(cliPEM, keyPEM(t, cliKey))
	if err != nil {
		t.Fatal(err)
	}
	rogueCert, err := tls.X509KeyPair(badPEM, keyPEM(t, badKey))
	if err != nil {
		t.Fatal(err)
	}

	// The client does not trust the server: the client has to fail.
	untrusting := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{Certificates: []tls.Certificate{goodCert}, MinVersion: tls.VersionTLS12},
	}}
	if _, err := untrusting.Get(url); err == nil {
		t.Errorf("Expected a failure when the client does not trust the server certificate")
	}
	// Plain HTTP must not work against a TLS server.
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(strings.Replace(url, "https://", "http://", 1))
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Errorf("Plain HTTP request unexpectedly succeeded")
		}
	}
	// No client certificate: the handshake has to fail, whatever the credentials are.
	if _, err := clientFor().Get(url); err == nil {
		t.Errorf("Expected a TLS failure without a client certificate")
	}
	// Client certificate from an untrusted CA.
	if _, err := clientFor(rogueCert).Get(url); err == nil {
		t.Errorf("Expected a TLS failure with a client certificate from an untrusted CA")
	}
	// Valid certificate, but wrong or missing credentials.
	if got := getAuth(t, clientFor(goodCert), url, "", ""); got != http.StatusUnauthorized {
		t.Errorf("Valid certificate, no credentials: expected 401, got %d", got)
	}
	if got := getAuth(t, clientFor(goodCert), url, "prometheus", "wrong"); got != http.StatusUnauthorized {
		t.Errorf("Valid certificate, wrong password: expected 401, got %d", got)
	}
	// Everything valid.
	if got := getAuth(t, clientFor(goodCert), url, "prometheus", "secret"); got != http.StatusOK {
		t.Errorf("Valid certificate and credentials: expected 200, got %d", got)
	}
}
