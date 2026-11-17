# cgroup Prometheus exporter

[![Build Status](https://circleci.com/gh/treydock/cgroup_exporter/tree/master.svg?style=shield)](https://circleci.com/gh/treydock/cgroup_exporter)
[![GitHub release](https://img.shields.io/github/v/release/treydock/cgroup_exporter?include_prereleases&sort=semver)](https://github.com/treydock/cgroup_exporter/releases/latest)
![GitHub All Releases](https://img.shields.io/github/downloads/treydock/cgroup_exporter/total)
[![codecov](https://codecov.io/gh/treydock/cgroup_exporter/branch/master/graph/badge.svg)](https://codecov.io/gh/treydock/cgroup_exporter)

# cgroup Prometheus exporter

The `cgroup_exporter` produces metrics from cgroups.

This is a modified version of https://github.com/treydock/cgroup_exporter tuned to work for slurm use. Both cgroupv1 and cgroupv2 work with this version and there is no longer any need to use the cgroupv2 branch.

This exporter by default listens on port `9306` and all metrics are exposed via the `/metrics` endpoint.

# Usage

## Install from source

Clone the [repo](https://github.com/plazonic/cgroup_exporter)

To produce the `cgroup_exporter` binaries:

```
go build
```

## Use github prebuilt-binaries
Alternatively, download from [github](https://github.com/plazonic/cgroup_exporter/releases/)

## Process metrics

If you wish to collect process information for a cgroup pass the `--collect.proc` flag. If this exporter is not running as root then it's required to set capabilities to ensure the user running this exporter can read everything under procfs:

```
setcap cap_sys_ptrace=eip /usr/bin/cgroup_exporter
```

## TLS and authentication

TLS, mutual TLS and basic authentication are provided by the Prometheus [exporter-toolkit](https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md). Enable them by passing a web configuration file:

```
cgroup_exporter --web.config.file=/etc/cgroup_exporter/web-config.yml
```

The `--web.listen-address` flag can be repeated to listen on several addresses, and `--web.systemd-socket` is available for systemd socket activation.

[webconfig.example.yaml](webconfig.example.yaml) configures basic authentication over TLS, with both sides verifying each other:

```yaml
tls_server_config:
  cert_file: /etc/cgroup_exporter/server.crt      # leaf first, then any intermediates
  key_file: /etc/cgroup_exporter/server.key
  client_auth_type: RequireAndVerifyClientCert
  client_ca_file: /etc/cgroup_exporter/ca.crt     # CA that signed Prometheus's client cert
  min_version: TLS12
basic_auth_users:
  prometheus: $2y$10$...
```

Passwords are stored as bcrypt hashes, which can be generated with `htpasswd -nBC 10 "" | tr -d ':\n'`.

Notes:

- `client_auth_type` defaults to `NoClientCert`. Setting `client_ca_file` without a `client_auth_type` is rejected at startup.
- Every certificate the exporter needs to present must be in `cert_file`: the leaf first, followed by any intermediates. The CA in `client_ca_file` only needs to be the one that signs (or is the root of) the Prometheus client certificate, and Prometheus has to send its intermediates as part of `cert_file`.
- The server certificate needs the `serverAuth` extended key usage and a SAN matching the name Prometheus scrapes. The client certificate needs `clientAuth`.
- A client without a valid certificate fails the TLS handshake. A client with a valid certificate but a wrong password gets a `401`.

Matching Prometheus scrape configuration:

```yaml
scrape_configs:
  - job_name: cgroup
    scheme: https
    basic_auth:
      username: prometheus
      password_file: /etc/prometheus/cgroup_exporter.pass
    tls_config:
      ca_file: /etc/prometheus/ca.crt           # verifies the exporter's certificate
      cert_file: /etc/prometheus/client.crt     # presented to the exporter
      key_file: /etc/prometheus/client.key
    static_configs:
      - targets: ['node1.example.org:9306']
```

## Metrics

Example of metrics exposed by this exporter when looking at `/user.slice` paths:

```
cgroup_cpu_system_seconds{cgroup="/user.slice/user-20821.slice"} 1.96
cgroup_cpu_total_seconds{cgroup="/user.slice/user-20821.slice"} 3.817500568
cgroup_cpu_user_seconds{cgroup="/user.slice/user-20821.slice"} 1.61
cgroup_cpus{cgroup="/user.slice/user-20821.slice"} 0
cgroup_cpu_info{cgroup="/user.slice/user-20821.slice",cpus=""} 1
cgroup_info{cgroup="/user.slice/user-20821.slice",uid="20821",username="tdockendorf",jobid=""} 1
cgroup_memory_cache_bytes{cgroup="/user.slice/user-20821.slice"} 2.322432e+06
cgroup_memory_fail_count{cgroup="/user.slice/user-20821.slice"} 0
cgroup_memory_rss_bytes{cgroup="/user.slice/user-20821.slice"} 5.378048e+06
cgroup_memory_total_bytes{cgroup="/user.slice/user-20821.slice"} 6.8719476736e+10
cgroup_memory_used_bytes{cgroup="/user.slice/user-20821.slice"} 6.90176e+06
cgroup_memsw_fail_count{cgroup="/user.slice/user-20821.slice"} 0
cgroup_memsw_total_bytes{cgroup="/user.slice/user-20821.slice"} 9.223371968135295e+18
cgroup_memsw_used_bytes{cgroup="/user.slice/user-20821.slice"} 0
```

Example of metrics exposed by this exporter when looking at `/slurm` paths:

```
cgroup_cpu_system_seconds{cgroup="/slurm/uid_20821/job_12"} 0
cgroup_cpu_total_seconds{cgroup="/slurm/uid_20821/job_12"} 0.007840451
cgroup_cpu_user_seconds{cgroup="/slurm/uid_20821/job_12"} 0
cgroup_cpus{cgroup="/slurm/uid_20821/job_12"} 2
cgroup_cpu_info{cgroup="/slurm/uid_20821/job_12",cpus="0,1"} 1
cgroup_info{cgroup="/slurm/uid_20821/job_12",jobid="12",uid="20821",username="tdockendorf"} 1
cgroup_memory_cache_bytes{cgroup="/slurm/uid_20821/job_12"} 4.096e+03
cgroup_memory_fail_count{cgroup="/slurm/uid_20821/job_12"} 0
cgroup_memory_rss_bytes{cgroup="/slurm/uid_20821/job_12"} 3.11296e+05
cgroup_memory_total_bytes{cgroup="/slurm/uid_20821/job_12"} 2.147483648e+09
cgroup_memory_used_bytes{cgroup="/slurm/uid_20821/job_12"} 315392
cgroup_memsw_fail_count{cgroup="/slurm/uid_20821/job_12"} 0
cgroup_memsw_total_bytes{cgroup="/slurm/uid_20821/job_12"} 2.147483648e+09
cgroup_memsw_used_bytes{cgroup="/slurm/uid_20821/job_12"} 315392
```

Example of metrics exposed by this exporter when looking at `/torque` paths:

```
cgroup_cpu_system_seconds{cgroup="/torque/1182958.batch.example.com"} 26.35
cgroup_cpu_total_seconds{cgroup="/torque/1182958.batch.example.com"} 939.568245515
cgroup_cpu_user_seconds{cgroup="/torque/1182958.batch.example.com"} 915.61
cgroup_cpus{cgroup="/torque/1182958.batch.example.com"} 8
cgroup_cpu_info{cgroup="/torque/1182958.batch.example.com",cpus="0,1,2,3,4,5,6,7,8"} 1
cgroup_info{cgroup="/torque/1182958.batch.example.com",jobid="1182958",uid="",username=""} 1
cgroup_memory_cache_bytes{cgroup="/torque/1182958.batch.example.com"} 1.09678592e+08
cgroup_memory_fail_count{cgroup="/torque/1182958.batch.example.com"} 0
cgroup_memory_rss_bytes{cgroup="/torque/1182958.batch.example.com"} 8.2444320768e+10
cgroup_memory_total_bytes{cgroup="/torque/1182958.batch.example.com"} 1.96755132416e+11
cgroup_memory_used_bytes{cgroup="/torque/1182958.batch.example.com"} 5.3434466304e+10
cgroup_memsw_fail_count{cgroup="/torque/1182958.batch.example.com"} 0
cgroup_memsw_total_bytes{cgroup="/torque/1182958.batch.example.com"} 1.96755132416e+11
cgroup_memsw_used_bytes{cgroup="/torque/1182958.batch.example.com"} 5.3434466304e+10
```
