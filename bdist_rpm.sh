#!/bin/bash 

go build

fpm -s dir -t rpm   -n nvidia_gpu_prometheus_exporter   -v $(cat VERSION)  --iteration 1.el9   --license Apache-2.0 \
--url https://github.com/plazonic/nvidia_gpu_prometheus_exporter  \
--description "Prometheus exporter for cgroup usage in slurm jobs" cgroup_exporter=/usr/bin/cgroup_exporter
