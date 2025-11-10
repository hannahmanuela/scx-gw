#!/bin/bash

# check we're running as root
if [ $(id -u) -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

sudo cat /sys/kernel/debug/tracing/trace_pipe > x.txt &
pipe_pid=$!

echo 1 > /sys/kernel/debug/tracing/tracing_on

sleep 0.5

./scx_h &
bpf_pid=$!

sleep 0.5

# /home/hannahmanuela/schedviz/util/trace.sh -out "/home/hannahmanuela/scx-gw" -capture_seconds 6 &
# PID_TRACE=$!


taskset -c 4 ./test_policy/test &
pid=$!

sleep 4

kill -9 $bpf_pid

Kill the entire process tree
pkill -TERM -P $pid
kill -TERM $pid
sleep 1
pkill -KILL -P $pid

kill -TERM $pipe_pid

# wait $PID_TRACE

echo 0 > /sys/kernel/debug/tracing/tracing_on
