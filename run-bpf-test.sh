#!/bin/bash

# check we're running as root
if [ $(id -u) -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

echo 1 > /sys/kernel/debug/tracing/tracing_on

./scx_h &
bpf_pid=$!

sleep 0.5

taskset -c 4 ./test_policy/test &
pid=$!

sleep 4

kill -9 $bpf_pid

# Kill the entire process tree
pkill -TERM -P $pid
kill -TERM $pid
sleep 1
pkill -KILL -P $pid

echo 0 > /sys/kernel/debug/tracing/tracing_on
