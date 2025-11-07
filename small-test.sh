if [ $(id -u) -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi


cd bpf-stuff
./scx_h &
bpf_pid=$!

cd ..

echo 1 > /sys/kernel/debug/tracing/tracing_on

sleep 0.5

mkdir -p /sys/fs/cgroup/grp_1
echo 1 > /sys/fs/cgroup/grp_1/cpu.weight

sleep 0.5

echo 0 > /sys/kernel/debug/tracing/tracing_on

kill -9 $bpf_pid


