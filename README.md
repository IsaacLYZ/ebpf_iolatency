# Ebpf Iolatency

This program uses tracepoint `block_rq_issue` and `block_rq_complete` to trace I/O latency.

## Usage
```sh
# Compile
make

# Run
# iolatency [interval in seconds]
./iolatency 5
# Will refresh table every 5 seconds

# Run test I/O program
# Need to install fio
fio test.fio
```

