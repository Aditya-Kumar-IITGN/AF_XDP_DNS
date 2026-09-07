#!/bin/bash

run_test() {
    local container_cmd="$1"
    local result_file="$2"

    echo -e "\n Running test: $result_file"

    # Start container
    docker run --rm --name=plswork -p 53:53/udp \
        --privileged --ulimit memlock=-1 --cpuset-cpus="0" -d cutedns \
        bash -c "$container_cmd"

    echo "Waiting 5s for server to start..."
    sleep 5

    # Start PERF inside container (tracking the server process)
    echo "Starting perf cycle counter..."

    # Detect server PID safely
    SERVER_PID=$(docker exec plswork pgrep -f -v "bash|perf|pgrep" | head -n 1)

    if [ -z "$SERVER_PID" ]; then
        echo "Could not detect server process. Perf will not run."
    else
        echo "Profiling process PID: $SERVER_PID"
        docker exec -d plswork bash -c "perf stat -e cycles,instructions -p $SERVER_PID 2> /tmp/perf_result.txt"
    fi

    # Run the DNS workload
    dnsperf -s 172.17.0.2 -d main/tmp.txt -c 3 -l 60 -q 10 -t 15 -v 2>&1 \
        | sed -n '/Statistics/,$p' > "$result_file"

    # Stop perf
    echo "Stopping perf..."
    docker exec plswork pkill -INT perf
    sleep 1

    # Append perf results
    echo -e "\n----- PERF METRICS -----" >> "$result_file"
    docker exec plswork cat /tmp/perf_result.txt >> "$result_file"

    # ---- Compute Cycles Per Query ----
    TOTAL_CYCLES=$(docker exec plswork cat /tmp/perf_result.txt | grep cycles | awk '{print $1}' | sed 's/,//g')
    QUERIES_DONE=$(grep "Queries completed:" "$result_file" | awk '{print $3}')

    if [[ ! -z "$TOTAL_CYCLES" && ! -z "$QUERIES_DONE" && "$QUERIES_DONE" -gt 0 ]]; then
        CYCLES_PER_QUERY=$(echo "$TOTAL_CYCLES / $QUERIES_DONE" | bc)
        echo -e "Cycles per Query: $CYCLES_PER_QUERY" >> "$result_file"
        echo "Cycles/query = $CYCLES_PER_QUERY"
    else
        echo "Unable to compute cycles/query"
    fi


    echo "Saved results → $result_file"

    # Stop container
    docker stop plswork > /dev/null 2>&1
    sleep 2
}

# Build image once
echo -e "\nBuilding Docker image..."
docker build -t cutedns .
echo "Build complete!"

# Create results directory
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RESULTS_DIR="results_single_core/$TIMESTAMP"
mkdir -p "$RESULTS_DIR"

# Run tests
run_test "./af_xdp_user -d eth0 --filename ./af_xdp_kern.o" "$RESULTS_DIR/xdp_luru_results.txt"
run_test "gcc server.c -o server -Wall && ./server" "$RESULTS_DIR/normal_luru_results.txt"
run_test "./af_xdp_user_cached -d eth0 --filename ./af_xdp_kern.o" "$RESULTS_DIR/xdp_hashcache_results.txt"
run_test "gcc server_cached.c -o server_cached -Wall && ./server_cached" "$RESULTS_DIR/normal_hashcache_results.txt"

echo -e "\nAll tests completed!"
