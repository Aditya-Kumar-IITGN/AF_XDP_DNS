# DNS Resolver using AF-XDP

## Report: [`G21_31_DNS Resolver using AF_XDP Report.pdf`](./G21_31_DNS%20Resolver%20using%20AF_XDP%20Report.pdf)

## Presentation: [`G21_31_DNS Resolver using AF_XDP PPT.pdf`](./G21_31_DNS%20Resolver%20using%20AF_XDP%20PPT.pdf)

## Replicating Results

To run all tests, run these commands on the host terminal:
```sh
  chmod +x run_tests.sh
  ./run_tests
```
This shell file includes all steps for replicating the results we obtained. It includes Docker image creation, compiling resolver files, starting the resolver, running tests, etc.
The results of these tests are stored in the `results_single_core` directory inside a subfolder named after the timestamp at which the experiment was run. 


## Custom testing

1. Build:

```sh
    docker build -t cutedns .
```

2. Run:

```sh
docker run --rm -it --name=plswork  -p 53:53/udp\
  --privileged \
  --ulimit memlock=-1 \
  cutedns /bin/bash
```

In case host port 53 is already in use, change 53 to any other number (say 3000).
```sh
docker run --rm -it --name=plswork  -p 3000:53/udp --privileged --ulimit memlock=-1 cutedns /bin/bash
```

3. In a new terminal on host, get the IP of the container:

```sh
docker inspect -f '{{.NetworkSettings.IPAddress}}' plswork
```

4. In docker bash, run, `./af_xdp_user -d eth0 --filename ./af_xdp_kern.o`

5. Do `dig` and compare.

6. Sanity check. While Step 5 runs, launch a new docker terminal, `docker exec -it plswork /bin/bash`, and write `xdp-loader status`.

7. See that xdp mode is native! (means zero copy works)

8. Comparing with no XDP. Run `gcc server.c -o server -Wall`. Run `./server`.

9. On host, run `dnsperf -s {docker_container_ip} -d tmp.txt -c 3 -l 60 -q 10 -t 15 -v`
Here, replace docker_container_ip either with something returns