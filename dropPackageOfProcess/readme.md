## Allowing package on specific port for specific process

1. Create droppackageofprocess.c and write c code
2. Then generate .o files  using command `clang -O2 -target bpf -c droppackageofprocess.c -o droppackageofprocess.o`
3. create main.go file
4. `go build && sudo ./dropPackageOfProcess` for running function
5. `sudo ip link set dev lo xdp off` run this to remove link for saftey and error proof

Always need to generate and rebuild files if any changes in .c file.

"ifconfig" for finding interface of a machine used and ip address

#For Testing
1. cd to myprocess
1.  `go run main.go` it will try to make connection for both 4040 and  8080
3. 4040 should be successful but 8080 should show error as it is filtered
2. `nc -v 127.0.0.1 8080` run this command to send request to port 8080 and 4040 to check is it successful or not. 
3. `nc -v 172.31.2.95 4040` run this parrallely to create traffic on port
4. observe that after running our program no traffic is watched in tcp dump
