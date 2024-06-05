## Droping package on specific port

1. Create droppackageofport.c and write c code
2. Then generate .o files  using command `clang -O2 -g  -target bpf -c droppackageofport.c -o droppackageofport.o`
3. create main.go file
4. `go build && sudo ./dropPackageOfPort 4040` for running function

Always need to generate and rebuild files if any changes in .c file.

"ifconfig" for finding interface of a machine used and ip address

#For Testing
1. build and run main.go as mentioned above
2. `sudo tcpdump -i enX0 tcp port 4040` run this command to see tcp trafic on interface enX0 and port 4040
3. `nc -v 172.31.2.95 4040` run this parrallely to create traffic on port
4. observe that after running our program no traffic is watched in tcp dump
