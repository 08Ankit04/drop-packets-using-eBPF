package main

import (
    "fmt"
    "os"
    "os/signal"
    "syscall"
    "net"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
)

const defaultPort uint16 = 4040

func loadEBPFProgram() (*ebpf.Collection, error) {
    // Load the compiled eBPF object file
    spec, err := ebpf.LoadCollectionSpec("droppackageofport.o")
    if err != nil {
        return nil, fmt.Errorf("loading collection spec: %v", err)
    }

    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        return nil, fmt.Errorf("creating collection: %v", err)
    }

    return coll, nil
}

func main() {
    // Adjust rlimit to allow for loading eBPF programs
    if err := rlimit.RemoveMemlock(); err != nil {
        fmt.Fprintf(os.Stderr, "Failed to adjust rlimit: %v\n", err)
        os.Exit(1)
    }

    // Load the eBPF program
    coll, err := loadEBPFProgram()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to load eBPF program: %v\n", err)
        os.Exit(1)
    }
    defer coll.Close()

    // Default port to block
    port := defaultPort
    if len(os.Args) > 1 {
        fmt.Sscanf(os.Args[1], "%d", &port)
    }

    // Update the eBPF map with the port to block
    blockPortMap := coll.Maps["block_port"]
    if blockPortMap == nil {
        fmt.Fprintf(os.Stderr, "Failed to find map: block_port\n")
        os.Exit(1)
    }

    key := uint16(80) // example port number to block
    value := uint8(1) // example value

    if err := blockPortMap.Update(key, value, ebpf.UpdateAny); err != nil {
        fmt.Fprintf(os.Stderr, "Failed to update map: %v\n", err)
        os.Exit(1)
    }

    // Attach the eBPF program to the network interface
    prog := coll.Programs["drop_tcp_port"]
	if prog == nil {
		fmt.Fprintf(os.Stderr, "Failed to get eBPF program\n")
		os.Exit(1)
	}

    // Get the network interface index
    iface, err := net.InterfaceByName("enX0")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to get interface by name: %v\n", err)
        os.Exit(1)
    }

	link1, err := link.AttachXDP(link.XDPOptions{
        Program:   prog,
        Interface: iface.Index,
        Flags:     link.XDPGenericMode, // Adjust the flags as necessary
    })
	
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to attach XDP program: %v\n", err)
        os.Exit(1)
    }
    defer link1.Close()

    fmt.Printf("Dropping TCP packets on port %d\n", port)

    // Wait for termination signal
    sigs := make(chan os.Signal, 1)
    signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
    <-sigs

    fmt.Println("Exiting...")
}
