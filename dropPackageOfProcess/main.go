package main

import (
  "fmt"
  "os"
  "bytes"
  "net"

  "github.com/cilium/ebpf"
  "github.com/cilium/ebpf/link"
  "github.com/cilium/ebpf/rlimit"
)

func main() {
  bpfFilepath := "droppackageofprocess.o" // Change to your file path

  // Allow the current process to lock memory for eBPF maps
  if err := rlimit.RemoveMemlock(); err != nil {
    fmt.Println("Error removing memlock:", err)
    return
  }

  // Read the eBPF program
  f, err := os.Open(bpfFilepath)
  if err != nil {
    fmt.Println("Error opening eBPF program file:", err)
    return
  }
  defer f.Close()

  bpfBytes, err := os.ReadFile(bpfFilepath) // Read all bytes at once
  if err != nil {
    fmt.Println("Error reading eBPF program file:", err)
    return
  }

  // Load the eBPF program
  spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfBytes))
  if err != nil {
    fmt.Println("Error loading eBPF program spec:", err)
    return
  }

  coll, err := ebpf.NewCollection(spec)
  if err != nil {
    fmt.Println("Error creating eBPF collection:", err)
    return
  }
  defer coll.Close()

  // Assuming XDP program type (modify if needed)
  prog := coll.Programs["filter_func"]
  if prog == nil {
    fmt.Println("Error finding program in collection")
    return
  }

  // Get the network interface index
  iface, err := net.InterfaceByName("lo")
  if err != nil {
	  fmt.Fprintf(os.Stderr, "Failed to get interface by name: %v\n", err)
	  os.Exit(1)
  }

  // Attach the eBPF program
  l, err := link.AttachXDP(link.XDPOptions{
    Program:   prog,
    Interface: iface.Index,
  })
  if err != nil {
    fmt.Println("Error attaching eBPF program:", err)
    return
  }
  defer l.Close()

  fmt.Println("eBPF program loaded and attached successfully")
}
