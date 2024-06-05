package main

import (
    "fmt"
    "net"
    "time"
)

func main() {
    // Define allowed port and another port for testing
    allowedPort := 4040
    testPort := 8080

    // Create a listener on the allowed port
    listener, err := net.Listen("tcp", fmt.Sprintf(":%d", allowedPort))
    if err != nil {
        fmt.Println("Error creating listener:", err)
        return
    }
    defer listener.Close()

    fmt.Println("myprocess is listening on port:", allowedPort)

    // Accept incoming connections in a loop
    go func() {
        for {
            conn, err := listener.Accept()
            if err != nil {
                fmt.Println("Error accepting connection:", err)
                continue
            }
            defer conn.Close()

            fmt.Println("Received connection from:", conn.RemoteAddr())

            _, err = conn.Write([]byte("Hello from myprocess!"))
            if err != nil {
                fmt.Println("Error sending response:", err)
            }
        }
    }()

    // Send test traffic to another port in a separate goroutine
    go func() {
        for {
            // Connect to the test port
            conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", testPort))
            if err != nil {
                fmt.Println("Error connecting to test port:", err)
                time.Sleep(1 * time.Second) // Wait before retrying
                continue
            }
            defer conn.Close()

            _, err = conn.Write([]byte("Test traffic"))
            if err != nil {
                fmt.Println("Error sending test traffic:", err)
            }

            fmt.Println("Sent test traffic to port:", testPort)
            time.Sleep(2 * time.Second)
        }
    }()

    // Keep the main program running
    select {}
}
