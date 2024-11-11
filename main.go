package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
)

// Structure for the client request containing the client's public key
type ClientRequest struct {
	ClientPublicKey string `json:"client_public_key"`
}

// Structure for server response containing the server's public key
type ServerResponse struct {
	ServerPublicKey string `json:"server_public_key"`
}

// Helper function to execute a shell command and capture the output
func execCommand(cmd string, args ...string) (string, error) {
	// Ensure we use the full path for the wg command
	cmdPath := "/usr/bin/wg" + cmd
	out, err := exec.Command(cmdPath, args...).CombinedOutput()
	return string(out), err
}

// Handler to set up the WireGuard interface and add a peer with the client's public key
func keyExchangeHandler(w http.ResponseWriter, r *http.Request) {
	// Decode the incoming JSON request
	var clientReq ClientRequest
	err := json.NewDecoder(r.Body).Decode(&clientReq)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Generate the server's private key
	serverPrivateKey, err := execCommand("wg", "genkey")
	if err != nil {
		http.Error(w, "Error generating server private key", http.StatusInternalServerError)
		log.Println("Key generation error:", err)
		return
	}

	// Generate the server's public key from the private key
	serverPublicKey, err := execCommand("echo", serverPrivateKey+" | wg pubkey")
	if err != nil {
		http.Error(w, "Error generating server public key", http.StatusInternalServerError)
		log.Println("Public key generation error:", err)
		return
	}

	// Create the WireGuard interface if it doesn't exist
	_, err = execCommand("wg", "set", "wg0", "private-key", "/etc/wireguard/privatekey", "listen-port", "51820")
	if err != nil {
		http.Error(w, "Error creating WireGuard interface", http.StatusInternalServerError)
		log.Println("Interface creation error:", err)
		return
	}

	// Configure the WireGuard interface with the server's private key and client as a peer
	_, err = execCommand("wg", "set", "wg0",
		"private-key", "/etc/wireguard/privatekey",
		"listen-port", "51820",
		"peer", clientReq.ClientPublicKey,
		"allowed-ips", "10.0.0.2/32")
	if err != nil {
		http.Error(w, "Error configuring WireGuard interface", http.StatusInternalServerError)
		log.Println("Interface configuration error:", err)
		return
	}

	// Send the server's public key to the client in response
	response := ServerResponse{ServerPublicKey: serverPublicKey}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Root handler to show a welcome message on the base URL
func rootHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to the WireGuard Server!!")
}

func main() {
	// Ensure the path includes /usr/bin
	fmt.Println("Current PATH:", os.Getenv("PATH"))

	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/key-exchange", keyExchangeHandler)
	fmt.Println("Server is running on port 8000... v1")
	log.Fatal(http.ListenAndServe(":8000", nil))
}
