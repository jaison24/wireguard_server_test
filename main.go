package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"github.com/libp2p/go-wireguard/wgcfg"
)

// Structure for the client request containing the client's public key
type ClientRequest struct {
	ClientPublicKey string `json:"client_public_key"`
}

// Structure for server response containing the server's public key
type ServerResponse struct {
	ServerPublicKey string `json:"server_public_key"`
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
	privateKey, err := wgcfg.GeneratePrivateKey()
	if err != nil {
		http.Error(w, "Error generating server private key", http.StatusInternalServerError)
		log.Println("Key generation error:", err)
		return
	}

	// Generate the server's public key from the private key
	publicKey := privateKey.PublicKey()

	// Configure the WireGuard interface
	config := wgcfg.Config{
		PrivateKey: privateKey,
		Peers: []wgcfg.Peer{
			{
				PublicKey: clientReq.ClientPublicKey,
				AllowedIPs: []string{"10.0.0.2/32"},
			},
		},
	}

	// Here you would create or configure the WireGuard interface, but this will depend on your system.
	// For example, you can use the `wg-quick` tool or some low-level system API to apply the config.

	// Send the server's public key to the client in response
	response := ServerResponse{ServerPublicKey: publicKey.String()}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Root handler to show a welcome message on the base URL
func rootHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to the WireGuard Server V9!")
}

func main() {
	// Start the HTTP server
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/key-exchange", keyExchangeHandler)
	fmt.Println("Server is running on port 8000...")
	log.Fatal(http.ListenAndServe(":8000", nil))
}
