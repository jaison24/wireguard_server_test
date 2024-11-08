package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Structure for the client request containing the client's public key
type ClientRequest struct {
	ClientPublicKey string `json:"client_public_key"`
}

// Structure for server response containing the server's public key
type ServerResponse struct {
	ServerPublicKey string `json:"server_public_key"`
}

// Handler to generate keys and add a peer with client's public key
func keyExchangeHandler(w http.ResponseWriter, r *http.Request) {
	// Decode the incoming JSON request
	var clientReq ClientRequest
	err := json.NewDecoder(r.Body).Decode(&clientReq)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Generate server private and public keys
	serverPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		http.Error(w, "Error generating server keys", http.StatusInternalServerError)
		log.Println("Key generation error:", err)
		return
	}
	serverPublicKey := serverPrivateKey.PublicKey()

	// Create a WireGuard client to manage the interface
	client, err := wgctrl.New()
	if err != nil {
		http.Error(w, "Error initializing WireGuard client", http.StatusInternalServerError)
		log.Println("WireGuard client error:", err)
		return
	}
	defer client.Close()

	// Set up the configuration for the WireGuard interface
	config := wgtypes.Config{
		PrivateKey:   &serverPrivateKey,
		ListenPort:   new(int), // default port (set your port here if needed)
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:  parseKey(clientReq.ClientPublicKey),
				AllowedIPs: []net.IPNet{{IP: []byte{10, 20, 10, 2}, Mask: []byte{255, 255, 255, 255}}},
			},
		},
	}

	// Apply the configuration to wg0 interface
	err = client.ConfigureDevice("wg0", config)
	if err != nil {
		http.Error(w, "Error configuring WireGuard interface", http.StatusInternalServerError)
		log.Println("Interface configuration error:", err)
		return
	}

	// Respond to the client with the server's public key
	response := ServerResponse{ServerPublicKey: serverPublicKey.String()}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func parseKey(pubKey string) wgtypes.Key {
	key, err := wgtypes.ParseKey(pubKey)
	if err != nil {
		log.Fatalf("Invalid public key format: %v", err)
	}
	return key
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to the WireGuard Server!")
}

func main() {
	http.HandleFunc("/", rootHandler)

	http.HandleFunc("/key-exchange", keyExchangeHandler)
	fmt.Println("Server is running on port 8000...")
	log.Fatal(http.ListenAndServe(":8000", nil))
}
