package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
)

type ClientRequest struct {
	ClientPublicKey string `json:"client_public_key"`
}

type ServerResponse struct {
	ServerPublicKey string `json:"server_public_key"`
}

func createWireGuardInterface() error {
	// Generate server keys (you can replace this with your key if pre-generated)
	privateKeyCmd := `wg genkey`
	privateKeyOut, err := exec.Command("sh", "-c", privateKeyCmd).Output()
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}
	privateKey := string(privateKeyOut)

	publicKeyCmd := fmt.Sprintf(`echo "%s" | wg pubkey`, privateKey)
	publicKeyOut, err := exec.Command("sh", "-c", publicKeyCmd).Output()
	if err != nil {
		return fmt.Errorf("failed to generate public key: %v", err)
	}
	serverPublicKey := string(publicKeyOut)

	// Configure wg0 interface with server's private key
	setupCmd := fmt.Sprintf(`sudo ip link add dev wg0 type wireguard &&
                             sudo ip address add 10.20.10.1/24 dev wg0 &&
                             echo "%s" | sudo wg set wg0 private-key /dev/stdin &&
                             sudo ip link set up dev wg0`, privateKey)
	err = exec.Command("sh", "-c", setupCmd).Run()
	if err != nil {
		return fmt.Errorf("failed to setup WireGuard interface: %v", err)
	}

	fmt.Println("WireGuard interface wg0 created with server public key:", serverPublicKey)
	return nil
}

func addPeer(clientPublicKey string) error {
	// Add peer configuration to wg0
	peerCmd := fmt.Sprintf(`sudo wg set wg0 peer %s allowed-ips 10.20.10.2/32`, clientPublicKey)
	err := exec.Command("sh", "-c", peerCmd).Run()
	if err != nil {
		return fmt.Errorf("failed to add peer: %v", err)
	}
	return nil
}

func keyExchangeHandler(w http.ResponseWriter, r *http.Request) {
	var clientReq ClientRequest
	err := json.NewDecoder(r.Body).Decode(&clientReq)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	err = addPeer(clientReq.ClientPublicKey)
	if err != nil {
		http.Error(w, "Error adding peer", http.StatusInternalServerError)
		log.Println("Peer configuration error:", err)
		return
	}

	// Respond to the client (assuming serverPublicKey is already available)
	response := ServerResponse{ServerPublicKey: "SERVER_PUBLIC_KEY_HERE"} // Update with your actual server public key
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to the WireGuard Server!")
}

func main() {
	http.HandleFunc("/", rootHandler)

	// Run WireGuard interface setup
	err := createWireGuardInterface()
	if err != nil {
		log.Fatal("Failed to create WireGuard interface:", err)
	}

	// HTTP server setup
	http.HandleFunc("/key-exchange", keyExchangeHandler)
	fmt.Println("Server is running on port 8000...")
	log.Fatal(http.ListenAndServe(":8000", nil))
}
