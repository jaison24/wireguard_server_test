package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"text/template"
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
	out, err := exec.Command(cmd, args...).CombinedOutput()
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

	// Create the WireGuard configuration template
	configTemplate := `
[Interface]
Address = 10.0.0.1/24
PrivateKey = {{.PrivateKey}}
ListenPort = 51820

[Peer]
PublicKey = {{.PeerPublicKey}}
AllowedIPs = 10.0.0.2/32
`

	// Generate the configuration file content
	tmpl, err := template.New("wgConfig").Parse(configTemplate)
	if err != nil {
		http.Error(w, "Error generating configuration template", http.StatusInternalServerError)
		log.Println("Template parsing error:", err)
		return
	}

	// Write the configuration to the file
	configFile, err := os.Create("/etc/wireguard/wg0.conf")
	if err != nil {
		http.Error(w, "Error creating WireGuard configuration file", http.StatusInternalServerError)
		log.Println("File creation error:", err)
		return
	}
	defer configFile.Close()

	// Execute the template with the server's private key and client's public key
	err = tmpl.Execute(configFile, map[string]string{
		"PrivateKey":    serverPrivateKey,
		"PeerPublicKey": clientReq.ClientPublicKey,
	})
	if err != nil {
		http.Error(w, "Error writing to configuration file", http.StatusInternalServerError)
		log.Println("Template execution error:", err)
		return
	}

	// Restart WireGuard interface after updating the configuration
	_, err = execCommand("wg-quick", "down", "wg0")
	if err != nil {
		http.Error(w, "Error bringing down the interface", http.StatusInternalServerError)
		log.Println("wg-quick down error:", err)
		return
	}

	_, err = execCommand("wg-quick", "up", "wg0")
	if err != nil {
		http.Error(w, "Error bringing up the interface", http.StatusInternalServerError)
		log.Println("wg-quick up error:", err)
		return
	}

	// Send the server's public key to the client in response
	response := ServerResponse{ServerPublicKey: serverPublicKey}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Root handler to show a welcome message on the base URL
func rootHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to the WireGuard Server!")
}

func main() {
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/key-exchange", keyExchangeHandler)
	fmt.Println("Server is running on port 8000...")
	log.Fatal(http.ListenAndServe(":8000", nil))
}
