package main

import (
	"io"
	"log"
	"net/http"
)

func helloHandler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	log.Printf("[Backend] Peticion legitima procesada: %s %s | Body: %s", r.Method, r.URL.Path, string(body))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success","message":"Peticion procesada por backend sin anomalias"}`))
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", helloHandler)

	log.Println("[+] Servidor Backend HTTP escuchando en http://0.0.0.0:8443")
	if err := http.ListenAndServe("0.0.0.0:8443", mux); err != nil {
		log.Fatalf("Error critico en servidor backend: %v", err)
	}
}
