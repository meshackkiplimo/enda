package main

import (
	"fmt"
	"log"
	"net/http"

	"mine/auth"
	"mine/route"
)

func main() {
	r := route.SetupRoutes()

	// Register authentication handlers
	r.HandleFunc("/register", auth.RegisterHandler)
	r.HandleFunc("/login", auth.LoginHandler)

	fmt.Println("Server is running on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
