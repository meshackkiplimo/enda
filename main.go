package main

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "time"

    jwt "github.com/dgrijalva/jwt-go"
)

// User structure to hold user data
type User struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

// JWT Claims structure
type Claims struct {
    Username string `json:"username"`
    jwt.StandardClaims
}

// A secret key for signing JWTs - in practice, this should not be hardcoded
var jwtKey = []byte("my_secret_key")

// A map to simulate a database - this would be replaced by an actual database in a real app
var users = map[string]string{
    "user1": "password1",
    "user2": "password2",
}

func main() {
    // Register endpoints
    http.HandleFunc("/register", registerHandler)
    http.HandleFunc("/login", loginHandler)
    http.HandleFunc("/protected", authMiddleware(protectedHandler))

    fmt.Println("Server is running on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

// Middleware to authenticate requests
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Extract token from header
        tokenString := r.Header.Get("Authorization")
        if tokenString == "" {
            http.Error(w, "Missing Authorization Token", http.StatusUnauthorized)
            return
        }

        // Validate token
        claims := &Claims{}
        token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
            return jwtKey, nil
        })
        if err != nil {
            if err == jwt.ErrSignatureInvalid {
                http.Error(w, "Invalid token signature", http.StatusUnauthorized)
            } else {
                http.Error(w, err.Error(), http.StatusBadRequest)
            }
            return
        }
        if !token.Valid {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        // Pass along the request to the next handler
        next.ServeHTTP(w, r)
    })
}

// Handler for user registration
func registerHandler(w http.ResponseWriter, r *http.Request) {
    var u User
    err := json.NewDecoder(r.Body).Decode(&u)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // Check if the user already exists
    if _, exists := users[u.Username]; exists {
        http.Error(w, "User already exists", http.StatusConflict)
        return
    }

    // In a real app, you'd hash the password before storing
    users[u.Username] = u.Password
    w.WriteHeader(http.StatusCreated)
}

// Handler for user login
func loginHandler(w http.ResponseWriter, r *http.Request) {
    var u User
    err := json.NewDecoder(r.Body).Decode(&u)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // Check if the user exists and the password is correct
    if pass, exists := users[u.Username]; exists && pass == u.Password {
        expirationTime := time.Now().Add(5 * time.Minute)
        claims := &Claims{
            Username: u.Username,
            StandardClaims: jwt.StandardClaims{
                ExpiresAt: expirationTime.Unix(),
            },
        }

        token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
        tokenString, err := token.SignedString(jwtKey)
        if err != nil {
            http.Error(w, "Error generating token", http.StatusInternalServerError)
            return
        }

        http.SetCookie(w, &http.Cookie{
            Name:    "token",
            Value:   tokenString,
            Expires: expirationTime,
        })
        json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
    } else {
        http.Error(w, "Invalid username or password", http.StatusUnauthorized)
    }
}

// Example handler that requires authentication
func protectedHandler(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Access granted to protected resource!"))
}