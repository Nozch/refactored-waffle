package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
)

//資格情報
type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

type Token struct {
	Token string `json:"token"`
}

var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

var jwtKey = []byte("your_secret_key")

//トークンの文字列を作る
func generateToken(username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	//クレームを設定
	claims := &jwt.StandardClaims{
		Subject: username,
		ExpiresAt: expirationTime.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

//リクエストをレスポンスにする
//エラー1. リクエストの解析に失敗
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("LoginHandler called with %s method", r.Method)
	
	//デバッグ　リクエストのボディをログに出すコード。
	// body, err := ioutil.ReadAll(r.Body)
	// if err != nil {
	// 	http.Error(w, "Error reading request body", http.StatusInternalServerError)
	// }
	// log.Printf("Request body: %s", body)

	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		log.Printf("Error decoding request body: %v", err)
		http.Error(w, "Failed to parse credentials", http.StatusBadRequest)
		return
	}

	//エラー2. 不正な資格情報
	// ここではユーザーの認証情報のチェックは疑似的に実装しています。
	// 実際のプロダクトでは、ユーザーのパスワードをハッシュ化して安全に保存し、それを利用して認証を行います。
	expectedPassword, ok := users[creds.Username]
	if !ok || expectedPassword != creds.Password {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	//エラー3. トークンの作成に失敗
	tokenString, err := generateToken(creds.Username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)	
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	newToken := &Token{Token: tokenString}
	json.NewEncoder(w).Encode(newToken)
}

func VerifyHandler(w http.ResponseWriter, r *http.Request) {
    // Get the token from the header
    authHeader := r.Header.Get("Authorization")
    tokenString := strings.Split(authHeader, " ")[1]

    // Now parse the token
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        // Don't forget to validate the alg is what you expect:
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }

        // jwtKey is our secret key
        return jwtKey, nil
    })

    if err != nil {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }

    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        username := claims["sub"].(string)
        // Respond with a message that includes the username from the token
        w.Write([]byte(fmt.Sprintf("Hello, %s", username)))
    } else {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }
	
}


func main() {
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/verify", VerifyHandler)
	 
	// http.HandleFunc("/welcome", WelcomeHandler)
	// http.HandleFunc("/refresh", RefreshHandler)
	log.Println("Starting server on :8010")
	err := http.ListenAndServe(":8010", nil)
	if err != nil {
		log.Fatal(err)
	}

}
