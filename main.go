package main

import (

	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"database/sql"

	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
)
type User struct {
	ID int `json:"id"`
	Username string `json:"username"`
	PasswordHash string `json:"password_hash"`
}
//資格情報
type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

type Token struct {
	Token string `json:"token"`
}

//DB interface is used for *MockDB and *sqlx.DB
type App struct {
	DB DBInterface
}

type DBInterface interface {
	Select(dest interface{}, query string, args ...interface{}) error
	Get(dest interface{}, query string, args ...interface{}) error
	Exec(query string, args ...interface{}) (sql.Result, error)
	NamedExec(query string, arg interface{}) (sql.Result, error)
}


var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

var jwtKey = []byte("your_secret_key")

//トークンの文字列を作る
func GenerateToken(username string) (string, error) {
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
func (a *App) LoginHandler(w http.ResponseWriter, r *http.Request) {
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
	tokenString, err := GenerateToken(creds.Username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)	
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	newToken := &Token{Token: tokenString}
	json.NewEncoder(w).Encode(newToken)
}

func (a *App) VerifyHandler(w http.ResponseWriter, r *http.Request) {
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


func (a *App) UsersHandler(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case "GET":
		users := []User{}
		err := a.DB.Select(&users, "SELECT * FROM users")
		if err != nil {
			http.Error(w, "Failed to get users", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(users)
	case "POST":
		var user User
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			http.Error(w, "Failed to parse request body", http.StatusBadRequest)
			return
		}

		_, err = a.DB.NamedExec(`INSERT INTO users (username, password_hash) VALUES (:username, :password)`,
			map[string]interface{}{
				"username": user.Username,
				"password_hash": user.PasswordHash,
			})
			if err != nil {
				http.Error(w, "Failed to insert user", http.StatusInternalServerError)
				return
			}

			w.WriteHeader(http.StatusCreated)
	case "PUT":
		var user User
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			http.Error(w, "Failed to parse request body", http.StatusBadRequest)
			return
		}
		
		_, err = a.DB.NamedExec(`UPDATE users SET username = :username, password_hash = :password_hash`, 
		map[string]interface{}{
			"id": user.ID,
			"username": user.Username,
			"password": user.PasswordHash,
		})
	if err != nil {
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
		return 
	}

	w.WriteHeader(http.StatusOK)

	case "DELETE":
		vars := mux.Vars(r)
		id, ok := vars["id"]
		if !ok {
			http.Error(w, "Missing URL parameter id", http.StatusBadRequest)
			return
		}
		_, err := a.DB.Exec(`DELETE FROM users WHERE id = $1`, id)
		if err != nil {
			http.Error(w, "Failed to delete user", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/users":
		a.UsersHandler(w, r)
	case "/login":
		a.LoginHandler(w, r)
	case "/verify":
		a.VerifyHandler(w, r)
	default:
		http.NotFound(w, r)
	}
}

func main() {

	db, err := sqlx.Connect("postgres", "user=foo dbname=bar sslmode=disable")
	if err != nil {
		log.Fatalln(err)
	}

	app := &App {
		DB: db,
	}

	http.Handle("/", app)

	log.Println("Starting server on :8010")
	err = http.ListenAndServe(":8010", nil)
	if err != nil {
		log.Fatal(err)
	}

}
