package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/jwtauth"
	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

var (
	DATABASE_URL, DB_DRIVER, JWT_SECRET_KEY, PORT string
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalln("cound not load .env file")
	}
	DATABASE_URL = os.Getenv("DATABASE_URL")
	DB_DRIVER = os.Getenv("DB_DRIVER")
	JWT_SECRET_KEY = os.Getenv("JWT_SECRET_KEY")
	PORT = os.Getenv("PORT")
}

func DBClient() (*sql.DB, error) {
	db, err := sql.Open(DB_DRIVER, DATABASE_URL)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}
	fmt.Println("connected to database")
	return db, nil
}

func GenerateAuthToken() *jwtauth.JWTAuth {
	tokenAuth := jwtauth.New("HS256", []byte(JWT_SECRET_KEY), nil)
	return tokenAuth
}

type Server struct {
	Router    *chi.Mux
	DB        *sql.DB
	AuthToken *jwtauth.JWTAuth
}

func CreateServer(db *sql.DB) *Server {
	server := &Server{
		Router:    chi.NewRouter(),
		DB:        db,
		AuthToken: GenerateAuthToken(),
	}
	return server
}

func (s *Server) MountMiddleware() {
	s.Router.Use(middleware.Logger)
}

func (s *Server) MountHandlers() {
	s.Router.Route("/user", func(userRouter chi.Router) {
		userRouter.Post("/login", s.LoginUser)
		userRouter.Post("/", s.CreateUser)

		userRouter.Group(func(r chi.Router) {
			r.Use(jwtauth.Verifier(s.AuthToken))
			r.Use(jwtauth.Authenticator)

			r.Get("/{id}", s.GetUser)
		})
	})
}

type User struct {
	Id    int    `json:"id"`
	Email string `json:"email"`
	Hash  string `json:"hash"`
}

type UserRequestBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Response struct {
	Id int `json:"id"`
}

func ScanRow(rows *sql.Rows) (*User, error) {
	user := new(User)
	err := rows.Scan(&user.Id, &user.Email, &user.Hash)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func getHashPassword(password string) (string, error) {
	bytePassword := []byte(password)
	hash, err := bcrypt.GenerateFromPassword(bytePassword, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (s *Server) CreateUser(w http.ResponseWriter, r *http.Request) {
	userReqBody := new(UserRequestBody)
	if err := json.NewDecoder(r.Body).Decode(userReqBody); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("incorrect user data enterred"))
		return
	}

	hashPassword, err := getHashPassword(userReqBody.Password)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server issue accured"))
		return
	}

	query := `INSERT INTO User (email, hash) VALUES (?, ?)`
	result, err := s.DB.Exec(query, userReqBody.Email, hashPassword)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server issue accured"))
		return
	}
	recordId, _ := result.LastInsertId()
	response := Response{
		Id: int(recordId),
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func checkPassword(hashPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashPassword), []byte(password))
	return err == nil
}

func (s *Server) LoginUser(w http.ResponseWriter, r *http.Request) {
	userReqBody := new(UserRequestBody)
	if err := json.NewDecoder(r.Body).Decode(userReqBody); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("incorrect user data enterred"))
		return
	}
	query := `SELECT * FROM User where email = ?`
	rows, err := s.DB.Query(query, userReqBody.Email)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("incorrect user data enterred"))
		return
	}
	var user *User
	for rows.Next() {
		user, err = ScanRow(rows)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("internal server issue accured"))
			return
		}
	}

	if !checkPassword(user.Hash, userReqBody.Password) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("incorrect password enterred"))
		return
	}

	claims := map[string]interface{}{"id": user.Id, "email": user.Email}
	_, tokenString, err := s.AuthToken.Encode(claims)
	if err != nil {
		// 	w.WriteHeader(http.StatusInternalServerError)
		// 	w.Write([]byte("internal server issue accured"))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(tokenString))
}

func (s *Server) GetUser(w http.ResponseWriter, r *http.Request) {
	idParam := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idParam)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("incorrect password enterred"))
		return
	}

	_, claims, _ := jwtauth.FromContext(r.Context())
	idFromClaims := int(claims["id"].(float64))

	if id != idFromClaims {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("could not authorized"))
		return
	}

	query := `SELECT * FROM User WHERE id = ?`

	rows, err := s.DB.Query(query, id)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("could not authorized"))
		return
	}

	var user *User
	for rows.Next() {
		user, err = ScanRow(rows)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("internal server issue accured"))
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}

func main() {
	db, err := DBClient()
	if err != nil {
		log.Fatalln("could not connect to database:", err)
	}

	server := CreateServer(db)
	server.MountMiddleware()
	server.MountHandlers()
	fmt.Printf("server running on port%v\n", PORT)
	http.ListenAndServe(PORT, server.Router)
}
