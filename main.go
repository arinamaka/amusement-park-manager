package main

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"
	"strconv"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var templates = template.Must(template.ParseGlob("templates/*.html"))
var pool *sql.DB

type User struct {
	ID       int
	Name     string
	Email    string
	PhoneNr  string
	Password string
	Salt     string
	Admin    bool
}

func main() {
	var err error
	pool, err = sql.Open("sqlite3", "./db.sqlite")
	defer pool.Close()
	if err != nil {
		log.Fatal("Unable to open database", err)
	}

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/admin/", adminHandler)
	http.HandleFunc("/admin/login", loginHandler)
	http.HandleFunc("/admin/register", registerHandler)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	log.Println("Staring server on http://localhost:8000")
	log.Fatal(http.ListenAndServe(":8000", nil))
}

func hashPassword(password, salt string) (string, error) {
	bytes := []byte(password + salt)
	hashed, err := bcrypt.GenerateFromPassword(bytes, 14)
	return string(hashed), err
}

func checkPasswordHash(password, salt, hash string) bool {
	bytes := []byte(password + salt)
	err := bcrypt.CompareHashAndPassword([]byte(hash), bytes)
	return err == nil
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	templates.ExecuteTemplate(w, "index.html", nil)
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin/" {
		http.NotFound(w, r)
		return
	}
	session_id, err := r.Cookie("session")
	if err != nil {
		log.Printf("Cookie error: %v", err)
	}
	if session_id == nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	users := queryUsers("WHERE ID=?", session_id.Value)
	log.Printf("SessionID: %v, Users: %v", session_id.Value, users)

	data := map[string]interface{}{
		"user": users[0].Name,
	}
	templates.ExecuteTemplate(w, "base.html", data)
}

func queryUsers(query string, values ...any) []User {
	rows, err := pool.Query("SELECT * FROM Users "+query, values...)
	// log.Printf("q: %v %v","SELECT * FROM Users " + query, values)
	if err != nil {
		log.Printf("error: Query error %v.", err)
	}
	result := []User{}
	for rows.Next() {
		var user User
		err = rows.Scan(&user.ID, &user.Name, &user.Email, &user.PhoneNr, &user.Password, &user.Salt, &user.Admin)
		if err != nil {
			log.Printf("error: Scan error %v.", err)
			continue
		}
		result = append(result, user)
	}
	return result
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		r.ParseForm()
		users := queryUsers("WHERE Email=?", r.FormValue("email"))
		if len(users) == 0 {
			templates.ExecuteTemplate(w, "base.html", map[string]interface{}{"error": "Parola sau E-mail gresit."})
			return
		}
		user := users[0]

		// err := pool.QueryRow("SELECT * FROM Users WHERE Email=?",r.FormValue("email")).Scan(&uer.ID,&uer.Name,&user.Email,&user.PhoneNr,&user.Password,&user.Salt,&user.Admin)
		// if err == sql.ErrNoRows {
		// log.Printf("No user with email: %v", r.FormValue("email"))
		// }else if err != nil {
		// log.Printf("Querry error: %v", err)
		// } else {

		if r.FormValue("email") == user.Email && checkPasswordHash(r.FormValue("password"), user.Email, user.Password) {
			log.Printf("Authenificated user: %s (%v,%v,%v,%v,%v,%v,%v)", r.FormValue("email"), user.ID, user.Name, user.Email, user.PhoneNr, user.Password, user.Salt, user.Admin)

			http.SetCookie(w, &http.Cookie{
				Name:     "session",
				Value:    strconv.Itoa(user.ID),
				Path:     "/",
				HttpOnly: true,
			})
			http.Redirect(w, r, "/admin/", http.StatusSeeOther)
			return
		} else {
			templates.ExecuteTemplate(w, "base.html", map[string]interface{}{"error": "Parola sau E-mail gresit."})
		}
	}
	templates.ExecuteTemplate(w, "base.html", nil)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		r.ParseForm()
		log.Printf("Register user: %s\n", r.FormValue("name"))

		password := r.FormValue("password")
		salt := r.FormValue("email") // using email as salt
		hashed_password, _ := hashPassword(password, salt)

		//TODO: Validate input, ex. Don't let users with a email that is already used.
		result, err := pool.Exec("INSERT INTO Users (Name, Email, PhoneNr, Password, Salt, Admin) VALUES (?,?,?,?,?,?) RETURNING ID",
			r.FormValue("name"),
			r.FormValue("email"),
			r.FormValue("tel"),
			hashed_password,
			salt,
			true)
		log.Printf("Created user: %s Password: %v salt: %v (%v, %v)", r.FormValue("name"), hashed_password, salt, result, err)
		http.Redirect(w, r, "/admin/", http.StatusSeeOther)
	default:
		break
	}
	templates.ExecuteTemplate(w, "base.html", map[string]interface{}{"register": true})
}
