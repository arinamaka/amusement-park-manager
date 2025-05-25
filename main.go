package main

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var templates = template.Must(template.ParseGlob("templates/*.html"))
var db *sql.DB

type User struct {
	ID       int
	Name     string
	Email    string
	PhoneNr  string
	Password string
	Salt     string
	Admin    bool
}

type Ticket struct {
	ID   int
	Type string
	Used bool
	DateEmmited string
	DateExpiry string
	DateUsed string
	BuyerId int
}

type CreditCard struct {
	ID   int
	Name string
	Number int
	MonthExpiry int
	YearExpiry int
	CCV int
};

type Visitor struct {
	ID   int
	Name string
	CreditCardID int
}

func main() {
	var err error
	db, err = sql.Open("sqlite3", "./db.sqlite")
	defer db.Close()
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

	switch r.Method{
		case "POST":
		r.ParseForm()
		var ticket Ticket
		var card CreditCard
		var visitor Visitor
		ticket.Type = r.FormValue("type")
		card.Name = r.FormValue("cardname")
		card.Number, _ = strconv.Atoi(r.FormValue("cardnumber"))
		card.MonthExpiry, _ = strconv.Atoi(r.FormValue("expmonth"))
		card.YearExpiry, _ = strconv.Atoi(r.FormValue("expyear"))
		card.CCV, _ = strconv.Atoi(r.FormValue("cvv"))

		// Insert credit card
		result, err := db.Exec("INSERT INTO CreditCard (Name,Number,MonthExpiry,YearExpiry,CCV) VALUES (?,?,?,?,?) RETURNING ID", 
			card.Name, 
			card.Number,
			card.MonthExpiry, 
			card.YearExpiry,
			card.CCV)
		if err != nil {
			log.Printf("Scan error: %v", err)
			return
		}
		id, _ := result.LastInsertId()
		card.ID = int(id)
		log.Printf("CardID: %v", card.ID)

		// Insert Visitor, with cardID
		result, err = db.Exec("INSERT INTO Visitor (Name, CreditCardID) VALUES (?,?) RETURNING ID", card.Name, card.ID)
		if err != nil {
			log.Printf("Scan error: %v", err)
			return
		}
		id, _ = result.LastInsertId()
		visitor.ID = int(id)
		
		log.Printf("VisitorID: %v", visitor.ID)

		// Insert Ticket, with VisitorID
		_, err = db.Exec("INSERT INTO Ticket (Type, Used, DateEmmited, DateExpiry, DateUsed, BuyerId) VALUES (?,?,?,?,?,?)", 
			ticket.Type,
			false,
			time.Now().Format(time.RFC3339),
			time.Now().AddDate(0,1,0).Format(time.RFC3339), // Expires one month after purchase
			"0001-01-01T00:00:00Z",
			visitor.ID,
		)
		if err != nil {
			log.Printf("Scan error: %v", err)
			return
		}
		log.Print("Added Ticket!")
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
	rows, err := db.Query("SELECT * FROM Users "+query, values...)
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
		result, err := db.Exec("INSERT INTO Users (Name, Email, PhoneNr, Password, Salt, Admin) VALUES (?,?,?,?,?,?) RETURNING ID",
			r.FormValue("name"),
			r.FormValue("email"),
			r.FormValue("tel"),
			hashed_password,
			salt,
			true)
		log.Printf("Created user: %s with ID: %v, error: %v", r.FormValue("name"), result, err)
		http.Redirect(w, r, "/admin/", http.StatusSeeOther)
	default:
		break
	}
	templates.ExecuteTemplate(w, "base.html", map[string]interface{}{"register": true})
}
