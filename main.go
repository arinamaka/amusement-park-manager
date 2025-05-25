package main

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"time"

	"gorm.io/gorm"
	"gorm.io/driver/sqlite"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

const DB_URL = "test.sqlite"

var templates = template.Must(template.ParseGlob("templates/*.html"))
var db *gorm.DB

type User struct {
	ID       uint
	Name     string
	Email    string
	PhoneNr  *string
	Password string
	Salt     string
	Admin    bool
}

type Ticket struct {
	ID   uint
	Type string
	Used bool
	CreatedAt time.Time
	ExpiresAt sql.NullTime
	UsedAt sql.NullTime
	BuyerID int
	Buyer Visitor
}

type CreditCard struct {
	ID   uint
	Name string
	Number int
	MonthExpiry int
	YearExpiry int
	CCV int
};

type Visitor struct {
	ID   uint
	Name string
	CreditCardID int
	CreditCard CreditCard
}

type Event struct {
	ID uint
	Date time.Time
	Name string
	Description string
}

func main() {
	var err error
	db, err = gorm.Open(sqlite.Open(DB_URL), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database: ", err)
	}

	db.AutoMigrate(&User{}, &Ticket{},&CreditCard{}, &Visitor{}, &Event{})
	
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/admin/", adminHandler)
	http.HandleFunc("/admin/events", adminEventsHandler)
	http.HandleFunc("/admin/events/edit", adminEventsEditHandler)
	http.HandleFunc("/admin/login", loginHandler)
	http.HandleFunc("/admin/register", registerHandler)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	log.Println("[Server] Staring server on http://localhost:8000")
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

func doesPageExist(w http.ResponseWriter, r *http.Request, path string) bool {
	if r.URL.Path != path {
		http.NotFound(w, r)
		log.Printf("[404] '%v", r.URL.Path)
		return false
	}
	return true
}


func isAuthentificated(w http.ResponseWriter, r *http.Request) *User {
	session_id, err := r.Cookie("session")
	if err != nil || session_id == nil{
		return nil
	}

	var user User
	db.First(&user, session_id.Value)
	log.Printf("[Session] %v, %v", user.ID, user.Email)
	return &user
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if !doesPageExist(w,r, "/") {
		return
	}

	switch r.Method{
		case "POST":
		r.ParseForm()
		typ := r.FormValue("type")
		cardname := r.FormValue("cardname")
		cardnumber, _ := strconv.Atoi(r.FormValue("cardnumber"))
		expmonth, _ := strconv.Atoi(r.FormValue("expmonth"))
		expyear, _ := strconv.Atoi(r.FormValue("expyear"))
		ccv, _ := strconv.Atoi(r.FormValue("cvv"))
		
		// Insert credit card
		card := CreditCard{Name: cardname, Number: cardnumber, MonthExpiry: expmonth, YearExpiry: expyear, CCV: ccv}
		result := db.Create(&card)
		if result.Error != nil {
			log.Printf("error inserting credit card: %v", card.ID)
			return
		}
		log.Printf("CardID: %v", card.ID)

		// Insert Visitor, with cardID
		visitor := Visitor{Name: cardname, CreditCard: card}
		result = db.Create(&visitor)
		if result.Error != nil {
			log.Printf("error inserting credit card: %v", result)
			return
		}
		log.Printf("VisitorID: %v", visitor.ID)

		// Insert Ticket, with VisitorID
		// createdAt := time.Now().Format(time.RFC3339)
		ticket := Ticket{Type:typ, Used: false, Buyer: visitor}
		result = db.Create(&ticket)
		if result.Error != nil {
			log.Printf("error inserting credit card: %v", result.Error)
			return
		}
		log.Print("Added Ticket!")
	}
	templates.ExecuteTemplate(w, "index.html", nil)
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	if !doesPageExist(w,r, "/admin/") {
		return
	}
	
	user := isAuthentificated(w, r)
	if user == nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	
	data := map[string]interface{}{
		"user": user.Name,
		"page": "Dashboard",
		"page_link": "/admin/",
	}
	templates.ExecuteTemplate(w, "base.html", data)
}

func adminEventsEditHandler(w http.ResponseWriter, r *http.Request) {
	if !doesPageExist(w,r, "/admin/events/edit") {
		return
	}

	if r.Method != "PUT" {
		http.Error(w, "Method Not Supported", http.StatusMethodNotAllowed)
		return
	}

	
	err := templates.ExecuteTemplate(w, "event_edit.html", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func adminEventsHandler(w http.ResponseWriter, r *http.Request) {
	if !doesPageExist(w,r, "/admin/events") {
		return
	}
	user := isAuthentificated(w, r)
	if user == nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	switch r.Method {
	case "POST":
		r.ParseForm()
		date, _ := time.Parse("2006-01-02T15:04",r.FormValue("date"))
		name := r.FormValue("name")
		description := r.FormValue("description")

		event := Event{Date:date, Name:name, Description:description}
		result := db.Create(&event)
		if result.Error != nil {
			log.Printf("Failed to create event: %v", result.Error)
		}
		
		log.Printf("Created event: %s", name)
	}
	
	data := map[string]interface{}{
		"user": user.Name,
		"page": "Evenimente",
		"page_link": "/admin/events",
	}
	templates.ExecuteTemplate(w, "base.html", data)

	
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		r.ParseForm()
		email := r.FormValue("email")
		password := r.FormValue("password")
		
		var user User
		db.Where("email = ?", email).First(&user)
		
		if email == user.Email && checkPasswordHash(password, user.Email, user.Password) {
			log.Printf("Authenificated user: %s (%v,%v,%v,%v,%v,%v,%v)", email, user.ID, user.Name, user.Email, user.PhoneNr, user.Password, user.Salt, user.Admin)
			http.SetCookie(w, &http.Cookie{
				Name:     "session",
				Value:    strconv.Itoa(int(user.ID)),
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
		name := r.FormValue("name")
		email := r.FormValue("email")
		tel := r.FormValue("tel")
		password := r.FormValue("password")
		
		salt := email // using email as salt
		hashed_password, _ := hashPassword(password, salt)

		//TODO: Validate input, ex. Don't let users with a email that is already used.
		user := User{Name:name, Email: email, PhoneNr: &tel, Password: hashed_password, Salt: salt, Admin:true}
		result := db.Create(&user)
		if result.Error != nil {
			log.Printf("Failed to create user: %v", result.Error)
		}
		log.Printf("Created user: %s", name)
		http.Redirect(w, r, "/admin/", http.StatusSeeOther)
	default:
		break
	}
	templates.ExecuteTemplate(w, "base.html", map[string]interface{}{"register": true})
}
