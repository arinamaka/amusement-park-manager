package main

import (
	// "database/sql"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"time"
	"fmt"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"golang.org/x/crypto/bcrypt"
)

const DB_URL = "db.sqlite"

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
	ID           uint
	CreatedAt    time.Time
	ExpiresAt    time.Time
	BuyerID      int
	Buyer        Visitor
	AttractionID int
	Attraction   Attraction
}

type CreditCard struct {
	ID          uint
	Name        string
	Number      int
	MonthExpiry int
	YearExpiry  int
	CCV         int
}

type Visitor struct {
	ID           uint
	Name         string
	CreditCardID int
	CreditCard   CreditCard
}

type Event struct {
	ID          uint
	Date        time.Time
	Name        string
	Description string
}

type Attraction struct {
	ID       uint
	Name     string
	Type     string
	Capacity uint
	Price    uint
}

func main() {
	var err error
	db, err = gorm.Open(sqlite.Open(DB_URL), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database: ", err)
	}

	db.AutoMigrate(&User{}, &Ticket{}, &CreditCard{}, &Visitor{}, &Event{}, &Attraction{})

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/price", priceHandler)
	http.HandleFunc("/admin/", adminHandler)
	http.HandleFunc("/admin/events", adminEventsHandler)
	http.HandleFunc("/admin/events/edit", adminEventsEditHandler)
	http.HandleFunc("/admin/attractions", adminAttractionsHandler)
	http.HandleFunc("/admin/attractions/edit", adminAttractionsEditHandler)
	http.HandleFunc("/admin/tickets", adminTicketsHandler)
	http.HandleFunc("/admin/visitors", adminVisitorsHandler)
	http.HandleFunc("/admin/login", loginHandler)
	http.HandleFunc("/admin/register", registerHandler)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	log.Println("[Server] Staring server on http://127.0.0.1:8000")
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
	if err != nil || session_id == nil {
		return nil
	}

	var user User
	db.First(&user, session_id.Value)
	log.Printf("[Session] %v, %v", user.ID, user.Email)
	return &user
}

func priceHandler(w http.ResponseWriter, r *http.Request) {
	if !doesPageExist(w, r, "/price") {
		return
	}

	id := r.URL.Query()["attraction"]
	var attraction Attraction
	db.Where("ID = ?", id).First(&attraction)
	fmt.Fprintf(w,"%d", attraction.Price)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if !doesPageExist(w, r, "/") {
		return
	}
	
	switch r.Method {
	case "POST":
		r.ParseForm()
		attractionID, _ := strconv.Atoi(r.FormValue("attraction"))
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
		createdAt := time.Now() //.Format("2006-01-02T15:04")
		expiresAt := time.Now() //.Format("2006-01-02T15:04")

		// Find attraction
		var attraction Attraction
		db.Where("ID = ?", attractionID).First(&attraction)

		ticket := Ticket{CreatedAt: createdAt, ExpiresAt: expiresAt, Attraction: attraction, Buyer: visitor}
		result = db.Create(&ticket)
		if result.Error != nil {
			log.Printf("error inserting credit card: %v", result.Error)
			return
		}
		log.Print("Added Ticket!")
	}
	
	var events []Event
	result := db.Find(&events)
	if result.Error != nil {
		log.Printf("Failed to find events: %v", result.Error)
	}
	
	
	var attractions []Attraction
	result = db.Find(&attractions)
	if result.Error != nil {
		log.Printf("Failed to find attractions: %v", result.Error)
	}

	data := map[string]interface{}{
		"attractions": attractions,
		"events": events,
	}

	templates.ExecuteTemplate(w, "index.html", data)
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	if !doesPageExist(w, r, "/admin/") {
		return
	}

	user := isAuthentificated(w, r)
	if user == nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	var visitors_day int64
	var tickets int64
	db.Model(&Visitor{}).Count(&visitors_day)
	db.Model(&Ticket{}).Count(&tickets)

	var income uint
	db.Model(&Ticket{}).
		Select("SUM(attractions.price)").
		Joins("JOIN attractions ON tickets.attraction_id = attractions.id").
		Scan(&income)

	data := map[string]interface{}{
		"user":         user.Name,
		"page":         "Dashboard",
		"page_link":    "/admin/",
		"visitors_day": visitors_day,
		"tickets":      tickets,
		"income":       income,
	}
	templates.ExecuteTemplate(w, "base.html", data)
}

func adminEventsHandler(w http.ResponseWriter, r *http.Request) {
	if !doesPageExist(w, r, "/admin/events") {
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
		date, _ := time.Parse("2006-01-02T15:04", r.FormValue("date"))
		name := r.FormValue("name")
		description := r.FormValue("description")

		if name == "" {
			break
		}

		event := Event{Date: date, Name: name, Description: description}
		result := db.Create(&event)
		if result.Error != nil {
			log.Printf("Failed to create event: %v", result.Error)
		}

		log.Printf("Created event: %s", name)
	}
	var events []Event
	result := db.Find(&events)
	if result.Error != nil {
		log.Printf("Failed to create event: %v", result.Error)
	}

	data := map[string]interface{}{
		"user":      user.Name,
		"page":      "Evenimente",
		"page_link": "/admin/events",
		"data":      events,
	}
	templates.ExecuteTemplate(w, "base.html", data)

}

func adminEventsEditHandler(w http.ResponseWriter, r *http.Request) {
	if !doesPageExist(w, r, "/admin/events/edit") {
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

func adminAttractionsHandler(w http.ResponseWriter, r *http.Request) {
	if !doesPageExist(w, r, "/admin/attractions") {
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
		name := r.FormValue("name")
		typ := r.FormValue("type")
		capacity, _ := strconv.Atoi(r.FormValue("capacity"))
		price, _ := strconv.Atoi(r.FormValue("price"))

		if name == "" {
			break
		}

		attraction := Attraction{Name: name, Type: typ, Capacity: uint(capacity), Price: uint(price)}
		result := db.Create(&attraction)
		if result.Error != nil {
			log.Printf("Failed to create attraction: %v", result.Error)
		}

		log.Printf("Created attraction: %s", name)
	}
	var attractions []Attraction
	result := db.Find(&attractions)
	if result.Error != nil {
		log.Printf("Failed to create event: %v", result.Error)
	}

	data := map[string]interface{}{
		"user":      user.Name,
		"page":      "Atractii",
		"page_link": "/admin/attractions",
		"data":      attractions,
	}
	templates.ExecuteTemplate(w, "base.html", data)
}

func adminAttractionsEditHandler(w http.ResponseWriter, r *http.Request) {
	if !doesPageExist(w, r, "/admin/attractions/edit") {
		return
	}

	if r.Method != "PUT" {
		http.Error(w, "Method Not Supported", http.StatusMethodNotAllowed)
		return
	}

	err := templates.ExecuteTemplate(w, "attractions_edit.html", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func adminTicketsHandler(w http.ResponseWriter, r *http.Request) {
	if !doesPageExist(w, r, "/admin/tickets") {
		return
	}
	user := isAuthentificated(w, r)
	if user == nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	var tickets []Ticket
	result := db.Find(&tickets)
	if result.Error != nil {
		log.Printf("Failed to query tickets: %v", result.Error)
	}

	data := map[string]interface{}{
		"user":      user.Name,
		"page":      "Bilete",
		"page_link": "/admin/tickets",
		"data":      tickets,
	}
	templates.ExecuteTemplate(w, "base.html", data)
}

func adminVisitorsHandler(w http.ResponseWriter, r *http.Request) {
	if !doesPageExist(w, r, "/admin/visitors") {
		return
	}
	user := isAuthentificated(w, r)
	if user == nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	var visitors []Visitor
	err := db.Preload("CreditCard").Find(&visitors).Error
	if err != nil {
		log.Printf("Failed to query visitors: %v", err)
	}

	data := map[string]interface{}{
		"user":      user.Name,
		"page":      "Vizitatori",
		"page_link": "/admin/visitors",
		"data":      visitors,
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
		user := User{Name: name, Email: email, PhoneNr: &tel, Password: hashed_password, Salt: salt, Admin: true}
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
