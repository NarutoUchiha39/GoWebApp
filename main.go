package main

import (
	"context"
	"html/template"
	"io"
	"log"
	"os"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/crypto/bcrypt"
)

type database struct {
	conn *pgxpool.Pool
	err  error
}

type page_error struct {
	Err []string
}

type custom_template struct {
	template *template.Template
}

func (t *custom_template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.template.ExecuteTemplate(w, name, data)
}

func createTemplate() *custom_template {
	return &custom_template{template: template.Must(template.ParseGlob("templates/**/*.html"))}
}

func load_env() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Could not load env")
	}
}

func connect_db(database_struct *database) {
	postgresURL := os.Getenv("POSTGRES_URL")

	config, err := pgxpool.ParseConfig(postgresURL)
	if err != nil {
		log.Fatalf("Unable to parse database URL: %v", err)
	}

	conn, err := pgxpool.NewWithConfig(context.Background(), config)

	if err != nil {
		database_struct.err = err
		log.Fatalf("Unable to connect to database: %v", err)
	} else {
		database_struct.conn = conn

	}

}

func getMessages(c echo.Context) []string {
	sess, _ := session.Get("session", c)
	flashes := sess.Flashes()
	messages := []string{}

	for _, r := range flashes {
		messages = append(messages, r.(string))
	}
	sess.Save(c.Request(), c.Response())
	return messages
}

func addFlashMessages(sess *sessions.Session, c echo.Context, message string) {

	sess.AddFlash(message)
	sess.Save(c.Request(), c.Response())
}

func main() {
	db_struct := &database{}
	load_env()
	connect_db(db_struct)

	if db_struct.err != nil {
		log.Fatalf("Database connection error: %v", db_struct.err)
	}

	e := echo.New()
	e.Use(middleware.Logger())
	e.Renderer = createTemplate()
	e.Static("/static", "templates")
	e.Use(session.Middleware(sessions.NewCookieStore([]byte(os.Getenv("Secret")))))

	e.GET("/login", func(c echo.Context) error {
		messages := getMessages(c)
		if len(messages) != 0 {
			log.Printf("Session_Login %s \n", messages[0])
		}
		return c.Render(200, "login", page_error{Err: messages})
	})

	e.GET("/signup", func(c echo.Context) error {
		messages := getMessages(c)
		return c.Render(200, "signup", page_error{Err: messages})
	})

	e.POST("/verify_signup", func(c echo.Context) error {
		email := c.FormValue("email")
		password := c.FormValue("password")
		phone_number := c.FormValue("PhoneNumber")
		name := c.FormValue("name")
		password_byte := append([]byte{}, password...)
		sess, _ := session.Get("session", c)

		hash, _ := bcrypt.GenerateFromPassword(password_byte, bcrypt.DefaultCost)

		s := strings.Builder{}
		s.Write(hash)

		rows, err := db_struct.conn.Query(context.Background(), "select * from contacts where (email=$1 or mobile_number=$2)", pgx.QueryExecModeSimpleProtocol, email, phone_number)

		if err != nil {
			addFlashMessages(sess, c, "Something Went wrong! Try again Later")
			return c.Redirect(302, "/signup")
		}

		length := 0

		for rows.Next() {
			length++
			break
		}

		if length != 0 {
			addFlashMessages(sess, c, "User Exists!")
			return c.Redirect(302, "/signup")
		} else {
			res, err := db_struct.conn.Exec(context.Background(), "INSERT INTO CONTACTS(email,profile_picture,name_,mobile_number,password) VALUES($1,$2,$3,$4,$5)", pgx.QueryExecModeSimpleProtocol, email, "NULL", name, phone_number, s.String())

			if err == nil {
				if res.Insert() {
					addFlashMessages(sess, c, "Signed Up Successfully !")
					return c.Redirect(302, "/")
				}

			}
			addFlashMessages(sess, c, "Something Went wrong! Try again Later")
			return c.Redirect(302, "/signup")
		}

	})

	e.POST("/verify_login", func(c echo.Context) error {
		email := c.FormValue("email")
		password := c.FormValue("password")
		sess, _ := session.Get("session", c)

		var password_ string
		err := db_struct.conn.QueryRow(context.Background(), "SELECT password FROM contacts WHERE email=$1", pgx.QueryExecModeSimpleProtocol, email).Scan(&password_)
		if err != nil {
			addFlashMessages(sess, c, "User does not exists!")
			return c.Redirect(302, "/login")
		}

		err = bcrypt.CompareHashAndPassword([]byte(password_), []byte(password))
		if err != nil {
			addFlashMessages(sess, c, err.Error())
			return c.Redirect(302, "/login")
		}
		return c.Redirect(302, "/")
	})

	e.GET("/", func(c echo.Context) error {

		return c.Render(200, "base", nil)
	})

	e.Logger.Fatal(e.Start("localhost:5000"))
}
