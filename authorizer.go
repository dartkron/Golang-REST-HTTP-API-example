package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"github.com/gocql/gocql"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

// Struct to represent configuration file params
type configFile struct {
	Port        string
	Serverslist string
	Keyspace    string
}

// Simple structure to represent login and add user response
type newUserRequest struct {
	Username string
	Password string
}

// Function read configuration and set return configFile type
func readConfig(confFilePath string) (configFile, error) {
	var config configFile

	confFile, err := ioutil.ReadFile(confFilePath)
	if err != nil {
		return config, err

	}

	json.Unmarshal(confFile, &config)
	return config, nil
}

// Function for creating datastructures if they're not exist
func createDatastructure(session *gocql.Session, keyspace string) error {
	err := session.Query("CREATE KEYSPACE IF NOT EXISTS " + keyspace +
		" WITH REPLICATION = { 'class' : 'SimpleStrategy', 'replication_factor' : 1 }").Exec()
	if err != nil {
		return err
	}

	err = session.Query("CREATE TABLE IF NOT EXISTS " + keyspace + ".users (" +
		"username varchar," +
		"password varchar," +
		"PRIMARY KEY(username))").Exec()
	if err != nil {
		return err
	}

	err = session.Query("CREATE TABLE IF NOT EXISTS " + keyspace + ".sessions (" +
		"session_id varchar PRIMARY KEY," +
		"username varchar)").Exec()
	return err
}

// Generation random session ID and verifiyng that it is unique
func generateSessionId(session *gocql.Session) (string, error) {
	var session_id string
	count := 2
	size := 32
	rb := make([]byte, size)

	// generating session_id while it will be uniq(actually in most cases it will be uniq in a first time)
	for count != 0 {
		rand.Read(rb)
		session_id = base64.URLEncoding.EncodeToString(rb)
		err := session.Query("SELECT COUNT(*) from sessions where session_id = '" + session_id + "'").Scan(&count)
		if err != nil {
			return session_id, err
		}
	}

	return session_id, nil
}

// Router for /user/ functions. Routing based on request method, i.e. GET, POST, PUT, DELETE.
// Currently only for POST, but it made expandable :-)
func userHandler(w http.ResponseWriter, r *http.Request, session *gocql.Session) {

	body, _ := ioutil.ReadAll(r.Body)

	switch {
	case r.Method == "POST":
		error_code, err := createUser(&body, session)
		if err != nil {
			log.Println("Error on creating user: ", err, "\nClient: ", r.RemoteAddr, " Request: ", string(body))
		}
		http.Error(w, http.StatusText(error_code), error_code)

	default:
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}
}

// Router for /session/ functions. Routing based on request method, i.e. GET, POST, PUT, DELETE.
func sessionHandler(w http.ResponseWriter, r *http.Request, session *gocql.Session) {
	body, _ := ioutil.ReadAll(r.Body)

	switch {
	case r.Method == "POST":
		session_id, error_code, err := createSession(&body, session)
		if err != nil {
			log.Println("Error on creating session: ", err, "\nClient: ", r.RemoteAddr, " Request: ", string(body))
		}

		// Set expire for a one year, same as in sessions table
		if session_id != "" {
			expire := time.Now().AddDate(1, 0, 0)

			authCookie := &http.Cookie{
				Name:    "session_id",
				Expires: expire,
				Value:   session_id,
			}

			http.SetCookie(w, authCookie)
		}

		http.Error(w, http.StatusText(error_code), error_code)

	case r.Method == "GET":
		session_id, _ := r.Cookie("session_id")
		error_code, err := checkSession(session, session_id.Value)
		if err != nil {
			log.Println("Error on checking authorization: ", err)
		}
		http.Error(w, http.StatusText(error_code), error_code)
	case r.Method == "DELETE":
		session_id, _ := r.Cookie("session_id")
		error_code, err := deleteSession(session, session_id.Value)
		if err != nil {
			log.Println("Error on checking authorization: ", err)
		}

		// Rewrite session_id cookie with empty sting and set expiration now
		expire := time.Now()

		authCookie := &http.Cookie{
			Name:    "session_id",
			Expires: expire,
			Value:   "",
		}

		http.SetCookie(w, authCookie)

		http.Error(w, http.StatusText(error_code), error_code)
	default:
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}
}

// Function handle new use creating
func createUser(body *[]byte, session *gocql.Session) (int, error) {
	var request newUserRequest
	var count int

	err := json.Unmarshal(*body, &request)
	if err != nil {
		return http.StatusBadRequest, err
	}

	// Here should be call of function to extended validation, but nothing was in requirements
	if request.Password == "" || request.Username == "" {
		return http.StatusBadRequest, errors.New("User or password is empty")
	}

	// Check if such user already existing
	err = session.Query("SELECT COUNT(*) from users where username = '" + request.Username + "'").Scan(&count)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	if count > 0 {
		return http.StatusConflict, errors.New("Such user alredy existing")
	}

	// Prepare password hash to write it to DB
	hash := sha256.New()
	hash.Write([]byte(request.Password))

	err = session.Query("INSERT INTO users (username,password) VALUES (?,?)", request.Username, hex.EncodeToString(hash.Sum(nil))).Exec()
	if err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusCreated, nil
}

// Function handling creating new session
func createSession(body *[]byte, session *gocql.Session) (string, int, error) {
	var request newUserRequest
	var session_id string
	var count int

	err := json.Unmarshal(*body, &request)
	if err != nil {
		return session_id, http.StatusBadRequest, err
	}

	// Here should be call of function to extended validation, but nothing was in requirements
	if request.Password == "" || request.Username == "" {
		return session_id, http.StatusBadRequest, errors.New("User or password is empty")
	}

	// Prepare password hash to make request to DB
	hash := sha256.New()
	hash.Write([]byte(request.Password))

	// Check if user and password is valid
	err = session.Query("SELECT COUNT(*) from users where username = '" + request.Username + "' and password ='" + hex.EncodeToString(hash.Sum(nil)) + "'").Scan(&count)
	if err != nil {
		return session_id, http.StatusInternalServerError, err
	}

	if count == 0 {
		return session_id, http.StatusUnauthorized, errors.New("User name or password is not correct")
	}

	// prepare session ID for a new session
	session_id, err = generateSessionId(session)
	if err != nil {
		return session_id, http.StatusInternalServerError, err
	}

	// set TTL to a one year to expire in same time with cookie
	err = session.Query("INSERT INTO sessions (session_id,username) VALUES (?,?) USING TTL 31536000", session_id, request.Username).Exec()
	if err != nil {
		return session_id, http.StatusInternalServerError, err
	}

	return session_id, http.StatusCreated, nil
}

// Function checking if provided cookie matching to active sessions
func checkSession(session *gocql.Session, session_id string) (int, error) {
	var count int

	// fast path to don't use DB when session_id cookie not indicated at all
	if session_id == "" {
		return http.StatusUnauthorized, nil
	}

	// Check if such session exist
	err := session.Query("SELECT COUNT(*) from sessions where session_id = '" + session_id + "'").Scan(&count)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	if count == 0 {
		return http.StatusUnauthorized, nil
	} else {
		return http.StatusOK, nil
	}

}

func deleteSession(session *gocql.Session, session_id string) (int, error) {
	// fast path to don't use DB when session_id cookie not indicated at all
	if session_id == "" {
		return http.StatusUnauthorized, nil
	}

	// removing session for DB
	err := session.Query("DELETE FROM sessions WHERE session_id = '" + session_id + "'").Exec()
	if err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil

}

func main() {

	confFilePath := flag.String("conf", "config.json", "path to application config")
	flag.Parse()

	config, err := readConfig(*confFilePath)
	if err != nil {
		log.Fatal("Couldn't read config file ", err)
	}

	// Initialize Cassandra cluster
	cluster := gocql.NewCluster(strings.Split(config.Serverslist, ",")...)

	// Establish connection to Cassandra
	session, err := cluster.CreateSession()
	if err != nil {
		log.Fatal(err)
	}

	// Creating necessary datastructures
	err = createDatastructure(session, config.Keyspace)
	if err != nil {
		log.Fatal("Get an error while creating datastructures: ", err)
	}

	// Close old session and open newly to created(or already existed) keyspace
	// This is a limitation of gocql library https://github.com/gocql/gocql#important-default-keyspace-changes
	session.Close()
	cluster.Keyspace = config.Keyspace
	session, _ = cluster.CreateSession()
	defer session.Close()

	// If someone ask root, reply 404
	http.HandleFunc("/", http.NotFound)

	http.HandleFunc("/user/", func(w http.ResponseWriter, r *http.Request) { userHandler(w, r, session) })
	http.HandleFunc("/session/", func(w http.ResponseWriter, r *http.Request) { sessionHandler(w, r, session) })

	err = http.ListenAndServe(":"+config.Port, nil)

	if err != nil {
		log.Fatal("Error on creating listener: ", err)
	}

	log.Println("Authorizer closed.")
}
