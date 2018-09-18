package main

import (
	"faith-core/app"
	"faith-core/controllers"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

var Server *http.Server

func main() {

	router := mux.NewRouter()
	router.Use(app.JwtAuthentication) //attach JWT auth middleware

	port := os.Getenv("PORT") //Get port from .env file, we did not specify any port so this should return an empty string when tested locally
	if port == "" {
		port = "8000" //localhost
	}

	router.HandleFunc("/api/user/new", controllers.CreateAccount).Methods("POST")
	router.HandleFunc("/api/user/login", controllers.Authenticate).Methods("POST")

	fmt.Println(port)

	Server = &http.Server{
		Addr:    "0.0.0.0:" + port,
		Handler: router,
	}

	log.Fatal(Server.ListenAndServe()) //Launch the app, visit localhost:8000/api
}
