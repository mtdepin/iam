package internal

import (
	"github.com/gorilla/mux"
)

// List of some generic handlers which are applied for all incoming requests.
var globalHandlers = []mux.MiddlewareFunc{}
