package controller

import (
	"github.com/raffaelespazzoli/secret-utils-operator/pkg/controller/certexpiryalert"
)

func init() {
	// AddToManagerFuncs is a list of functions to create controllers and add them to a manager.
	AddToManagerFuncs = append(AddToManagerFuncs, certexpiryalert.Add)
}
