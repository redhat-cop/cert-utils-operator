package controller

import (
	"github.com/raffaelespazzoli/cert-utils-operator/pkg/controller/secretinfo"
)

func init() {
	// AddToManagerFuncs is a list of functions to create controllers and add them to a manager.
	AddToManagerFuncs = append(AddToManagerFuncs, secretinfo.Add)
}
