package controller

import (
	"github.com/redhat-cop/cert-utils-operator/pkg/controller/configmaptokeystore"
)

func init() {
	// AddToManagerFuncs is a list of functions to create controllers and add them to a manager.
	AddToManagerFuncs = append(AddToManagerFuncs, configmaptokeystore.Add)
}
