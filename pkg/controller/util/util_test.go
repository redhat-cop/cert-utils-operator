package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateConfigMapNameValid(t *testing.T) {
	err := ValidateConfigMapName("namespace/resource-name")

	assert.Nil(t, err)
}

func TestValidateConfigMapNameInValid(t *testing.T) {
	err := ValidateConfigMapName("namespace")

	assert.Equal(t, "Invalid ca configmap name does not match format {namespace}/{configmap-name}", err.Error())
}
