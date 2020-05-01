package util

import (
	"errors"
	"strings"
)

const TLSSecret = "kubernetes.io/tls"
const AnnotationBase = "cert-utils-operator.redhat-cop.io"
const Cert = "tls.crt"
const Key = "tls.key"
const CA = "ca.crt"

func ValidateSecretName(secretNamespacedName string) error {
	if strings.Index(secretNamespacedName, "/") == -1 {
		err := errors.New("Invalid ca secret name does not match format {namespace}/{secert-name}")
		return err
	}

	return nil
}
