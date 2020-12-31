package secrettokeystore

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	keystore "github.com/pavel-v-chernykh/keystore-go"
	"github.com/redhat-cop/cert-utils-operator/controllers/util"
	outils "github.com/redhat-cop/operator-utils/pkg/util"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const javaKeyStoresAnnotation = util.AnnotationBase + "/generate-java-keystores"
const keystorepasswordAnnotation = util.AnnotationBase + "/java-keystore-password"
const defaultpassword = "changeme"
const keystoreName = "keystore.jks"
const truststoreName = "truststore.jks"

// SecretToKeyStoreReconciler reconciles a Namespace object
type SecretToKeyStoreReconciler struct {
	outils.ReconcilerBase
	Log            logr.Logger
	controllerName string
}

// SetupWithManager sets up the controller with the Manager.
func (r *SecretToKeyStoreReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.controllerName = "secret_to_keystore_controller"

	isAnnotatedSecret := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldSecret, ok := e.ObjectOld.(*corev1.Secret)
			if !ok {
				return false
			}
			newSecret, ok := e.ObjectNew.(*corev1.Secret)
			if !ok {
				return false
			}
			if newSecret.Type != util.TLSSecret {
				return false
			}
			oldValue, _ := e.ObjectOld.GetAnnotations()[javaKeyStoresAnnotation]
			newValue, _ := e.ObjectNew.GetAnnotations()[javaKeyStoresAnnotation]
			old := oldValue == "true"
			new := newValue == "true"
			// if the content has changed we trigger is the annotation is there
			if !reflect.DeepEqual(newSecret.Data[util.Cert], oldSecret.Data[util.Cert]) ||
				!reflect.DeepEqual(newSecret.Data[util.Key], oldSecret.Data[util.Key]) ||
				!reflect.DeepEqual(newSecret.Data[util.CA], oldSecret.Data[util.CA]) {
				return new
			}
			// otherwise we trigger if the annotation has changed
			return old != new
		},
		CreateFunc: func(e event.CreateEvent) bool {
			secret, ok := e.Object.(*corev1.Secret)
			if !ok {
				return false
			}
			if secret.Type != util.TLSSecret {
				return false
			}
			value, _ := e.Object.GetAnnotations()[javaKeyStoresAnnotation]
			return value == "true"
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{
			TypeMeta: v1.TypeMeta{
				Kind: "Secret",
			},
		}, builder.WithPredicates(isAnnotatedSecret)).
		Complete(r)
}

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=get;list;watch;create;patch

func (r *SecretToKeyStoreReconciler) Reconcile(context context.Context, req ctrl.Request) (reconcile.Result, error) {
	log := r.Log.WithValues("secret_to_keystore_contoller", req.NamespacedName)

	// Fetch the Secret instance
	instance := &corev1.Secret{}
	err := r.GetClient().Get(context, req.NamespacedName, instance)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}
	value, _ := instance.GetAnnotations()[javaKeyStoresAnnotation]
	if value == "true" {
		if value, ok := instance.Data[util.Cert]; ok && len(value) != 0 {
			if value, ok := instance.Data[util.Key]; ok && len(value) != 0 {
				keyStore, err := r.getKeyStoreFromSecret(instance)
				if err != nil {
					log.Error(err, "unable to create keystore from secret", "secret", instance.Namespace+"/"+instance.Name)
					return reconcile.Result{}, err
				}
				instance.Data[keystoreName] = keyStore
			}
		}
		if value, ok := instance.Data[util.CA]; ok && len(value) != 0 {
			trustStore, err := r.getTrustStoreFromSecret(instance)
			if err != nil {
				log.Error(err, "unable to create truststore from secret", "secret", instance.Namespace+"/"+instance.Name)
				return reconcile.Result{}, err
			}
			instance.Data[truststoreName] = trustStore
		}
	} else {
		delete(instance.Data, keystoreName)
		delete(instance.Data, truststoreName)
	}

	err = r.GetClient().Update(context, instance)
	if err != nil {
		log.Error(err, "unable to update secrer", "secret", instance.GetName())
		return r.ManageError(context, instance, err)
	}

	return r.ManageSuccess(context, instance)
}

func (r *SecretToKeyStoreReconciler) getKeyStoreFromSecret(secret *corev1.Secret) ([]byte, error) {
	keyStore := keystore.KeyStore{}
	key, ok := secret.Data[util.Key]
	if !ok {
		return []byte{}, errors.New("tls.key not found")
	}
	crt, ok := secret.Data[util.Cert]
	if !ok {
		return []byte{}, errors.New("tls.crt not found")
	}
	certs := []keystore.Certificate{}
	for p, rest := pem.Decode(crt); p != nil; p, rest = pem.Decode(rest) {
		certs = append(certs, keystore.Certificate{
			Type:    "X.509",
			Content: p.Bytes,
		})
	}
	p, _ := pem.Decode(key)
	if p == nil {
		return []byte{}, errors.New("no block found in key.tls, private key should have at least one pem block")
	}
	if !strings.Contains(p.Type, "PRIVATE KEY") {
		return []byte{}, errors.New("private key block not of type PRIVATE KEY")
	}

	keyStore["alias"] = &keystore.PrivateKeyEntry{
		Entry: keystore.Entry{
			CreationDate: time.Now(),
		},
		PrivKey:   p.Bytes,
		CertChain: certs,
	}
	buffer := bytes.Buffer{}
	err := keystore.Encode(&buffer, keyStore, []byte(getPassword(secret)))
	if err != nil {
		r.Log.Error(err, "unable to encode keystore", "keystore", keyStore)
		return []byte{}, err
	}
	return buffer.Bytes(), nil
}

func (r *SecretToKeyStoreReconciler) getTrustStoreFromSecret(secret *corev1.Secret) ([]byte, error) {
	keyStore := keystore.KeyStore{}
	ca, ok := secret.Data[util.CA]
	if !ok {
		return []byte{}, errors.New("ca bundle key not found: ca.crt")
	}
	i := 0
	for p, rest := pem.Decode(ca); p != nil; p, rest = pem.Decode(rest) {
		keyStore["alias"+strconv.Itoa(i)] = &keystore.TrustedCertificateEntry{
			Entry: keystore.Entry{
				CreationDate: time.Now(),
			},
			Certificate: keystore.Certificate{
				Type:    "X.509",
				Content: p.Bytes,
			},
		}

		// increment counter
		i++
	}
	buffer := bytes.Buffer{}
	err := keystore.Encode(&buffer, keyStore, []byte(getPassword(secret)))
	if err != nil {
		r.Log.Error(err, "unable to encode keystore", "keystore", keyStore)
		return []byte{}, err
	}
	return buffer.Bytes(), nil
}

func getPassword(secret *corev1.Secret) string {
	if pwd, ok := secret.GetAnnotations()[keystorepasswordAnnotation]; ok && pwd != "" {
		return pwd
	}
	return defaultpassword
}
