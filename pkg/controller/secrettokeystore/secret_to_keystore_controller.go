package secrettokeystore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strconv"
	"time"

	keystore "github.com/pavel-v-chernykh/keystore-go"
	"github.com/raffaelespazzoli/cert-utils-operator/pkg/controller/util"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = logf.Log.WithName("controller_secret_to_keystore")

const javaKeyStoresAnnotation = "raffa.systems/generate-java-keystores"
const password = "changeme"

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */

// Add creates a new Secret Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileSecret{client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("secret-to-keystore-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	isAnnotatedSecret := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			newSecret, ok := e.ObjectNew.(*corev1.Secret)
			if !ok {
				return false
			}
			if newSecret.Type != util.TLSSecret {
				return false
			}
			oldValue, _ := e.MetaOld.GetAnnotations()[javaKeyStoresAnnotation]
			newValue, nok := e.MetaNew.GetAnnotations()[javaKeyStoresAnnotation]
			if !nok {
				return false
			}
			if oldValue == newValue {
				return false
			}
			return newValue == "true"
		},
		CreateFunc: func(e event.CreateEvent) bool {
			secret, ok := e.Object.(*corev1.Secret)
			if !ok {
				return false
			}
			if secret.Type != util.TLSSecret {
				return false
			}
			value, _ := e.Meta.GetAnnotations()[javaKeyStoresAnnotation]
			return value == "true"
		},
	}

	// Watch for changes to primary resource Secret
	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForObject{}, isAnnotatedSecret)
	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileSecret{}

// ReconcileSecret reconciles a Secret object
type ReconcileSecret struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// Reconcile reads that state of the cluster for a Secret object and makes changes based on the state read
// and what is in the Secret.Spec
// TODO(user): Modify this Reconcile function to implement your Controller logic.  This example creates
// a Pod as an example
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileSecret) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling Secret")

	// Fetch the Secret instance
	instance := &corev1.Secret{}
	err := r.client.Get(context.TODO(), request.NamespacedName, instance)
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

	keyStore, err := getKeyStoreFromSecret(instance)
	trustStore, err := getTrustStoreFromSecret(instance)

	buffer := bytes.Buffer{}
	err = keystore.Encode(&buffer, *keyStore, []byte(password))
	if err != nil {
		log.Error(err, "unable to encode keystore", "keystore", keyStore)
		return reconcile.Result{}, err
	}
	instance.Data["keystore.jks"] = []byte(base64.StdEncoding.EncodeToString(buffer.Bytes()))

	buffer = bytes.Buffer{}
	err = keystore.Encode(&buffer, *trustStore, []byte(password))
	if err != nil {
		log.Error(err, "unable to encode truststore", "keystore", keyStore)
		return reconcile.Result{}, err
	}
	instance.Data["truststore.jks"] = []byte(base64.StdEncoding.EncodeToString(buffer.Bytes()))

	err = r.client.Update(context.TODO(), instance)
	if err != nil {
		log.Error(err, "unable to update secrer", "secret", instance.GetName())
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

func getKeyStoreFromSecret(secret *corev1.Secret) (*keystore.KeyStore, error) {
	keyStore := keystore.KeyStore{}
	key, ok := secret.Data["tls.key"]
	if !ok {
		return &keystore.KeyStore{}, errors.New("tls.key not found")
	}
	crt, ok := secret.Data["tls.crt"]
	if !ok {
		return &keystore.KeyStore{}, errors.New("tls.crt not found")
	}
	//TODO decode crt and key
	certs := []keystore.Certificate{}
	for p, rest := pem.Decode(crt); p != nil; p, rest = pem.Decode(rest) {
		certs = append(certs, keystore.Certificate{
			Type:    p.Type,
			Content: p.Bytes,
		})
	}

	p, _ := pem.Decode(key)
	if p == nil {
		return &keystore.KeyStore{}, errors.New("no block found in key.tls, private key should have at least one pem block")
	}
	if p.Type != "PRIVATE KEY" {
		return &keystore.KeyStore{}, errors.New("private key block not of type PRIVATE KEY")
	}

	keyStore["alias"] = keystore.PrivateKeyEntry{
		Entry: keystore.Entry{
			CreationDate: time.Now(),
		},
		PrivKey:   p.Bytes,
		CertChain: certs,
	}
	return &keyStore, nil
}

func getTrustStoreFromSecret(secret *corev1.Secret) (*keystore.KeyStore, error) {
	keyStore := keystore.KeyStore{}
	ca, ok := secret.Data["ca.crt"]
	if !ok {
		return &keystore.KeyStore{}, errors.New("ca bundle key not found: ca.crt")
	}
	//TODO decode ca
	i := 0
	for p, rest := pem.Decode(ca); p != nil; p, rest = pem.Decode(rest) {
		keyStore["alias"+strconv.Itoa(i)] = keystore.TrustedCertificateEntry{
			Entry: keystore.Entry{
				CreationDate: time.Now(),
			},
			Certificate: keystore.Certificate{
				Type:    p.Type,
				Content: p.Bytes,
			},
		}
	}
	return &keyStore, nil
}
