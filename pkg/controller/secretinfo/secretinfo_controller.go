package secretinfo

import (
	"context"
	"crypto/x509"
	"encoding/pem"

	"github.com/grantae/certinfo"
	"github.com/raffaelespazzoli/cert-utils-operator/pkg/controller/util"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
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

var log = logf.Log.WithName("controller_secretinfo")

const certInfoAnnotation = "raffa.systems/generate-cert-info"

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */

// Add creates a new SecretInfo Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileSecretInfo{client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("secretinfo-controller", mgr, controller.Options{Reconciler: r})
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
			oldValue, _ := e.MetaOld.GetAnnotations()[certInfoAnnotation]
			newValue, _ := e.MetaNew.GetAnnotations()[certInfoAnnotation]
			old := oldValue == "true"
			new := newValue == "true"
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
			value, _ := e.Meta.GetAnnotations()[certInfoAnnotation]
			return value == "true"
		},
	}

	// Watch for changes to primary resource SecretInfo
	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForObject{}, isAnnotatedSecret)
	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileSecretInfo{}

// ReconcileSecretInfo reconciles a SecretInfo object
type ReconcileSecretInfo struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// Reconcile reads that state of the cluster for a SecretInfo object and makes changes based on the state read
// and what is in the SecretInfo.Spec
// TODO(user): Modify this Reconcile function to implement your Controller logic.  This example creates
// a Pod as an example
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileSecretInfo) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling SecretInfo")

	// Fetch the SecretInfo instance
	instance := &corev1.Secret{}
	err := r.client.Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}
	value, _ := instance.GetAnnotations()[certInfoAnnotation]
	if value == "true" {
		instance.Data["tls.crt.info"] = []byte(generateCertInfo(instance.Data["tls.crt"]))
		instance.Data["ca.crt.info"] = []byte(generateCertInfo(instance.Data["ca.crt"]))
	} else {
		delete(instance.Data, "tls.crt.info")
		delete(instance.Data, "ca.crt.info")
	}

	err = r.client.Update(context.TODO(), instance)
	if err != nil {
		log.Error(err, "unable to update secrer", "secret", instance.GetName())
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

func generateCertInfo(pemCert []byte) string {
	result := ""
	for p, rest := pem.Decode(pemCert); p != nil; p, rest = pem.Decode(rest) {
		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			log.Error(err, "unable to decode this entry, skipping", "entry", string(p.Bytes))
			continue
		}

		// Print the certificate
		res, err := certinfo.CertificateText(cert)
		if err != nil {
			log.Error(err, "unable to describe this entry, skipping", "entry", cert)
			continue
		}
		result += res + "\n"
	}
	return result
}
