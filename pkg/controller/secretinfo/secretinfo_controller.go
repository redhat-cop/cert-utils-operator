package secretinfo

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"reflect"

	"github.com/grantae/certinfo"
	"github.com/redhat-cop/cert-utils-operator/pkg/controller/util"
	outils "github.com/redhat-cop/operator-utils/pkg/util"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const controllerName = "secretinfo_controller"

var log = logf.Log.WithName(controllerName)

const certInfoAnnotation = util.AnnotationBase + "/generate-cert-info"
const certInfo = "tls.crt.info"
const caInfo = "ca.crt.info"

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
	return &ReconcileSecretInfo{
		ReconcilerBase: outils.NewReconcilerBase(mgr.GetClient(), mgr.GetScheme(), mgr.GetConfig(), mgr.GetEventRecorderFor(controllerName)),
	}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New(controllerName, mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

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
			oldValue, _ := e.MetaOld.GetAnnotations()[certInfoAnnotation]
			newValue, _ := e.MetaNew.GetAnnotations()[certInfoAnnotation]
			old := oldValue == "true"
			new := newValue == "true"
			// if the content has changed we trigger is the annotation is there
			if !reflect.DeepEqual(newSecret.Data[util.Cert], oldSecret.Data[util.Cert]) ||
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
			value, _ := e.Meta.GetAnnotations()[certInfoAnnotation]
			return value == "true"
		},
	}

	// Watch for changes to primary resource SecretInfo
	err = c.Watch(&source.Kind{Type: &corev1.Secret{
		TypeMeta: v1.TypeMeta{
			Kind: "Secret",
		},
	}}, &handler.EnqueueRequestForObject{}, isAnnotatedSecret)
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
	outils.ReconcilerBase
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
	err := r.GetClient().Get(context.TODO(), request.NamespacedName, instance)
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
		if value, ok := instance.Data[util.Cert]; ok && len(value) != 0 {
			instance.Data[certInfo] = []byte(generateCertInfo(instance.Data[util.Cert]))
		}
		if value, ok := instance.Data[util.CA]; ok && len(value) != 0 {
			instance.Data[caInfo] = []byte(generateCertInfo(instance.Data[util.CA]))
		}
	} else {
		delete(instance.Data, certInfo)
		delete(instance.Data, caInfo)
	}

	err = r.GetClient().Update(context.TODO(), instance)
	if err != nil {
		log.Error(err, "unable to update secrer", "secret", instance.GetName())
		return r.ManageError(instance, err)
	}

	return r.ManageSuccess(instance)
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
