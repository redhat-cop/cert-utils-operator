package certificateinfo

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"reflect"

	"github.com/go-logr/logr"
	"github.com/grantae/certinfo"
	"github.com/redhat-cop/cert-utils-operator/controllers/util"
	outils "github.com/redhat-cop/operator-utils/pkg/util"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const certInfoAnnotation = util.AnnotationBase + "/generate-cert-info"
const certInfo = "tls.crt.info"
const caInfo = "ca.crt.info"

// CertificateInfoReconciler reconciles a Namespace object
type CertificateInfoReconciler struct {
	outils.ReconcilerBase
	Log            logr.Logger
	controllerName string
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateInfoReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.controllerName = "certificate_info_controller"

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
			oldValue, _ := e.ObjectOld.GetAnnotations()[certInfoAnnotation]
			newValue, _ := e.ObjectNew.GetAnnotations()[certInfoAnnotation]
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
			value, _ := e.Object.GetAnnotations()[certInfoAnnotation]
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
func (r *CertificateInfoReconciler) Reconcile(context context.Context, request reconcile.Request) (reconcile.Result, error) {
	log := r.Log.WithValues("certinfo", request.NamespacedName)

	// Fetch the SecretInfo instance
	instance := &corev1.Secret{}
	err := r.GetClient().Get(context, request.NamespacedName, instance)
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
			instance.Data[certInfo] = []byte(r.generateCertInfo(instance.Data[util.Cert]))
		}
		if value, ok := instance.Data[util.CA]; ok && len(value) != 0 {
			instance.Data[caInfo] = []byte(r.generateCertInfo(instance.Data[util.CA]))
		}
	} else {
		delete(instance.Data, certInfo)
		delete(instance.Data, caInfo)
	}

	err = r.GetClient().Update(context, instance)
	if err != nil {
		log.Error(err, "unable to update secrer", "secret", instance.GetName())
		return r.ManageError(context, instance, err)
	}

	return r.ManageSuccess(context, instance)
}

func (r *CertificateInfoReconciler) generateCertInfo(pemCert []byte) string {
	result := ""
	for p, rest := pem.Decode(pemCert); p != nil; p, rest = pem.Decode(rest) {
		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			r.Log.Error(err, "unable to decode this entry, skipping", "entry", string(p.Bytes))
			continue
		}

		// Print the certificate
		res, err := certinfo.CertificateText(cert)
		if err != nil {
			r.Log.Error(err, "unable to describe this entry, skipping", "entry", cert)
			continue
		}
		result += res + "\n"
	}
	return result
}
