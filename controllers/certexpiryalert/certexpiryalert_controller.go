package certexpiryalert

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"reflect"
	"time"

	"github.com/go-logr/logr"
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

const certExpiryAlertAnnotation = util.AnnotationBase + "/generate-cert-expiry-alert"
const certExpiryCheckFrequencyAnnotation = util.AnnotationBase + "/cert-expiry-check-frequency"
const certSoonToExpireFrequencyAnnotation = util.AnnotationBase + "/cert-soon-to-expire-check-frequency"
const certSoonToExpireThresholdAnnotation = util.AnnotationBase + "/cert-soon-to-expire-threshold"

// 90 days
const defaultSoonToExpireThreshold = time.Duration(1000 * 1000 * 1000 * 60 * 60 * 24 * 90)

// 1 hour
const defaultSoonToExpireFrequency = time.Duration(1000 * 1000 * 1000 * 60 * 60)

// 7 days
const defaultExpireFrequency = time.Duration(1000 * 1000 * 1000 * 60 * 60 * 24 * 7)

// CertExpiryAlertReconciler reconciles a Namespace object
type CertExpiryAlertReconciler struct {
	outils.ReconcilerBase
	Log            logr.Logger
	controllerName string
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertExpiryAlertReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.controllerName = "certexpiryalert_controller"

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
			oldValue, _ := e.ObjectOld.GetAnnotations()[certExpiryAlertAnnotation]
			newValue, _ := e.ObjectNew.GetAnnotations()[certExpiryAlertAnnotation]
			old := oldValue == "true"
			new := newValue == "true"
			// if the content has changed we trigger is the annotation is there
			if !reflect.DeepEqual(newSecret.Data[util.Cert], oldSecret.Data[util.Cert]) {
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
			value, _ := e.Object.GetAnnotations()[certExpiryAlertAnnotation]
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
func (r *CertExpiryAlertReconciler) Reconcile(context context.Context, request reconcile.Request) (reconcile.Result, error) {
	_ = r.Log.WithValues("cert-expiry-alert", request.NamespacedName)

	// Fetch the CertExpiryAlert instance
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
	if value, _ := instance.GetAnnotations()[certExpiryAlertAnnotation]; value != "true" {
		return reconcile.Result{}, nil
	}
	if value, ok := instance.Data[util.Cert]; ok && len(value) == 0 {
		return reconcile.Result{}, nil
	}
	expiry := r.getExpiry(instance)
	expiryThreshold := r.getExpiryThreshold(instance)
	if time.Now().Add(expiryThreshold).After(expiry) {
		//emit alert

		r.GetRecorder().Event(instance, "Warning", "Certs Soon to Expire", fmt.Sprintf("Certificate expiring in %d days", int(expiry.Sub(time.Now()).Hours()/24)))
		//reschdule for soon to expire frequency

		return reconcile.Result{
			Requeue:      true,
			RequeueAfter: r.getSoonToExpireCheckFrequency(instance),
		}, nil
	}

	return reconcile.Result{
		Requeue:      true,
		RequeueAfter: r.getExpiryCheckFrequency(instance),
	}, nil

}

func (r *CertExpiryAlertReconciler) getExpiry(secret *corev1.Secret) time.Time {
	result := time.Time{}
	for p, rest := pem.Decode(secret.Data[util.Cert]); p != nil; p, rest = pem.Decode(rest) {
		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			r.Log.Error(err, "unable to decode this entry, skipping", "entry", string(p.Bytes))
			continue
		}
		if result.Before(time.Now()) {
			result = cert.NotAfter
		} else {
			result = min(result, cert.NotAfter)
		}
	}
	return result
}

func min(a time.Time, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (r *CertExpiryAlertReconciler) getExpiryThreshold(secret *corev1.Secret) time.Duration {
	sthreshold, ok := secret.GetAnnotations()[certSoonToExpireThresholdAnnotation]
	if !ok {
		return defaultSoonToExpireThreshold
	}
	tthreshold, err := time.ParseDuration(string(sthreshold))
	if err != nil {
		r.Log.Error(err, "unable to parse duration", certSoonToExpireThresholdAnnotation, sthreshold)
		return defaultSoonToExpireThreshold
	}
	return tthreshold
}

func (r *CertExpiryAlertReconciler) getSoonToExpireCheckFrequency(secret *corev1.Secret) time.Duration {
	sthreshold, ok := secret.GetAnnotations()[certSoonToExpireFrequencyAnnotation]
	if !ok {
		return defaultSoonToExpireFrequency
	}
	tthreshold, err := time.ParseDuration(string(sthreshold))
	if err != nil {
		r.Log.Error(err, "unable to parse duration", certSoonToExpireFrequencyAnnotation, sthreshold)
		return defaultSoonToExpireFrequency
	}
	return tthreshold
}

func (r *CertExpiryAlertReconciler) getExpiryCheckFrequency(secret *corev1.Secret) time.Duration {
	sthreshold, ok := secret.GetAnnotations()[certExpiryCheckFrequencyAnnotation]
	if !ok {
		return defaultExpireFrequency
	}
	tthreshold, err := time.ParseDuration(string(sthreshold))
	if err != nil {
		r.Log.Error(err, "unable to parse duration", certExpiryCheckFrequencyAnnotation, sthreshold)
		return defaultExpireFrequency
	}
	return tthreshold
}
