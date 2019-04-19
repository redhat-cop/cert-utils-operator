package certexpiryalert

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/raffaelespazzoli/secret-utils-operator/pkg/controller/util"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
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

var log = logf.Log.WithName("controller_certexpiryalert")

const certExpiryAlertAnnotation = "raffa.systems/generate-cert-expiry-alert"
const certExpiryCheckFrequencyAnnotation = "raffa.systems/cert-expiry-check-frequency"
const certSoonToExpireFrequencyAnnotation = "raffa.systems/cert-soon-to-expire-check-frequency"
const certSoonToExpireThresholdAnnotation = "raffa.systems/cert-soon-to-expire-threshold"

// 90 days
const defaultSoonToExpireThreshold = time.Duration(1000 * 1000 * 1000 * 60 * 60 * 24 * 90)

// 1 hour
const defaultSoonToExpireFrequency = time.Duration(1000 * 1000 * 1000 * 60 * 60)

// 7 days
const defaultExpireFrequency = time.Duration(1000 * 1000 * 1000 * 60 * 60 * 24 * 7)

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */

// Add creates a new CertExpiryAlert Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileCertExpiryAlert{client: mgr.GetClient(), scheme: mgr.GetScheme(), recorder: mgr.GetRecorder("cert-utils")}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("certexpiryalert-controller", mgr, controller.Options{Reconciler: r})
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
			oldValue, _ := e.MetaOld.GetAnnotations()[certExpiryAlertAnnotation]
			newValue, nok := e.MetaNew.GetAnnotations()[certExpiryAlertAnnotation]
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
			value, _ := e.Meta.GetAnnotations()[certExpiryAlertAnnotation]
			return value == "true"
		},
	}

	// Watch for changes to primary resource CertExpiryAlert
	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForObject{}, isAnnotatedSecret)
	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileCertExpiryAlert{}

// ReconcileCertExpiryAlert reconciles a CertExpiryAlert object
type ReconcileCertExpiryAlert struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client   client.Client
	scheme   *runtime.Scheme
	recorder record.EventRecorder
}

// Reconcile reads that state of the cluster for a CertExpiryAlert object and makes changes based on the state read
// and what is in the CertExpiryAlert.Spec
// TODO(user): Modify this Reconcile function to implement your Controller logic.  This example creates
// a Pod as an example
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileCertExpiryAlert) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling CertExpiryAlert")

	// Fetch the CertExpiryAlert instance
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

	expiry := getExpiry(instance)
	expiryThreshold := getExpiryThreshold(instance)
	if time.Now().Add(expiryThreshold).After(expiry) {
		//emit alert

		r.recorder.Event(instance, "Warning", "Certs Soon to Expire", fmt.Sprintf("Certificate expiring in %d days", int(expiry.Sub(time.Now()).Hours()/24)))
		//reschdule for soon to expire frequency

		return reconcile.Result{
			Requeue:      true,
			RequeueAfter: getSoonToExpireCheckFrequency(instance),
		}, nil
	}

	return reconcile.Result{
		Requeue:      true,
		RequeueAfter: getExpiryCheckFrequency(instance),
	}, nil

}

func getExpiry(secret *corev1.Secret) time.Time {
	result := time.Time{}
	for p, rest := pem.Decode(secret.Data["tls.crt"]); p != nil; p, rest = pem.Decode(rest) {
		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			log.Error(err, "unable to decode this entry, skipping", "entry", string(p.Bytes))
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

func getExpiryThreshold(secret *corev1.Secret) time.Duration {
	sthreshold, ok := secret.GetAnnotations()[certSoonToExpireThresholdAnnotation]
	if !ok {
		return defaultSoonToExpireThreshold
	}
	tthreshold, err := time.ParseDuration(string(sthreshold))
	if err != nil {
		log.Error(err, "unable to parse duration", certSoonToExpireThresholdAnnotation, sthreshold)
		return defaultSoonToExpireThreshold
	}
	return tthreshold
}

func getSoonToExpireCheckFrequency(secret *corev1.Secret) time.Duration {
	sthreshold, ok := secret.GetAnnotations()[certSoonToExpireFrequencyAnnotation]
	if !ok {
		return defaultSoonToExpireFrequency
	}
	tthreshold, err := time.ParseDuration(string(sthreshold))
	if err != nil {
		log.Error(err, "unable to parse duration", certSoonToExpireFrequencyAnnotation, sthreshold)
		return defaultSoonToExpireFrequency
	}
	return tthreshold
}

func getExpiryCheckFrequency(secret *corev1.Secret) time.Duration {
	sthreshold, ok := secret.GetAnnotations()[certExpiryCheckFrequencyAnnotation]
	if !ok {
		return defaultExpireFrequency
	}
	tthreshold, err := time.ParseDuration(string(sthreshold))
	if err != nil {
		log.Error(err, "unable to parse duration", certExpiryCheckFrequencyAnnotation, sthreshold)
		return defaultExpireFrequency
	}
	return tthreshold
}
