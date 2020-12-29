package cainjection

import (
	"context"
	"strings"

	"github.com/go-logr/logr"
	"github.com/redhat-cop/cert-utils-operator/controllers/util"
	outils "github.com/redhat-cop/operator-utils/pkg/util"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// APIServiceReconciler reconciles a Namespace object
type APIServiceReconciler struct {
	outils.ReconcilerBase
	Log            logr.Logger
	controllerName string
}

// SetupWithManager sets up the controller with the Manager.
func (r *APIServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.controllerName = "apiservice_ca_injection_controller"

	return ctrl.NewControllerManagedBy(mgr).
		For(&apiregistrationv1.APIService{
			TypeMeta: v1.TypeMeta{
				Kind: "APIService",
			},
		}, builder.WithPredicates(util.IsAnnotatedForSecretCAInjection)).
		Watches(&source.Kind{Type: &corev1.Secret{
			TypeMeta: v1.TypeMeta{
				Kind: "Secret",
			},
		}}, util.NewEnqueueRequestForReferecingObject(r.GetRestConfig(), schema.FromAPIVersionAndKind("apiregistration.k8s.io/v1", "APIService")), builder.WithPredicates(util.IsCAContentChanged)).
		Complete(r)
}

// +kubebuilder:rbac:groups="apiregistration.k8s.io/v1",resources=apiservices,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=get;list;watch;create;patch
func (r *APIServiceReconciler) Reconcile(context context.Context, request reconcile.Request) (reconcile.Result, error) {
	log := r.Log.WithValues("apiservice", request.NamespacedName)

	// Fetch the apiservice instance
	instance := &apiregistrationv1.APIService{}
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

	caBundle := []byte{}

	if secretNamespacedName, ok := instance.GetAnnotations()[util.CertAnnotationSecret]; ok {
		err = util.ValidateSecretName(secretNamespacedName)
		if err != nil {
			log.Error(err, "invalid ca secret name", "secret", secretNamespacedName)
			return r.ManageError(context, instance, err)
		}
		//we need to inject the secret ca
		caBundle, err = util.GetSecretCA(r.GetClient(), secretNamespacedName[strings.Index(secretNamespacedName, "/")+1:], secretNamespacedName[:strings.Index(secretNamespacedName, "/")])
		if err != nil {
			log.Error(err, "unable to retrive ca from secret", "secret", secretNamespacedName)
			return r.ManageError(context, instance, err)
		}
	}

	instance.Spec.CABundle = caBundle
	err = r.GetClient().Update(context, instance)
	if err != nil {
		return r.ManageError(context, instance, err)
	}

	return r.ManageSuccess(context, instance)
}
