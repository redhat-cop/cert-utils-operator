package cainjection

import (
	"context"
	"strings"

	"github.com/go-logr/logr"
	"github.com/redhat-cop/cert-utils-operator/controllers/util"
	outils "github.com/redhat-cop/operator-utils/pkg/util"
	corev1 "k8s.io/api/core/v1"
	crd "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// CRDReconciler reconciles a Namespace object
type CRDReconciler struct {
	outils.ReconcilerBase
	Log            logr.Logger
	controllerName string
}

// SetupWithManager sets up the controller with the Manager.
func (r *CRDReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.controllerName = "crd_ca_injection_controller"

	return ctrl.NewControllerManagedBy(mgr).
		For(&crd.CustomResourceDefinition{
			TypeMeta: v1.TypeMeta{
				Kind: "CustomResourceDefinition",
			},
		}, builder.WithPredicates(util.IsAnnotatedForSecretCAInjection)).
		Watches(&source.Kind{Type: &corev1.Secret{
			TypeMeta: v1.TypeMeta{
				Kind: "Secret",
			},
		}}, util.NewEnqueueRequestForReferecingObject(r.GetRestConfig(), schema.FromAPIVersionAndKind("apiextensions.k8s.io/v1", "CustomResourceDefinition")), builder.WithPredicates(util.IsCAContentChanged)).
		Complete(r)
}

// +kubebuilder:rbac:groups="apiextensions.k8s.io",resources=customresourcedefinitions,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=get;list;watch;create;patch

func (r *CRDReconciler) Reconcile(context context.Context, req ctrl.Request) (reconcile.Result, error) {
	log := r.Log.WithValues("crd", req.NamespacedName)

	// Fetch the mutatingWebhookConfiguration instance
	instance := &crd.CustomResourceDefinition{}
	err := r.GetClient().Get(context, req.NamespacedName, instance)
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

	//we update only if the fields are initialized
	if instance.Spec.Conversion != nil {
		if instance.Spec.Conversion.Webhook != nil {
			instance.Spec.Conversion.Webhook.ClientConfig.CABundle = caBundle
			err = r.GetClient().Update(context, instance)
		}
	}
	if err != nil {
		return r.ManageError(context, instance, err)
	}

	return r.ManageSuccess(context, instance)
}
