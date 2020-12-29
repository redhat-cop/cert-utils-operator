package cainjection

import (
	"bytes"
	"context"
	"strings"

	"github.com/go-logr/logr"
	"github.com/redhat-cop/cert-utils-operator/controllers/util"
	outils "github.com/redhat-cop/operator-utils/pkg/util"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// ConfigmapReconciler reconciles a Namespace object
type ConfigmapReconciler struct {
	outils.ReconcilerBase
	Log            logr.Logger
	controllerName string
}

// SetupWithManager sets up the controller with the Manager.
func (r *ConfigmapReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.controllerName = "configmap_ca_injection_controller"

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ConfigMap{
			TypeMeta: v1.TypeMeta{
				Kind: "ConfigMap",
			},
		}, builder.WithPredicates(util.IsAnnotatedForSecretCAInjection)).
		Watches(&source.Kind{Type: &corev1.Secret{
			TypeMeta: v1.TypeMeta{
				Kind: "Secret",
			},
		}}, util.NewEnqueueRequestForReferecingObject(r.GetRestConfig(), schema.FromAPIVersionAndKind("v1", "ConfigMap")), builder.WithPredicates(util.IsCAContentChanged)).
		Complete(r)
}

// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=get;list;watch;create;patch
func (r *ConfigmapReconciler) Reconcile(context context.Context, request reconcile.Request) (reconcile.Result, error) {
	log := r.Log.WithValues("configmap", request.NamespacedName)

	// Fetch the mutatingWebhookConfiguration instance
	instance := &corev1.ConfigMap{}
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
	if len(caBundle) == 0 {
		delete(instance.Data, util.CA)
	} else {
		if instance.Data == nil {
			instance.Data = map[string]string{}
		}
		buffer := bytes.NewBuffer(caBundle)
		instance.Data[util.CA] = buffer.String()
	}
	err = r.GetClient().Update(context, instance)

	if err != nil {
		return r.ManageError(context, instance, err)
	}

	return r.ManageSuccess(context, instance)
}
