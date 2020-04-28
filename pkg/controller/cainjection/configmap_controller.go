package cainjection

import (
	"bytes"
	"context"
	"reflect"
	"strings"

	"github.com/redhat-cop/cert-utils-operator/pkg/controller/util"
	outils "github.com/redhat-cop/operator-utils/pkg/util"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const controllerNamecm = "configmap-ca-injection-controller"

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */
// newReconciler returns a new reconcile.Reconciler
func newConfigmapReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileConfigmap{
		ReconcilerBase: outils.NewReconcilerBase(mgr.GetClient(), mgr.GetScheme(), mgr.GetConfig(), mgr.GetEventRecorderFor(controllerNamecm)),
	}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func addConfigmapReconciler(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New(controllerNamecm, mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	isAnnotatedConfigMap := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldSecret, _ := e.MetaOld.GetAnnotations()[certAnnotationSecret]
			newSecret, _ := e.MetaNew.GetAnnotations()[certAnnotationSecret]
			log.V(1).Info("update func", "config map", e.MetaNew.GetName(), "annotation old", oldSecret, "annotation new", newSecret)
			return oldSecret != newSecret
		},
		CreateFunc: func(e event.CreateEvent) bool {
			_, ok1 := e.Meta.GetAnnotations()[certAnnotationSecret]
			log.V(1).Info("create func", "config map", e.Meta.GetName(), "has annotation", ok1)
			return ok1
		},
	}

	// Watch for changes to primary resource CRD
	err = c.Watch(&source.Kind{Type: &corev1.ConfigMap{
		TypeMeta: v1.TypeMeta{
			Kind: "ConfigMap",
		},
	}}, &handler.EnqueueRequestForObject{}, isAnnotatedConfigMap)
	if err != nil {
		return err
	}

	isContentChanged := predicate.Funcs{
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
			return !reflect.DeepEqual(newSecret.Data[util.CA], oldSecret.Data[util.CA])
		},
		CreateFunc: func(e event.CreateEvent) bool {
			secret, ok := e.Object.(*corev1.Secret)
			if !ok {
				return false
			}
			if secret.Type != util.TLSSecret {
				return false
			}
			return true
		},
	}

	// TODO(user): Modify this to be the types you create that are owned by the primary resource
	// Watch for changes to secondary resource Pods and requeue the owner ValidatingWebhookConfiguration
	err = c.Watch(&source.Kind{Type: &corev1.Secret{
		TypeMeta: v1.TypeMeta{
			Kind: "secret",
		},
	}}, &enqueueRequestForReferecingConfigmaps{
		Client: mgr.GetClient(),
	}, isContentChanged)
	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileSecret{}

// ReconcileCRD reconciles a mutatingWebhookConfiguration object
type ReconcileConfigmap struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	outils.ReconcilerBase
}

// Reconcile reads that state of the cluster for a mutatingWebhookConfiguration object and makes changes based on the state read
// and what is in the mutatingWebhookConfiguration.Spec
// TODO(user): Modify this Reconcile function to implement your Controller logic.  This example creates
// a Pod as an example
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileConfigmap) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling configmap")

	// Fetch the mutatingWebhookConfiguration instance
	instance := &corev1.ConfigMap{}
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

	caBundle := []byte{}

	if secretNamespacedName, ok := instance.GetAnnotations()[certAnnotationSecret]; ok {
		err = util.ValidateSecretName(secretNamespacedName)
		if err != nil {
			log.Error(err, "invalid ca secret name", "secret", secretNamespacedName)
			return r.ManageError(instance, err)
		}

		//we need to inject the secret ca
		caBundle, err = r.getSecretCA(secretNamespacedName[strings.Index(secretNamespacedName, "/")+1:], secretNamespacedName[:strings.Index(secretNamespacedName, "/")])
		if err != nil {
			log.Error(err, "unable to retrive ca from secret", "secret", secretNamespacedName)
			return r.ManageError(instance, err)
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
	err = r.GetClient().Update(context.TODO(), instance)

	if err != nil {
		return r.ManageError(instance, err)
	}

	return r.ManageSuccess(instance)
}

func matchSecretWithConfigmaps(c client.Client, secret types.NamespacedName) ([]corev1.ConfigMap, error) {
	configmapList := &corev1.ConfigMapList{}
	err := c.List(context.TODO(), configmapList, &client.ListOptions{})
	if err != nil {
		log.Error(err, "unable to list secret for this namespace: ", "namespace", secret.Namespace)
		return []corev1.ConfigMap{}, err
	}
	result := []corev1.ConfigMap{}
	for _, configmap := range configmapList.Items {
		if secretNamespacedName := configmap.GetAnnotations()[certAnnotationSecret]; secretNamespacedName[strings.Index(secretNamespacedName, "/")+1:] == secret.Name && secretNamespacedName[:strings.Index(secretNamespacedName, "/")] == secret.Namespace {
			result = append(result, configmap)
		}
	}
	return result, nil
}

type enqueueRequestForReferecingConfigmaps struct {
	client.Client
}

// trigger a router reconcile event for those routes that reference this secret
func (e *enqueueRequestForReferecingConfigmaps) Create(evt event.CreateEvent, q workqueue.RateLimitingInterface) {
	configmaps, _ := matchSecretWithConfigmaps(e.Client, types.NamespacedName{
		Name:      evt.Meta.GetName(),
		Namespace: evt.Meta.GetNamespace(),
	})
	for _, configmap := range configmaps {
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Name:      configmap.GetName(),
			Namespace: configmap.GetNamespace(),
		}})
	}
}

// Update implements EventHandler
// trigger a router reconcile event for those routes that reference this secret
func (e *enqueueRequestForReferecingConfigmaps) Update(evt event.UpdateEvent, q workqueue.RateLimitingInterface) {
	configmaps, _ := matchSecretWithConfigmaps(e.Client, types.NamespacedName{
		Name:      evt.MetaNew.GetName(),
		Namespace: evt.MetaNew.GetNamespace(),
	})
	for _, configmap := range configmaps {
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Name:      configmap.GetName(),
			Namespace: configmap.GetNamespace(),
		}})
	}
}

// Delete implements EventHandler
func (e *enqueueRequestForReferecingConfigmaps) Delete(evt event.DeleteEvent, q workqueue.RateLimitingInterface) {
	return
}

// Generic implements EventHandler
func (e *enqueueRequestForReferecingConfigmaps) Generic(evt event.GenericEvent, q workqueue.RateLimitingInterface) {
	configmaps, _ := matchSecretWithConfigmaps(e.Client, types.NamespacedName{
		Name:      evt.Meta.GetName(),
		Namespace: evt.Meta.GetNamespace(),
	})
	for _, configmap := range configmaps {
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Name:      configmap.GetName(),
			Namespace: configmap.GetNamespace(),
		}})
	}
}

func (r *ReconcileConfigmap) getSecretCA(secretName string, secretNamespace string) ([]byte, error) {
	secret := &corev1.Secret{}
	err := r.GetClient().Get(context.TODO(), types.NamespacedName{
		Namespace: secretNamespace,
		Name:      secretName,
	}, secret)
	if err != nil {
		log.Error(err, "unable to find referenced secret", "secret", secretName)
		return []byte{}, err
	}
	return secret.Data[util.CA], nil
}
