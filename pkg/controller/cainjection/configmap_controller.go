package cainjection

import (
	"bytes"
	"context"
	"strings"
	"time"

	"github.com/redhat-cop/cert-utils-operator/pkg/controller/util"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
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

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */
// newReconciler returns a new reconcile.Reconciler
func newConfigmapReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileConfigmap{client: mgr.GetClient(), scheme: mgr.GetScheme(), recorder: mgr.GetRecorder("configmap-ca-injection-controller")}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func addConfigmapReconciler(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("configmap-ca-injection-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	isAnnotatedSecret := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldSecret, _ := e.MetaOld.GetAnnotations()[certAnnotationSecret]
			newSecret, _ := e.MetaNew.GetAnnotations()[certAnnotationSecret]
			return oldSecret != newSecret
		},
		CreateFunc: func(e event.CreateEvent) bool {
			_, ok1 := e.Meta.GetAnnotations()[certAnnotationSecret]
			return ok1
		},
	}

	// Watch for changes to primary resource CRD
	err = c.Watch(&source.Kind{Type: &corev1.ConfigMap{}}, &handler.EnqueueRequestForObject{}, isAnnotatedSecret)
	if err != nil {
		return err
	}

	isContentChanged := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			_, ok := e.ObjectNew.(*corev1.ConfigMap)
			if !ok {
				return false
			}
			return true
		},
		CreateFunc: func(e event.CreateEvent) bool {
			_, ok := e.Object.(*corev1.ConfigMap)
			if !ok {
				return false
			}
			_, ok1 := e.Meta.GetAnnotations()[certAnnotationSecret]
			return ok1
		},
	}

	// TODO(user): Modify this to be the types you create that are owned by the primary resource
	// Watch for changes to secondary resource Pods and requeue the owner ValidatingWebhookConfiguration
	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &enqueueRequestForReferecingConfigmaps{
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
	client   client.Client
	scheme   *runtime.Scheme
	recorder record.EventRecorder
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

	caBundle := []byte{}

	if secretNamespacedName, ok := instance.GetAnnotations()[certAnnotationSecret]; ok {
		//we need to inject the secret ca
		caBundle, err = r.getSecretCA(secretNamespacedName[strings.Index(secretNamespacedName, "/")+1:], secretNamespacedName[:strings.Index(secretNamespacedName, "/")])
		if err != nil {
			log.Error(err, "unable to retrive ca from secret", "secret", secretNamespacedName)
			return r.manageError(err, instance)
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
	err = r.client.Update(context.TODO(), instance)

	if err != nil {
		return r.manageError(err, instance)
	}

	return reconcile.Result{}, err
}

func matchSecretWithConfigmaps(c client.Client, secret types.NamespacedName) ([]corev1.ConfigMap, error) {
	configmapList := &corev1.ConfigMapList{}
	err := c.List(context.TODO(), &client.ListOptions{}, configmapList)
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
	err := r.client.Get(context.TODO(), types.NamespacedName{
		Namespace: secretNamespace,
		Name:      secretName,
	}, secret)
	if err != nil {
		log.Error(err, "unable to find referenced secret", "secret", secretName)
		return []byte{}, err
	}
	return secret.Data[util.CA], nil
}

func (r *ReconcileConfigmap) manageError(issue error, instance runtime.Object) (reconcile.Result, error) {
	r.recorder.Event(instance, "Warning", "ProcessingError", issue.Error())
	return reconcile.Result{
		RequeueAfter: time.Minute * 2,
		Requeue:      true,
	}, nil
}
