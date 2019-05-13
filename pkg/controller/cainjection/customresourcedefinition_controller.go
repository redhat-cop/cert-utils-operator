package cainjection

import (
	"context"
	"io/ioutil"
	"reflect"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/redhat-cop/cert-utils-operator/pkg/controller/util"
	corev1 "k8s.io/api/core/v1"
	crd "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
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

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */
// newReconciler returns a new reconcile.Reconciler
func newCRDReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileCRD{client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func addCRD(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("crd-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	isAnnotatedCRD := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldSecret, _ := e.MetaOld.GetAnnotations()[certAnnotationSecret]
			newSecret, _ := e.MetaNew.GetAnnotations()[certAnnotationSecret]
			oldServiceCA, _ := e.MetaOld.GetAnnotations()[certAnnotationServiceCA]
			newServiceCA, _ := e.MetaNew.GetAnnotations()[certAnnotationServiceCA]
			return oldSecret != newSecret || oldServiceCA != newServiceCA
		},
		CreateFunc: func(e event.CreateEvent) bool {
			_, ok1 := e.Meta.GetAnnotations()[certAnnotationSecret]
			_, ok2 := e.Meta.GetAnnotations()[certAnnotationServiceCA]
			return ok1 || ok2
		},
	}

	// Watch for changes to primary resource CRD
	err = c.Watch(&source.Kind{Type: &crd.CustomResourceDefinition{}}, &handler.EnqueueRequestForObject{}, isAnnotatedCRD)
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
	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &enqueueRequestForReferecingCRDs{
		Client:        mgr.GetClient(),
		InjectionType: secretInjection,
	}, isContentChanged)
	if err != nil {
		return err
	}

	//let's watch for the file change
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	err = watcher.Add(systemCAFile)
	if err != nil {
		return err
	}

	events := make(chan event.GenericEvent)

	go func() {
		for {
			select {
			// watch for events
			case fileEvent := <-watcher.Events:
				log.Info("received event on file watcher channel", "event", fileEvent)
				if fileEvent.Op&fsnotify.Write == fsnotify.Write {
					// we received a change event on the file
					events <- event.GenericEvent{}
				}
				//we ignore all other events

				// watch for errors
			case err := <-watcher.Errors:
				log.Error(err, "error from file watch channel, ignoring ...")
			}
		}
	}()

	err = c.Watch(
		&source.Channel{Source: events},
		&enqueueRequestForReferecingCRDs{
			Client:        mgr.GetClient(),
			InjectionType: systemCAInjection,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileCRD{}

// ReconcileCRD reconciles a mutatingWebhookConfiguration object
type ReconcileCRD struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// Reconcile reads that state of the cluster for a mutatingWebhookConfiguration object and makes changes based on the state read
// and what is in the mutatingWebhookConfiguration.Spec
// TODO(user): Modify this Reconcile function to implement your Controller logic.  This example creates
// a Pod as an example
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileCRD) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling CRD")

	// Fetch the mutatingWebhookConfiguration instance
	instance := &crd.CustomResourceDefinition{}
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

	if ann, _ := instance.GetAnnotations()[certAnnotationServiceCA]; ann == "true" {
		//we need to inject the system ca
		caBundle, err = ioutil.ReadFile(systemCAFile)
		if err != nil {
			log.Error(err, "unable to read file", "file", systemCAFile)
			return reconcile.Result{}, err
		}
	}
	if secretNamespacedName, ok := instance.GetAnnotations()[certAnnotationSecret]; ok {
		//we need to inject the secret ca
		caBundle, err = r.getSecretCA(secretNamespacedName[strings.Index(secretNamespacedName, "/")+1:], secretNamespacedName[:strings.Index(secretNamespacedName, "/")])
		if err != nil {
			log.Error(err, "unable to retrive ca from secret", "secret", secretNamespacedName)
			return reconcile.Result{}, err
		}
	}

	//we update only if the fields are initialized
	if instance.Spec.Conversion != nil {
		if instance.Spec.Conversion.WebhookClientConfig != nil {
			instance.Spec.Conversion.WebhookClientConfig.CABundle = caBundle
			err = r.client.Update(context.TODO(), instance)
		}
	}

	return reconcile.Result{}, err
}

func matchSecretWithCRD(c client.Client, secret types.NamespacedName) ([]crd.CustomResourceDefinition, error) {
	CRDList := &crd.CustomResourceDefinitionList{}
	err := c.List(context.TODO(), &client.ListOptions{}, CRDList)
	if err != nil {
		log.Error(err, "unable to list mutatingWebhookConfiguration for this namespace: ", "namespace", secret.Namespace)
		return []crd.CustomResourceDefinition{}, err
	}
	result := []crd.CustomResourceDefinition{}
	for _, CRD := range CRDList.Items {
		if secretNamespacedName := CRD.GetAnnotations()[certAnnotationSecret]; secretNamespacedName[strings.Index(secretNamespacedName, "/")+1:] == secret.Name && secretNamespacedName[:strings.Index(secretNamespacedName, "/")] == secret.Namespace {
			result = append(result, CRD)
		}
	}
	return result, nil
}

func matchSystemCAWithCRD(c client.Client) ([]crd.CustomResourceDefinition, error) {
	CRDList := &crd.CustomResourceDefinitionList{}
	err := c.List(context.TODO(), &client.ListOptions{}, CRDList)
	if err != nil {
		log.Error(err, "unable to list mutatingWebhookConfiguration for all namespaces")
		return []crd.CustomResourceDefinition{}, err
	}
	result := []crd.CustomResourceDefinition{}
	for _, CRD := range CRDList.Items {
		if ann, ok := CRD.GetAnnotations()[certAnnotationServiceCA]; ok && ann == "true" {
			result = append(result, CRD)
		}
	}
	return result, nil
}

type enqueueRequestForReferecingCRDs struct {
	client.Client
	InjectionType string
}

// trigger a router reconcile event for those routes that reference this secret
func (e *enqueueRequestForReferecingCRDs) Create(evt event.CreateEvent, q workqueue.RateLimitingInterface) {
	CRDs := []crd.CustomResourceDefinition{}
	if e.InjectionType == secretInjection {
		CRDs, _ = matchSecretWithCRD(e.Client, types.NamespacedName{
			Name:      evt.Meta.GetName(),
			Namespace: evt.Meta.GetNamespace(),
		})
	}
	if e.InjectionType == systemCAInjection {
		CRDs, _ = matchSystemCAWithCRD(e.Client)
	}
	for _, CRD := range CRDs {
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Name: CRD.GetName(),
		}})
	}
}

// Update implements EventHandler
// trigger a router reconcile event for those routes that reference this secret
func (e *enqueueRequestForReferecingCRDs) Update(evt event.UpdateEvent, q workqueue.RateLimitingInterface) {
	CRDs := []crd.CustomResourceDefinition{}
	if e.InjectionType == secretInjection {
		CRDs, _ = matchSecretWithCRD(e.Client, types.NamespacedName{
			Name:      evt.MetaNew.GetName(),
			Namespace: evt.MetaNew.GetNamespace(),
		})
	}
	if e.InjectionType == systemCAInjection {
		CRDs, _ = matchSystemCAWithCRD(e.Client)
	}
	for _, CRD := range CRDs {
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Name: CRD.GetName(),
		}})
	}
}

// Delete implements EventHandler
func (e *enqueueRequestForReferecingCRDs) Delete(evt event.DeleteEvent, q workqueue.RateLimitingInterface) {
	return
}

// Generic implements EventHandler
func (e *enqueueRequestForReferecingCRDs) Generic(evt event.GenericEvent, q workqueue.RateLimitingInterface) {
	CRDs := []crd.CustomResourceDefinition{}
	if e.InjectionType == secretInjection {
		CRDs, _ = matchSecretWithCRD(e.Client, types.NamespacedName{
			Name:      evt.Meta.GetName(),
			Namespace: evt.Meta.GetNamespace(),
		})
	}
	if e.InjectionType == systemCAInjection {
		CRDs, _ = matchSystemCAWithCRD(e.Client)
	}
	for _, CRD := range CRDs {
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Name: CRD.GetName(),
		}})
	}
}

func (r *ReconcileCRD) getSecretCA(secretName string, secretNamespace string) ([]byte, error) {
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
