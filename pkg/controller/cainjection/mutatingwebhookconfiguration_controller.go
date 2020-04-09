package cainjection

import (
	"context"
	"io/ioutil"
	"reflect"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/redhat-cop/cert-utils-operator/pkg/controller/util"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
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
func newMutatingReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileMutatingWebhookConfiguration{client: mgr.GetClient(), scheme: mgr.GetScheme(), recorder: mgr.GetEventRecorderFor("mutatingwebhookconfiguration-controller")}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func addMutating(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("mutatingwebhookconfiguration-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	isAnnotatedMutatingWebhookConfiguration := predicate.Funcs{
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

	// Watch for changes to primary resource MutatingWebhookConfiguration
	err = c.Watch(&source.Kind{Type: &admissionregistrationv1beta1.MutatingWebhookConfiguration{}}, &handler.EnqueueRequestForObject{}, isAnnotatedMutatingWebhookConfiguration)
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
	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &enqueueRequestForReferecingMutatingWebHooks{
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
				//log.Info("received event on file watcher channel", "event", fileEvent)
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
		&enqueueRequestForReferecingMutatingWebHooks{
			Client:        mgr.GetClient(),
			InjectionType: systemCAInjection,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileMutatingWebhookConfiguration{}

// ReconcileMutatingWebhookConfiguration reconciles a mutatingWebhookConfiguration object
type ReconcileMutatingWebhookConfiguration struct {
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
func (r *ReconcileMutatingWebhookConfiguration) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling MutatingWebhookConfiguration")

	// Fetch the mutatingWebhookConfiguration instance
	instance := &admissionregistrationv1beta1.MutatingWebhookConfiguration{}
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
			return r.manageError(err, instance)
		}
	}
	if secretNamespacedName, ok := instance.GetAnnotations()[certAnnotationSecret]; ok {
		//we need to inject the secret ca
		caBundle, err = r.getSecretCA(secretNamespacedName[strings.Index(secretNamespacedName, "/")+1:], secretNamespacedName[:strings.Index(secretNamespacedName, "/")])
		if err != nil {
			log.Error(err, "unable to retrive ca from secret", "secret", secretNamespacedName)
			return r.manageError(err, instance)
		}
	}
	for i := range instance.Webhooks {
		instance.Webhooks[i].ClientConfig.CABundle = caBundle
	}
	err = r.client.Update(context.TODO(), instance)
	if err != nil {
		return r.manageError(err, instance)
	}
	return reconcile.Result{}, nil
}

func matchSecretWithMutatingWebhooks(c client.Client, secret types.NamespacedName) ([]admissionregistrationv1beta1.MutatingWebhookConfiguration, error) {
	mutatingWebHookList := &admissionregistrationv1beta1.MutatingWebhookConfigurationList{}
	err := c.List(context.TODO(), mutatingWebHookList, &client.ListOptions{})
	if err != nil {
		log.Error(err, "unable to list mutatingWebhookConfiguration for this namespace: ")
		return []admissionregistrationv1beta1.MutatingWebhookConfiguration{}, err
	}
	result := []admissionregistrationv1beta1.MutatingWebhookConfiguration{}
	for _, mutatingWebHook := range mutatingWebHookList.Items {
		if secretNamespacedName := mutatingWebHook.GetAnnotations()[certAnnotationSecret]; secretNamespacedName[strings.Index(secretNamespacedName, "/")+1:] == secret.Name && secretNamespacedName[:strings.Index(secretNamespacedName, "/")] == secret.Namespace {
			result = append(result, mutatingWebHook)
		}
	}
	return result, nil
}

func matchSystemCAWithMutatingWebhooks(c client.Client) ([]admissionregistrationv1beta1.MutatingWebhookConfiguration, error) {
	mutatingWebHookList := &admissionregistrationv1beta1.MutatingWebhookConfigurationList{}
	err := c.List(context.TODO(), mutatingWebHookList, &client.ListOptions{})
	if err != nil {
		log.Error(err, "unable to list mutatingWebhookConfiguration for all namespaces")
		return []admissionregistrationv1beta1.MutatingWebhookConfiguration{}, err
	}
	result := []admissionregistrationv1beta1.MutatingWebhookConfiguration{}
	for _, mutatingWebHook := range mutatingWebHookList.Items {
		if ann, ok := mutatingWebHook.GetAnnotations()[certAnnotationServiceCA]; ok && ann == "true" {
			result = append(result, mutatingWebHook)
		}
	}
	return result, nil
}

type enqueueRequestForReferecingMutatingWebHooks struct {
	client.Client
	InjectionType string
}

// trigger a router reconcile event for those routes that reference this secret
func (e *enqueueRequestForReferecingMutatingWebHooks) Create(evt event.CreateEvent, q workqueue.RateLimitingInterface) {
	mutatingWebHooks := []admissionregistrationv1beta1.MutatingWebhookConfiguration{}
	if e.InjectionType == secretInjection {
		mutatingWebHooks, _ = matchSecretWithMutatingWebhooks(e.Client, types.NamespacedName{
			Name:      evt.Meta.GetName(),
			Namespace: evt.Meta.GetNamespace(),
		})
	}
	if e.InjectionType == systemCAInjection {
		mutatingWebHooks, _ = matchSystemCAWithMutatingWebhooks(e.Client)
	}
	for _, mutatingWebHook := range mutatingWebHooks {
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Name: mutatingWebHook.GetName(),
		}})
	}
}

// Update implements EventHandler
// trigger a router reconcile event for those routes that reference this secret
func (e *enqueueRequestForReferecingMutatingWebHooks) Update(evt event.UpdateEvent, q workqueue.RateLimitingInterface) {
	mutatingWebHooks := []admissionregistrationv1beta1.MutatingWebhookConfiguration{}
	if e.InjectionType == secretInjection {
		mutatingWebHooks, _ = matchSecretWithMutatingWebhooks(e.Client, types.NamespacedName{
			Name:      evt.MetaNew.GetName(),
			Namespace: evt.MetaNew.GetNamespace(),
		})
	}
	if e.InjectionType == systemCAInjection {
		mutatingWebHooks, _ = matchSystemCAWithMutatingWebhooks(e.Client)
	}
	for _, mutatingWebHook := range mutatingWebHooks {
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Name: mutatingWebHook.GetName(),
		}})
	}
}

// Delete implements EventHandler
func (e *enqueueRequestForReferecingMutatingWebHooks) Delete(evt event.DeleteEvent, q workqueue.RateLimitingInterface) {
	return
}

// Generic implements EventHandler
func (e *enqueueRequestForReferecingMutatingWebHooks) Generic(evt event.GenericEvent, q workqueue.RateLimitingInterface) {
	mutatingWebHooks := []admissionregistrationv1beta1.MutatingWebhookConfiguration{}
	if e.InjectionType == secretInjection {
		mutatingWebHooks, _ = matchSecretWithMutatingWebhooks(e.Client, types.NamespacedName{
			Name:      evt.Meta.GetName(),
			Namespace: evt.Meta.GetNamespace(),
		})
	}
	if e.InjectionType == systemCAInjection {
		mutatingWebHooks, _ = matchSystemCAWithMutatingWebhooks(e.Client)
	}
	for _, mutatingWebHook := range mutatingWebHooks {
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Name: mutatingWebHook.GetName(),
		}})
	}
}

func (r *ReconcileMutatingWebhookConfiguration) getSecretCA(secretName string, secretNamespace string) ([]byte, error) {
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

func (r *ReconcileMutatingWebhookConfiguration) manageError(issue error, instance runtime.Object) (reconcile.Result, error) {
	r.recorder.Event(instance, "Warning", "ProcessingError", issue.Error())
	return reconcile.Result{
		RequeueAfter: time.Minute * 2,
		Requeue:      true,
	}, nil
}
