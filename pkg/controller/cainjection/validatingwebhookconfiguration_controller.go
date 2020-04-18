package cainjection

import (
	"context"
	"flag"
	"io/ioutil"
	"reflect"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/redhat-cop/cert-utils-operator/pkg/controller/util"
	outils "github.com/redhat-cop/operator-utils/pkg/util"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
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
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var systemCAFile string

func init() {
	flag.StringVar(&systemCAFile, "systemCaFilename", "/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt", "file where the system ca can be found")
}

const controllerNamewca = "webhook_ca_injection_controller"
const certAnnotationSecret = util.AnnotationBase + "/injectca-from-secret"
const certAnnotationServiceCA = util.AnnotationBase + "/injectca-from-service_ca"

//const systemCAFile = "/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt"
const secretInjection = "Secret"
const systemCAInjection = "System"

var log = logf.Log.WithName("ca_injection_controller")

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */

// Add creates a new ValidatingWebhookConfiguration Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	err := addMutating(mgr, newMutatingReconciler(mgr))
	if err != nil {
		return err
	}
	err = addCRD(mgr, newCRDReconciler(mgr))
	if err != nil {
		return err
	}
	err = addSecretReconciler(mgr, newSecretReconciler(mgr))
	if err != nil {
		return err
	}
	err = addConfigmapReconciler(mgr, newConfigmapReconciler(mgr))
	if err != nil {
		return err
	}
	return addValidating(mgr, newValidatingReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newValidatingReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileValidatingWebhookConfiguration{
		ReconcilerBase: outils.NewReconcilerBase(mgr.GetClient(), mgr.GetScheme(), mgr.GetConfig(), mgr.GetEventRecorderFor(controllerNamewca)),
	}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func addValidating(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New(controllerNamewca, mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	isAnnotatedValidatingWebhookConfiguration := predicate.Funcs{
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

	// Watch for changes to primary resource ValidatingWebhookConfiguration
	err = c.Watch(&source.Kind{Type: &admissionregistrationv1beta1.ValidatingWebhookConfiguration{
		TypeMeta: v1.TypeMeta{
			Kind: "ValidatingWebhookConfiguration",
		},
	}}, &handler.EnqueueRequestForObject{}, isAnnotatedValidatingWebhookConfiguration)
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
	}}, &enqueueRequestForReferecingValidatingWebHooks{
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
		&enqueueRequestForReferecingValidatingWebHooks{
			Client:        mgr.GetClient(),
			InjectionType: systemCAInjection,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileValidatingWebhookConfiguration{}

// ReconcileValidatingWebhookConfiguration reconciles a ValidatingWebhookConfiguration object
type ReconcileValidatingWebhookConfiguration struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	outils.ReconcilerBase
}

// Reconcile reads that state of the cluster for a ValidatingWebhookConfiguration object and makes changes based on the state read
// and what is in the ValidatingWebhookConfiguration.Spec
// TODO(user): Modify this Reconcile function to implement your Controller logic.  This example creates
// a Pod as an example
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileValidatingWebhookConfiguration) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling ValidatingWebhookConfiguration")

	// Fetch the ValidatingWebhookConfiguration instance
	instance := &admissionregistrationv1beta1.ValidatingWebhookConfiguration{}
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

	if ann, _ := instance.GetAnnotations()[certAnnotationServiceCA]; ann == "true" {
		//we need to inject the system ca
		caBundle, err = ioutil.ReadFile(systemCAFile)
		if err != nil {
			log.Error(err, "unable to read file", "file", systemCAFile)
			return r.ManageError(instance, err)
		}
		//log.Info("data read:", "data", string(caBundle))
	}
	if secretNamespacedName, ok := instance.GetAnnotations()[certAnnotationSecret]; ok {
		//we need to inject the secret ca
		caBundle, err = r.getSecretCA(secretNamespacedName[strings.Index(secretNamespacedName, "/")+1:], secretNamespacedName[:strings.Index(secretNamespacedName, "/")])
		if err != nil {
			log.Error(err, "unable to retrive ca from secret", "secret", secretNamespacedName)
			return r.ManageError(instance, err)
		}
	}
	for i := range instance.Webhooks {
		instance.Webhooks[i].ClientConfig.CABundle = caBundle
	}
	err = r.GetClient().Update(context.TODO(), instance)
	if err != nil {
		return r.ManageError(instance, err)
	}
	return r.ManageSuccess(instance)
}

func matchSecretWithValidatingWebhooks(c client.Client, secret types.NamespacedName) ([]admissionregistrationv1beta1.ValidatingWebhookConfiguration, error) {
	validatingWebHookList := &admissionregistrationv1beta1.ValidatingWebhookConfigurationList{}
	err := c.List(context.TODO(), validatingWebHookList, &client.ListOptions{})
	if err != nil {
		log.Error(err, "unable to list ValidatingWebhookConfiguration for this namespace: ")
		return []admissionregistrationv1beta1.ValidatingWebhookConfiguration{}, err
	}
	result := []admissionregistrationv1beta1.ValidatingWebhookConfiguration{}
	for _, validatingWebHook := range validatingWebHookList.Items {
		if secretNamespacedName := validatingWebHook.GetAnnotations()[certAnnotationSecret]; secretNamespacedName[strings.Index(secretNamespacedName, "/")+1:] == secret.Name && secretNamespacedName[:strings.Index(secretNamespacedName, "/")] == secret.Namespace {
			result = append(result, validatingWebHook)
		}
	}
	return result, nil
}

func matchSystemCAWithValidatingWebhooks(c client.Client) ([]admissionregistrationv1beta1.ValidatingWebhookConfiguration, error) {
	validatingWebHookList := &admissionregistrationv1beta1.ValidatingWebhookConfigurationList{}
	err := c.List(context.TODO(), validatingWebHookList, &client.ListOptions{})
	if err != nil {
		log.Error(err, "unable to list ValidatingWebhookConfiguration for all namespaces")
		return []admissionregistrationv1beta1.ValidatingWebhookConfiguration{}, err
	}
	result := []admissionregistrationv1beta1.ValidatingWebhookConfiguration{}
	for _, validatingWebHook := range validatingWebHookList.Items {
		if ann, ok := validatingWebHook.GetAnnotations()[certAnnotationServiceCA]; ok && ann == "true" {
			result = append(result, validatingWebHook)
		}
	}
	return result, nil
}

type enqueueRequestForReferecingValidatingWebHooks struct {
	client.Client
	InjectionType string
}

// trigger a router reconcile event for those routes that reference this secret
func (e *enqueueRequestForReferecingValidatingWebHooks) Create(evt event.CreateEvent, q workqueue.RateLimitingInterface) {
	validatingWebHooks := []admissionregistrationv1beta1.ValidatingWebhookConfiguration{}
	if e.InjectionType == secretInjection {
		validatingWebHooks, _ = matchSecretWithValidatingWebhooks(e.Client, types.NamespacedName{
			Name:      evt.Meta.GetName(),
			Namespace: evt.Meta.GetNamespace(),
		})
	}
	if e.InjectionType == systemCAInjection {
		validatingWebHooks, _ = matchSystemCAWithValidatingWebhooks(e.Client)
	}
	for _, validatingWebHook := range validatingWebHooks {
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Name: validatingWebHook.GetName(),
		}})
	}
}

// Update implements EventHandler
// trigger a router reconcile event for those routes that reference this secret
func (e *enqueueRequestForReferecingValidatingWebHooks) Update(evt event.UpdateEvent, q workqueue.RateLimitingInterface) {
	validatingWebHooks := []admissionregistrationv1beta1.ValidatingWebhookConfiguration{}
	if e.InjectionType == secretInjection {
		validatingWebHooks, _ = matchSecretWithValidatingWebhooks(e.Client, types.NamespacedName{
			Name:      evt.MetaNew.GetName(),
			Namespace: evt.MetaNew.GetNamespace(),
		})
	}
	if e.InjectionType == systemCAInjection {
		validatingWebHooks, _ = matchSystemCAWithValidatingWebhooks(e.Client)
	}
	for _, validatingWebHook := range validatingWebHooks {
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Name: validatingWebHook.GetName(),
		}})
	}
}

// Delete implements EventHandler
func (e *enqueueRequestForReferecingValidatingWebHooks) Delete(evt event.DeleteEvent, q workqueue.RateLimitingInterface) {
	return
}

// Generic implements EventHandler
func (e *enqueueRequestForReferecingValidatingWebHooks) Generic(evt event.GenericEvent, q workqueue.RateLimitingInterface) {
	validatingWebHooks := []admissionregistrationv1beta1.ValidatingWebhookConfiguration{}
	if e.InjectionType == secretInjection {
		validatingWebHooks, _ = matchSecretWithValidatingWebhooks(e.Client, types.NamespacedName{
			Name:      evt.Meta.GetName(),
			Namespace: evt.Meta.GetNamespace(),
		})
	}
	if e.InjectionType == systemCAInjection {
		validatingWebHooks, _ = matchSystemCAWithValidatingWebhooks(e.Client)
	}
	for _, validatingWebHook := range validatingWebHooks {
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Name: validatingWebHook.GetName(),
		}})
	}
}

func (r *ReconcileValidatingWebhookConfiguration) getSecretCA(secretName string, secretNamespace string) ([]byte, error) {
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
