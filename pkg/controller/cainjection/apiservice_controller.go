package cainjection

import (
	"context"
	errs "errors"
	"io/ioutil"
	"reflect"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/redhat-cop/cert-utils-operator/pkg/controller/util"
	outils "github.com/redhat-cop/operator-utils/pkg/util"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const controllerNameAPIService = "apiservice_controller"

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */
// newReconciler returns a new reconcile.Reconciler
func newAPIServiceReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileAPIService{
		ReconcilerBase: outils.NewReconcilerBase(mgr.GetClient(), mgr.GetScheme(), mgr.GetConfig(), mgr.GetEventRecorderFor(controllerNameAPIService)),
	}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func addAPIService(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New(controllerNameAPIService, mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	isAnnotatedAPIService := predicate.Funcs{
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
	err = c.Watch(&source.Kind{Type: &apiregistrationv1.APIService{
		TypeMeta: v1.TypeMeta{
			Kind: "APIService",
		},
	}}, &handler.EnqueueRequestForObject{}, isAnnotatedAPIService)
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
			Kind: "Secret",
		},
	}}, &enqueueRequestForReferecingAPIServices{
		Client:        mgr.GetClient(),
		InjectionType: secretInjection,
	}, isContentChanged)
	if err != nil {
		return err
	}

	//let's watch for the file change
	// we only do this if we are running on openshift
	reconcileBase, ok := r.(*ReconcileAPIService)
	if !ok {
		return errs.New("unable to convert to ReconcileCRD")
	}

	if ok, err := reconcileBase.IsAPIResourceAvailable(schema.GroupVersionKind{
		Group:   "route.openshift.io",
		Version: "v1",
		Kind:    "Route",
	}); ok && err == nil {
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
			&enqueueRequestForReferecingCRDs{
				Client:        mgr.GetClient(),
				InjectionType: systemCAInjection,
			},
		)
		if err != nil {
			return err
		}
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileCRD{}

// ReconcileAPIServer reconciles a apiserver object
type ReconcileAPIService struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	outils.ReconcilerBase
}

// Reconcile reads that state of the cluster for a apiservice object and makes changes based on the state read
// and what is in the apiservice.Spec
func (r *ReconcileAPIService) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling APIService")

	// Fetch the apiservice instance
	instance := &apiregistrationv1.APIService{}
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
	}
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

	//we update only if the fields are initialized
	instance.Spec.CABundle = caBundle
	err = r.GetClient().Update(context.TODO(), instance)
	if err != nil {
		return r.ManageError(instance, err)
	}

	return r.ManageSuccess(instance)
}

func matchSecretWithAPIService(c client.Client, secret types.NamespacedName) ([]apiregistrationv1.APIService, error) {
	APIServiceList := &apiregistrationv1.APIServiceList{}
	err := c.List(context.TODO(), APIServiceList, &client.ListOptions{})
	if err != nil {
		log.Error(err, "unable to list apiservices")
		return []apiregistrationv1.APIService{}, err
	}
	result := []apiregistrationv1.APIService{}
	for _, APIService := range APIServiceList.Items {
		if secretNamespacedName := APIService.GetAnnotations()[certAnnotationSecret]; secretNamespacedName[strings.Index(secretNamespacedName, "/")+1:] == secret.Name && secretNamespacedName[:strings.Index(secretNamespacedName, "/")] == secret.Namespace {
			result = append(result, APIService)
		}
	}
	return result, nil
}

func matchSystemCAWithAPIService(c client.Client) ([]apiregistrationv1.APIService, error) {
	APIServiceList := &apiregistrationv1.APIServiceList{}
	err := c.List(context.TODO(), APIServiceList, &client.ListOptions{})
	if err != nil {
		log.Error(err, "unable to list apiservices")
		return []apiregistrationv1.APIService{}, err
	}
	result := []apiregistrationv1.APIService{}
	for _, APIService := range APIServiceList.Items {
		if ann, ok := APIService.GetAnnotations()[certAnnotationServiceCA]; ok && ann == "true" {
			result = append(result, APIService)
		}
	}
	return result, nil
}

type enqueueRequestForReferecingAPIServices struct {
	client.Client
	InjectionType string
}

// trigger a router reconcile event for those routes that reference this secret
func (e *enqueueRequestForReferecingAPIServices) Create(evt event.CreateEvent, q workqueue.RateLimitingInterface) {
	APIServices := []apiregistrationv1.APIService{}
	if e.InjectionType == secretInjection {
		APIServices, _ = matchSecretWithAPIService(e.Client, types.NamespacedName{
			Name:      evt.Meta.GetName(),
			Namespace: evt.Meta.GetNamespace(),
		})
	}
	if e.InjectionType == systemCAInjection {
		APIServices, _ = matchSystemCAWithAPIService(e.Client)
	}
	for _, CRD := range APIServices {
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Name: CRD.GetName(),
		}})
	}
}

// Update implements EventHandler
// trigger a router reconcile event for those routes that reference this secret
func (e *enqueueRequestForReferecingAPIServices) Update(evt event.UpdateEvent, q workqueue.RateLimitingInterface) {
	APIServices := []apiregistrationv1.APIService{}
	if e.InjectionType == secretInjection {
		APIServices, _ = matchSecretWithAPIService(e.Client, types.NamespacedName{
			Name:      evt.MetaNew.GetName(),
			Namespace: evt.MetaNew.GetNamespace(),
		})
	}
	if e.InjectionType == systemCAInjection {
		APIServices, _ = matchSystemCAWithAPIService(e.Client)
	}
	for _, CRD := range APIServices {
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Name: CRD.GetName(),
		}})
	}
}

// Delete implements EventHandler
func (e *enqueueRequestForReferecingAPIServices) Delete(evt event.DeleteEvent, q workqueue.RateLimitingInterface) {
	return
}

// Generic implements EventHandler
func (e *enqueueRequestForReferecingAPIServices) Generic(evt event.GenericEvent, q workqueue.RateLimitingInterface) {
	APIServices := []apiregistrationv1.APIService{}
	if e.InjectionType == secretInjection {
		APIServices, _ = matchSecretWithAPIService(e.Client, types.NamespacedName{
			Name:      evt.Meta.GetName(),
			Namespace: evt.Meta.GetNamespace(),
		})
	}
	if e.InjectionType == systemCAInjection {
		APIServices, _ = matchSystemCAWithAPIService(e.Client)
	}
	for _, CRD := range APIServices {
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Name: CRD.GetName(),
		}})
	}
}

func (r *ReconcileAPIService) getSecretCA(secretName string, secretNamespace string) ([]byte, error) {
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
