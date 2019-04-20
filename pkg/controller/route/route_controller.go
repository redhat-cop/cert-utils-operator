package route

import (
	"context"
	"reflect"

	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	routev1 "github.com/openshift/api/route/v1"
	"github.com/redhat-cop/cert-utils-operator/pkg/controller/util"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const CertAnnotation = "raffa.systems/certs-from-secret"
const ReplaceDestCAAnnotation = "raffa.systems/replace-dest-CA"

var log = logf.Log.WithName("controller_route")

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */

// Add creates a new Route Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileRoute{client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("route-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// this will filter routes that have the annotation and on update only if the annotation is changed.
	isAnnotatedRoute := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldSecret, _ := e.MetaOld.GetAnnotations()[CertAnnotation]
			newSecret, _ := e.MetaNew.GetAnnotations()[CertAnnotation]
			return oldSecret != newSecret
		},
		CreateFunc: func(e event.CreateEvent) bool {
			_, ok := e.Meta.GetAnnotations()[CertAnnotation]
			return ok
		},
	}

	// Watch for changes to primary resource Route
	err = c.Watch(&source.Kind{Type: &routev1.Route{}}, &handler.EnqueueRequestForObject{}, isAnnotatedRoute)
	if err != nil {
		return err
	}

	// this will filter new secrets and secrets where the content changed
	// secret that are actually referenced by routes will be filtered by the handler
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
			return reflect.DeepEqual(oldSecret.Data, newSecret.Data)
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
	// Watch for changes to secondary resource Pods and requeue the owner Route
	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &enqueueRequestForReferecingRoutes{
		Client: mgr.GetClient(),
	}, isContentChanged)
	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileRoute{}

// ReconcileRoute reconciles a Route object
type ReconcileRoute struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// Reconcile reads that state of the cluster for a Route object and makes changes based on the state read
// and what is in the Route.Spec
// TODO(user): Modify this Reconcile function to implement your Controller logic.  This example creates
// a Pod as an example
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileRoute) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling Route")

	// Fetch the Route instance
	instance := &routev1.Route{}
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
	secretName, ok := instance.GetAnnotations()[CertAnnotation]
	if !ok {
		instance.Spec.TLS.Key = ""
		instance.Spec.TLS.Certificate = ""
		instance.Spec.TLS.CACertificate = ""
		instance.Spec.TLS.DestinationCACertificate = ""
	} else {
		secret := &corev1.Secret{}
		err = r.client.Get(context.TODO(), types.NamespacedName{
			Namespace: instance.GetNamespace(),
			Name:      secretName,
		}, secret)
		if err != nil {
			log.Error(err, "unable to find referenced secret", "secret", secretName)
			return reconcile.Result{}, err
		}
		populateRouteWithCertifcates(instance, secret)
	}
	err = r.client.Update(context.TODO(), instance)
	if err != nil {
		log.Error(err, "unable to update route", "route", instance)
		return reconcile.Result{}, err
	}

	// if we are here we know it's because a route was create/modified or its referenced secret was created/modified
	// therefore the only think we need to do is to update the route certificates

	return reconcile.Result{}, nil
}

func matchSecret(c client.Client, secret types.NamespacedName) ([]routev1.Route, error) {
	routeList := &routev1.RouteList{}
	err := c.List(context.TODO(), &client.ListOptions{
		Namespace: secret.Namespace,
	}, routeList)
	if err != nil {
		log.Error(err, "unable to list routes for this namespace: ", "namespace", secret.Namespace)
		return []routev1.Route{}, err
	}
	result := []routev1.Route{}
	for _, route := range routeList.Items {
		if secretName := route.GetAnnotations()[CertAnnotation]; secretName == secret.Name {
			result = append(result, route)
		}
	}
	return result, nil
}

type enqueueRequestForReferecingRoutes struct {
	client.Client
}

// trigger a router reconcile event for those routes that reference this secret
func (e *enqueueRequestForReferecingRoutes) Create(evt event.CreateEvent, q workqueue.RateLimitingInterface) {
	routes, _ := matchSecret(e.Client, types.NamespacedName{
		Name:      evt.Meta.GetName(),
		Namespace: evt.Meta.GetNamespace(),
	})
	for _, route := range routes {
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Namespace: route.GetNamespace(),
			Name:      route.GetName(),
		}})
	}
}

// Update implements EventHandler
// trigger a router reconcile event for those routes that reference this secret
func (e *enqueueRequestForReferecingRoutes) Update(evt event.UpdateEvent, q workqueue.RateLimitingInterface) {
	routes, _ := matchSecret(e.Client, types.NamespacedName{
		Name:      evt.MetaNew.GetName(),
		Namespace: evt.MetaNew.GetNamespace(),
	})
	for _, route := range routes {
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Namespace: route.GetNamespace(),
			Name:      route.GetName(),
		}})
	}
}

// Delete implements EventHandler
func (e *enqueueRequestForReferecingRoutes) Delete(evt event.DeleteEvent, q workqueue.RateLimitingInterface) {
	return
}

// Generic implements EventHandler
func (e *enqueueRequestForReferecingRoutes) Generic(evt event.GenericEvent, q workqueue.RateLimitingInterface) {
	return
}

func populateRouteWithCertifcates(route *routev1.Route, secret *corev1.Secret) {
	if route.Spec.TLS.Termination == "edge" || route.Spec.TLS.Termination == "reencrypt" {
		// here we need to replace the terminating certifciate
		route.Spec.TLS.Key = string(secret.Data["tls.key"])
		route.Spec.TLS.Certificate = string(secret.Data["tls.crt"])
		route.Spec.TLS.CACertificate = string(secret.Data["ca.crt"])
	}
	if replace, _ := route.GetAnnotations()[ReplaceDestCAAnnotation]; replace == "true" {
		// here we also need to replace the ca
		route.Spec.TLS.DestinationCACertificate = string(secret.Data["ca.crt"])
	}
}
