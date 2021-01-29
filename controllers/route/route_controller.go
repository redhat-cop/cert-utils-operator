package route

import (
	"context"
	"reflect"

	"github.com/go-logr/logr"
	routev1 "github.com/openshift/api/route/v1"
	"github.com/redhat-cop/cert-utils-operator/controllers/util"
	outils "github.com/redhat-cop/operator-utils/pkg/util"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const certAnnotation = util.AnnotationBase + "/certs-from-secret"
const destCAAnnotation = util.AnnotationBase + "/destinationCA-from-secret"

// RouteCertificateReconciler reconciles a Namespace object
type RouteCertificateReconciler struct {
	outils.ReconcilerBase
	Log            logr.Logger
	controllerName string
}

// SetupWithManager sets up the controller with the Manager.
func (r *RouteCertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.controllerName = "route_certificate_controller"

	// this will filter routes that have the annotation and on update only if the annotation is changed.
	isAnnotatedAndSecureRoute := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			newRoute, ok := e.ObjectNew.DeepCopyObject().(*routev1.Route)
			if !ok || newRoute.Spec.TLS == nil || !(newRoute.Spec.TLS.Termination == "edge" || newRoute.Spec.TLS.Termination == "reencrypt") {
				return false
			}
			oldSecret, _ := e.ObjectOld.GetAnnotations()[certAnnotation]
			newSecret, _ := e.ObjectNew.GetAnnotations()[certAnnotation]
			if oldSecret != newSecret {
				return true
			}
			oldRoute, _ := e.ObjectOld.DeepCopyObject().(*routev1.Route)
			if newSecret != "" {
				if newRoute.Spec.TLS.Key != oldRoute.Spec.TLS.Key {
					return true
				}
				if newRoute.Spec.TLS.Certificate != oldRoute.Spec.TLS.Certificate {
					return true
				}
				if newRoute.Spec.TLS.CACertificate != oldRoute.Spec.TLS.CACertificate {
					return true
				}
			}
			oldCASecret, _ := e.ObjectOld.GetAnnotations()[destCAAnnotation]
			newCASecret, _ := e.ObjectNew.GetAnnotations()[destCAAnnotation]
			if newCASecret != oldCASecret {
				return true
			}
			if newCASecret != "" {
				if newRoute.Spec.TLS.DestinationCACertificate != oldRoute.Spec.TLS.DestinationCACertificate {
					return true
				}
			}
			return false
		},
		CreateFunc: func(e event.CreateEvent) bool {
			route, ok := e.Object.DeepCopyObject().(*routev1.Route)
			if !ok || route.Spec.TLS == nil || !(route.Spec.TLS.Termination == "edge" || route.Spec.TLS.Termination == "reencrypt") {
				return false
			}
			_, ok = e.Object.GetAnnotations()[certAnnotation]
			_, okca := e.Object.GetAnnotations()[destCAAnnotation]
			return ok || okca
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return false
		},

		GenericFunc: func(e event.GenericEvent) bool {
			return false
		},
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
			return !reflect.DeepEqual(newSecret.Data[util.Cert], oldSecret.Data[util.Cert]) ||
				!reflect.DeepEqual(newSecret.Data[util.Key], oldSecret.Data[util.Key]) ||
				!reflect.DeepEqual(newSecret.Data[util.CA], oldSecret.Data[util.CA])
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

	return ctrl.NewControllerManagedBy(mgr).
		For(&routev1.Route{
			TypeMeta: v1.TypeMeta{
				Kind: "Route",
			},
		}, builder.WithPredicates(isAnnotatedAndSecureRoute)).
		Watches(&source.Kind{Type: &corev1.Secret{
			TypeMeta: v1.TypeMeta{
				Kind: "Secret",
			},
		}}, &enqueueRequestForReferecingRoutes{
			Client: mgr.GetClient(),
			log:    ctrl.Log.WithName("enqueueRequestForReferecingRoutes"),
		}, builder.WithPredicates(isContentChanged)).
		Complete(r)
}

// +kubebuilder:rbac:groups=route.openshift.io,resources=*,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=get;list;watch;create;patch

func (r *RouteCertificateReconciler) Reconcile(context context.Context, req ctrl.Request) (reconcile.Result, error) {
	log := r.Log.WithValues("route-certificate", req.NamespacedName)

	// Fetch the Route instance
	instance := &routev1.Route{}
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
	if instance.Spec.TLS == nil {
		return reconcile.Result{}, nil
	}
	secretName, ok := instance.GetAnnotations()[certAnnotation]
	caSecretName, okca := instance.GetAnnotations()[destCAAnnotation]
	shouldUpdate := false
	if !ok {
		if instance.Spec.TLS.Key != "" {
			instance.Spec.TLS.Key = ""
			shouldUpdate = true
		}
		if instance.Spec.TLS.Certificate != "" {
			instance.Spec.TLS.Certificate = ""
			shouldUpdate = true
		}
		if instance.Spec.TLS.CACertificate != "" {
			instance.Spec.TLS.CACertificate = ""
			shouldUpdate = true
		}

	} else {
		secret := &corev1.Secret{}
		err = r.GetClient().Get(context, types.NamespacedName{
			Namespace: instance.GetNamespace(),
			Name:      secretName,
		}, secret)
		if err != nil {
			log.Error(err, "unable to find referenced secret", "secret", secretName)
			return r.ManageError(context, instance, err)
		}
		shouldUpdate = shouldUpdate || populateRouteWithCertifcates(instance, secret)
	}
	if !okca {
		if instance.Spec.TLS.DestinationCACertificate != "" {
			instance.Spec.TLS.DestinationCACertificate = ""
			shouldUpdate = true
		}
	} else {
		secret := &corev1.Secret{}
		err = r.GetClient().Get(context, types.NamespacedName{
			Namespace: instance.GetNamespace(),
			Name:      caSecretName,
		}, secret)
		if err != nil {
			log.Error(err, "unable to find referenced ca secret", "secret", secretName)
			return r.ManageError(context, instance, err)
		}
		shouldUpdate = shouldUpdate || populateRouteDestCA(instance, secret)
	}

	if shouldUpdate {
		err = r.GetClient().Update(context, instance)
		if err != nil {
			log.Error(err, "unable to update route", "route", instance)
			return r.ManageError(context, instance, err)
		}
	}

	// if we are here we know it's because a route was create/modified or its referenced secret was created/modified
	// therefore the only think we need to do is to update the route certificates

	return r.ManageSuccess(context, instance)
}

func (e *enqueueRequestForReferecingRoutes) matchSecret(c client.Client, secret types.NamespacedName) ([]routev1.Route, error) {
	routeList := &routev1.RouteList{}
	err := c.List(context.TODO(), routeList, &client.ListOptions{
		Namespace: secret.Namespace,
	})
	if err != nil {
		e.log.Error(err, "unable to list routes for this namespace: ", "namespace", secret.Namespace)
		return []routev1.Route{}, err
	}
	result := []routev1.Route{}
	for _, route := range routeList.Items {
		if secretName := route.GetAnnotations()[certAnnotation]; secretName == secret.Name && route.Spec.TLS != nil {
			result = append(result, route)
		}
		if secretName := route.GetAnnotations()[destCAAnnotation]; secretName == secret.Name && route.Spec.TLS != nil {
			result = append(result, route)
		}
	}
	return result, nil
}

type enqueueRequestForReferecingRoutes struct {
	client.Client
	log logr.Logger
}

// trigger a router reconcile event for those routes that reference this secret
func (e *enqueueRequestForReferecingRoutes) Create(evt event.CreateEvent, q workqueue.RateLimitingInterface) {
	routes, _ := e.matchSecret(e.Client, types.NamespacedName{
		Name:      evt.Object.GetName(),
		Namespace: evt.Object.GetNamespace(),
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
	routes, _ := e.matchSecret(e.Client, types.NamespacedName{
		Name:      evt.ObjectNew.GetName(),
		Namespace: evt.ObjectNew.GetNamespace(),
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

func populateRouteWithCertifcates(route *routev1.Route, secret *corev1.Secret) bool {
	shouldUpdate := false
	if route.Spec.TLS.Termination == "edge" || route.Spec.TLS.Termination == "reencrypt" {
		// here we need to replace the terminating certifciate
		if value, ok := secret.Data[util.Key]; ok && len(value) != 0 {
			if route.Spec.TLS.Key != string(value) {
				route.Spec.TLS.Key = string(value)
				shouldUpdate = true
			}
		}
		if value, ok := secret.Data[util.Cert]; ok && len(value) != 0 {
			if route.Spec.TLS.Certificate != string(value) {
				route.Spec.TLS.Certificate = string(value)
				shouldUpdate = true
			}
		}
		if value, ok := secret.Data[util.CA]; ok && len(value) != 0 {
			if route.Spec.TLS.CACertificate != string(value) {
				route.Spec.TLS.CACertificate = string(value)
				shouldUpdate = true
			}
		}
	}
	return shouldUpdate
}

func populateRouteDestCA(route *routev1.Route, secret *corev1.Secret) bool {
	shouldUpdate := false
	if value, ok := secret.Data[util.CA]; ok && len(value) != 0 {
		if route.Spec.TLS.DestinationCACertificate != string(value) {
			route.Spec.TLS.DestinationCACertificate = string(value)
			shouldUpdate = true
		}
	}
	return shouldUpdate
}
