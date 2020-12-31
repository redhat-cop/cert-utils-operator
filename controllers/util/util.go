package util

import (
	"context"
	"errors"
	"reflect"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const TLSSecret = "kubernetes.io/tls"
const AnnotationBase = "cert-utils-operator.redhat-cop.io"
const Cert = "tls.crt"
const Key = "tls.key"
const CA = "ca.crt"
const CABundle = "ca-bundle.crt"

var log = ctrl.Log.WithName("controllers").WithName("KeepalivedGroup")

const CertAnnotationSecret = AnnotationBase + "/injectca-from-secret"

func ValidateSecretName(secretNamespacedName string) error {
	if strings.Index(secretNamespacedName, "/") == -1 {
		err := errors.New("Invalid ca secret name does not match format {namespace}/{secert-name}")
		return err
	}

	return nil
}

func ValidateConfigMapName(configMapNamespacedName string) error {
	if strings.Index(configMapNamespacedName, "/") == -1 {
		err := errors.New("Invalid ca configmap name does not match format {namespace}/{configmap-name}")
		return err
	}

	return nil
}

var IsAnnotatedForSecretCAInjection = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		oldSecret, _ := e.ObjectOld.GetAnnotations()[CertAnnotationSecret]
		newSecret, _ := e.ObjectNew.GetAnnotations()[CertAnnotationSecret]
		return oldSecret != newSecret
	},
	CreateFunc: func(e event.CreateEvent) bool {
		_, ok1 := e.Object.GetAnnotations()[CertAnnotationSecret]
		return ok1
	},
}

var IsCAContentChanged = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		oldSecret, ok := e.ObjectOld.(*corev1.Secret)
		if !ok {
			return false
		}
		newSecret, ok := e.ObjectNew.(*corev1.Secret)
		if !ok {
			return false
		}
		if newSecret.Type != TLSSecret {
			return false
		}
		return !reflect.DeepEqual(newSecret.Data[CA], oldSecret.Data[CA])
	},
	CreateFunc: func(e event.CreateEvent) bool {
		secret, ok := e.Object.(*corev1.Secret)
		if !ok {
			return false
		}
		if secret.Type != TLSSecret {
			return false
		}
		return true
	},
}

func (e *enqueueRequestForReferecingObject) matchSecretWithResource(secret types.NamespacedName) ([]unstructured.Unstructured, error) {
	unstructuredList, err := e.client.List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		log.Error(err, "unable to list resources", "with client", e.client)
		return []unstructured.Unstructured{}, err
	}
	result := []unstructured.Unstructured{}
	for _, obj := range unstructuredList.Items {
		if secretNamespacedName := obj.GetAnnotations()[CertAnnotationSecret]; secretNamespacedName[strings.Index(secretNamespacedName, "/")+1:] == secret.Name && secretNamespacedName[:strings.Index(secretNamespacedName, "/")] == secret.Namespace {
			result = append(result, obj)
		}
	}
	return result, nil
}

func NewEnqueueRequestForReferecingObject(config *rest.Config, gvk schema.GroupVersionKind) *enqueueRequestForReferecingObject {
	gvr, _ := meta.UnsafeGuessKindToResource(gvk)
	client := dynamic.NewForConfigOrDie(config).Resource(gvr)
	return &enqueueRequestForReferecingObject{
		client: client,
	}
}

type enqueueRequestForReferecingObject struct {
	client dynamic.NamespaceableResourceInterface
}

// trigger a router reconcile event for those routes that reference this secret
func (e *enqueueRequestForReferecingObject) Create(evt event.CreateEvent, q workqueue.RateLimitingInterface) {
	namespacedName := types.NamespacedName{
		Name:      evt.Object.GetName(),
		Namespace: evt.Object.GetNamespace(),
	}
	objs, err := e.matchSecretWithResource(namespacedName)

	if err != nil {
		log.Error(err, "unable to match resources", "with namespaced name", namespacedName)
	}

	for _, obj := range objs {
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Name:      obj.GetName(),
			Namespace: obj.GetNamespace(),
		}})
	}
}

// Update implements EventHandler
// trigger a router reconcile event for those routes that reference this secret
func (e *enqueueRequestForReferecingObject) Update(evt event.UpdateEvent, q workqueue.RateLimitingInterface) {
	namespacedName := types.NamespacedName{
		Name:      evt.ObjectNew.GetName(),
		Namespace: evt.ObjectNew.GetNamespace(),
	}
	objs, err := e.matchSecretWithResource(namespacedName)

	if err != nil {
		log.Error(err, "unable to match resources", "with namespaced name", namespacedName)
	}

	for _, obj := range objs {
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Name:      obj.GetName(),
			Namespace: obj.GetNamespace(),
		}})
	}
}

// Delete implements EventHandler
func (e *enqueueRequestForReferecingObject) Delete(evt event.DeleteEvent, q workqueue.RateLimitingInterface) {
	return
}

// Generic implements EventHandler
func (e *enqueueRequestForReferecingObject) Generic(evt event.GenericEvent, q workqueue.RateLimitingInterface) {
	return
}

func GetSecretCA(c client.Client, secretName string, secretNamespace string) ([]byte, error) {
	secret := &corev1.Secret{}
	err := c.Get(context.TODO(), types.NamespacedName{
		Namespace: secretNamespace,
		Name:      secretName,
	}, secret)
	if err != nil {
		log.Error(err, "unable to find referenced secret", "secret", secretName)
		return []byte{}, err
	}
	return secret.Data[CA], nil
}
