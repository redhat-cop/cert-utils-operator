package configmaptokeystore

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"reflect"
	"strconv"
	"time"

	keystore "github.com/pavel-v-chernykh/keystore-go"
	"github.com/redhat-cop/cert-utils-operator/pkg/controller/util"
	outils "github.com/redhat-cop/operator-utils/pkg/util"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const controllerName = "configmap_to_keystore_controller"

var log = logf.Log.WithName(controllerName)

const javaTrustStoreAnnotation = util.AnnotationBase + "/generate-java-truststore"
const javaTrustStoreSourceAnnotation = util.AnnotationBase + "/source-ca-key"
const keystorepasswordAnnotation = util.AnnotationBase + "/java-keystore-password"
const defaultpassword = "changeme"
const truststoreName = "truststore.jks"

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */

// Add creates a new ConfigMap Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileConfigMap{
		ReconcilerBase: outils.NewReconcilerBase(mgr.GetClient(), mgr.GetScheme(), mgr.GetConfig(), mgr.GetEventRecorderFor(controllerName)),
	}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New(controllerName, mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	isAnnotatedConfigMap := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldConfigMap, ok := e.ObjectOld.(*corev1.ConfigMap)
			if !ok {
				return false
			}
			newConfigMap, ok := e.ObjectNew.(*corev1.ConfigMap)
			if !ok {
				return false
			}
			oldValue, _ := e.MetaOld.GetAnnotations()[javaTrustStoreAnnotation]
			newValue, _ := e.MetaNew.GetAnnotations()[javaTrustStoreAnnotation]
			oldSourceKey := getSourceKey(e.MetaOld.GetAnnotations())
			newSourceKey := getSourceKey(e.MetaNew.GetAnnotations())

			old := oldValue == "true"
			new := newValue == "true"
			// if the content has changed we trigger is the annotation is there
			if !reflect.DeepEqual(newConfigMap.Data[newSourceKey], oldConfigMap.Data[oldSourceKey]) {
				return new
			}
			// otherwise we trigger if the annotation has changed
			return old != new
		},
		CreateFunc: func(e event.CreateEvent) bool {
			value, _ := e.Meta.GetAnnotations()[javaTrustStoreAnnotation]
			return value == "true"
		},
	}

	// Watch for changes to primary resource Secret
	err = c.Watch(&source.Kind{Type: &corev1.ConfigMap{
		TypeMeta: v1.TypeMeta{
			Kind: "ConfigMap",
		},
	}}, &handler.EnqueueRequestForObject{}, isAnnotatedConfigMap)
	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileConfigMap{}

// ReconcileConfigMap reconciles a ConfigMap object
type ReconcileConfigMap struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	outils.ReconcilerBase
}

// Reconcile reads that state of the cluster for a Secret object and makes changes based on the state read
// and what is in the Secret.Spec
// TODO(user): Modify this Reconcile function to implement your Controller logic.  This example creates
// a Pod as an example
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileConfigMap) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling ConfigMap")

	// Fetch the Secret instance
	instance := &corev1.ConfigMap{}
	err := r.GetClient().Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}
	value, _ := instance.GetAnnotations()[javaTrustStoreAnnotation]
	if value == "true" {
		sourceKey := getSourceKey(instance.GetAnnotations())
		if value, ok := instance.Data[sourceKey]; ok && len(value) != 0 {
			trustStore, err := getTrustStoreFromConfigMap(instance, sourceKey)
			if err != nil {
				log.Error(err, "unable to create truststore from configmap", "configmap", instance.Namespace+"/"+instance.Name)
				return reconcile.Result{}, err
			}
			if instance.BinaryData == nil {
				instance.BinaryData = make(map[string][]byte)
			}
			instance.BinaryData[truststoreName] = trustStore
		}
	} else {
		delete(instance.Data, truststoreName)
	}

	err = r.GetClient().Update(context.TODO(), instance)
	if err != nil {
		log.Error(err, "unable to update configmap", "configmap", instance.GetName())
		return r.ManageError(instance, err)
	}

	return r.ManageSuccess(instance)
}

func getTrustStoreFromConfigMap(configMap *corev1.ConfigMap, sourceKey string) ([]byte, error) {
	keyStore := keystore.KeyStore{}
	ca, ok := configMap.Data[sourceKey]
	if !ok {
		return nil, errors.New("ca bundle key not found: " + sourceKey)
	}
	i := 0
	for p, rest := pem.Decode([]byte(ca)); p != nil; p, rest = pem.Decode(rest) {
		keyStore["alias"+strconv.Itoa(i)] = &keystore.TrustedCertificateEntry{
			Entry: keystore.Entry{
				CreationDate: time.Now(),
			},
			Certificate: keystore.Certificate{
				Type:    "X.509",
				Content: p.Bytes,
			},
		}
		i++
	}
	buffer := bytes.Buffer{}
	err := keystore.Encode(&buffer, keyStore, []byte(getPassword(configMap)))
	if err != nil {
		log.Error(err, "unable to encode keystore", "keystore", keyStore)
		return nil, err
	}
	return buffer.Bytes(), nil
}

func getPassword(configMap *corev1.ConfigMap) string {
	if pwd, ok := configMap.GetAnnotations()[keystorepasswordAnnotation]; ok && pwd != "" {
		return pwd
	}
	return defaultpassword
}

func getSourceKey(annotations map[string]string) string {
	sourceKey, err := annotations[javaTrustStoreSourceAnnotation]

	if !err || len(sourceKey) == 0 {
		sourceKey = util.CABundle
	}

	return sourceKey
}
