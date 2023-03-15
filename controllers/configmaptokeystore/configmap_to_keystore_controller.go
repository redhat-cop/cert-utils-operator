package configmaptokeystore

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"reflect"
	"strconv"

	"github.com/go-logr/logr"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/redhat-cop/cert-utils-operator/controllers/util"
	outils "github.com/redhat-cop/operator-utils/pkg/util"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const javaTrustStoreAnnotation = util.AnnotationBase + "/generate-java-truststore"
const javaTrustStoreSourceAnnotation = util.AnnotationBase + "/source-ca-key"
const keystorepasswordAnnotation = util.AnnotationBase + "/java-keystore-password"
const defaultpassword = "changeme"
const truststoreName = "truststore.jks"

// ConfigMapToKeystoreReconciler reconciles a Namespace object
type ConfigMapToKeystoreReconciler struct {
	outils.ReconcilerBase
	Log            logr.Logger
	controllerName string
}

// SetupWithManager sets up the controller with the Manager.
func (r *ConfigMapToKeystoreReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.controllerName = "configmap_to_keystore_controller"

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
			oldValue, _ := e.ObjectOld.GetAnnotations()[javaTrustStoreAnnotation]
			newValue, _ := e.ObjectNew.GetAnnotations()[javaTrustStoreAnnotation]
			oldSourceKey := getSourceKey(e.ObjectOld.GetAnnotations())
			newSourceKey := getSourceKey(e.ObjectNew.GetAnnotations())

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
			value, _ := e.Object.GetAnnotations()[javaTrustStoreAnnotation]
			return value == "true"
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ConfigMap{
			TypeMeta: v1.TypeMeta{
				Kind: "ConfigMap",
			},
		}, builder.WithPredicates(isAnnotatedConfigMap)).
		Complete(r)
}

// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=get;list;watch;create;patch

func (r *ConfigMapToKeystoreReconciler) Reconcile(context context.Context, req ctrl.Request) (reconcile.Result, error) {
	log := r.Log.WithValues("configmap-to-keystore", req.NamespacedName)

	// Fetch the Secret instance
	instance := &corev1.ConfigMap{}
	err := r.GetClient().Get(context, req.NamespacedName, instance)
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
			trustStore, err := r.getTrustStoreFromConfigMap(instance, sourceKey)
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

	err = r.GetClient().Update(context, instance)
	if err != nil {
		log.Error(err, "unable to update configmap", "configmap", instance.GetName())
		return r.ManageError(context, instance, err)
	}

	return r.ManageSuccess(context, instance)
}

func (r *ConfigMapToKeystoreReconciler) getTrustStoreFromConfigMap(configMap *corev1.ConfigMap, sourceKey string) ([]byte, error) {
	keyStore := keystore.New(
		keystore.WithOrderedAliases(),
	)
	ca, ok := configMap.Data[sourceKey]
	if !ok {
		return nil, errors.New("ca bundle key not found: " + sourceKey)
	}
	i := 0

	for p, rest := pem.Decode([]byte(ca)); p != nil; p, rest = pem.Decode(rest) {
		keyStore.SetTrustedCertificateEntry(
			"alias"+strconv.Itoa(i),
			keystore.TrustedCertificateEntry{
				CreationTime: configMap.GetCreationTimestamp().Time,
				Certificate: keystore.Certificate{
					Type:    "X.509",
					Content: p.Bytes,
				},
			},
		)
		i++
	}

	buffer := bytes.Buffer{}
	err := keyStore.Store(&buffer, []byte(getPassword(configMap)))
	if err != nil {
		r.Log.Error(err, "unable to encode keystore", "keystore", keyStore)
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
