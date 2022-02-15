package secrettokeystore

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	keystore "github.com/pavel-v-chernykh/keystore-go/v4"
	"github.com/redhat-cop/cert-utils-operator/controllers/util"
	outils "github.com/redhat-cop/operator-utils/pkg/util"
	"github.com/scylladb/go-set/strset"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const javaKeyStoresAnnotation = util.AnnotationBase + "/generate-java-keystores"
const keystorepasswordAnnotation = util.AnnotationBase + "/java-keystore-password"
const storesCreationTiemstamp = util.AnnotationBase + "/java-keystores-creation-timestamp"
const defaultpassword = "changeme"
const keystoreName = "keystore.jks"
const truststoreName = "truststore.jks"

// SecretToKeyStoreReconciler reconciles a Namespace object
type SecretToKeyStoreReconciler struct {
	outils.ReconcilerBase
	Log            logr.Logger
	controllerName string
}

// SetupWithManager sets up the controller with the Manager.
func (r *SecretToKeyStoreReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.controllerName = "secret_to_keystore_controller"

	isAnnotatedSecret := predicate.Funcs{
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
			oldValue := e.ObjectOld.GetAnnotations()[javaKeyStoresAnnotation]
			newValue := e.ObjectNew.GetAnnotations()[javaKeyStoresAnnotation]
			old := oldValue == "true"
			new := newValue == "true"
			// if the content has changed we trigger if the annotation is present
			if !reflect.DeepEqual(newSecret.Data[util.Cert], oldSecret.Data[util.Cert]) ||
				!reflect.DeepEqual(newSecret.Data[util.Key], oldSecret.Data[util.Key]) ||
				!reflect.DeepEqual(newSecret.Data[util.CA], oldSecret.Data[util.CA]) ||
				!reflect.DeepEqual(newSecret.Data[keystoreName], oldSecret.Data[keystoreName]) ||
				!reflect.DeepEqual(newSecret.Data[truststoreName], oldSecret.Data[truststoreName]) {
				return new
			}
			// otherwise we trigger if the annotation has changed
			return old != new
		},
		CreateFunc: func(e event.CreateEvent) bool {
			secret, ok := e.Object.(*corev1.Secret)
			if !ok {
				return false
			}
			if secret.Type != util.TLSSecret {
				return false
			}
			value := e.Object.GetAnnotations()[javaKeyStoresAnnotation]
			return value == "true"
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{
			TypeMeta: v1.TypeMeta{
				Kind: "Secret",
			},
		}, builder.WithPredicates(isAnnotatedSecret)).
		Complete(r)
}

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=get;list;watch;create;patch

func (r *SecretToKeyStoreReconciler) Reconcile(context context.Context, req ctrl.Request) (reconcile.Result, error) {
	log := r.Log.WithValues("secret_to_keystore_contoller", req.NamespacedName)

	// Fetch the Secret instance
	instance := &corev1.Secret{}
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
	//orig_instance := instance.DeepCopy()
	value := instance.GetAnnotations()[javaKeyStoresAnnotation]
	if value == "true" {
		if value, ok := instance.Data[util.Cert]; ok && len(value) != 0 {
			if value, ok := instance.Data[util.Key]; ok && len(value) != 0 {
				keyStore, err := r.getKeyStoreFromSecret(instance)
				if err != nil {
					log.Error(err, "unable to create keystore from secret", "secret", instance.Namespace+"/"+instance.Name)
					return reconcile.Result{}, err
				}
				if oldKeyStoreB, ok := instance.Data[keystoreName]; ok {
					if !compareKeyStoreBinary(oldKeyStoreB, keyStore, []byte(getPassword(instance)), r.Log) {
						instance.Data[keystoreName] = keyStore
					}
				} else {
					instance.Data[keystoreName] = keyStore
				}
			}
		}
		if value, ok := instance.Data[util.CA]; ok && len(value) != 0 {
			trustStore, err := r.getTrustStoreFromSecret(instance)
			if err != nil {
				log.Error(err, "unable to create truststore from secret", "secret", instance.Namespace+"/"+instance.Name)
				return reconcile.Result{}, err
			}
			if oldTrustStoreB, ok := instance.Data[truststoreName]; ok {
				if !compareKeyStoreBinary(oldTrustStoreB, trustStore, []byte(getPassword(instance)), r.Log) {
					instance.Data[truststoreName] = trustStore
				}
			}
			instance.Data[truststoreName] = trustStore
		}
	} else {
		delete(instance.Data, keystoreName)
		delete(instance.Data, truststoreName)
	}

	//client.StrategicMergeFrom(orig_instance)
	//log.V(1).Info("about to patch object", "data len", len(instance.Data), "orig data len", len(orig_instance.Data))
	//err = r.GetClient().Patch(context, instance, client.StrategicMergeFrom(instance))
	log.V(1).Info("updating with", "instance", instance, "key len", len(instance.Data), "resource version", instance.GetResourceVersion())
	err = r.GetClient().Update(context, instance)
	if err != nil {
		log.Error(err, "unable to update secret", "secret", instance.GetName())
		return r.ManageError(context, instance, err)
	}

	return r.ManageSuccess(context, instance)
}

func compareKeyStoreBinary(a, b, password []byte, flog logr.Logger) bool {
	aKeyStore := keystore.New()
	err := aKeyStore.Load(bytes.NewReader(a), password)
	if err != nil {
		flog.Error(err, "unable to loadkeystore")
		return false
	}
	bKeyStore := keystore.New()
	err = bKeyStore.Load(bytes.NewReader(b), password)
	if err != nil {
		flog.Error(err, "unable to loadkeystore")
		return false
	}
	return compareKeyStore(aKeyStore, bKeyStore, password, flog)
}

func compareKeyStore(a, b keystore.KeyStore, password []byte, flog logr.Logger) bool {
	aliasesASet := strset.New(a.Aliases()...)
	aleasesBSet := strset.New(b.Aliases()...)
	if !aliasesASet.IsEqual(aleasesBSet) {
		return false
	}
	for _, alias := range a.Aliases() {
		if a.IsTrustedCertificateEntry(alias) {
			if !b.IsTrustedCertificateEntry(alias) {
				return false
			}
			TCEA, err := a.GetTrustedCertificateEntry(alias)
			if err != nil {
				flog.Error(err, "unable to get trusted cert entry for", "alias", alias)
				return false
			}
			TCEB, err := b.GetTrustedCertificateEntry(alias)
			if err != nil {
				flog.Error(err, "unable to get trusted cert entry for", "alias", alias)
				return false
			}
			if !reflect.DeepEqual(TCEA, TCEB) {
				return false
			}
		}
		if a.IsPrivateKeyEntry(alias) {
			if !b.IsPrivateKeyEntry(alias) {
				return false
			}
			PKEA, err := a.GetPrivateKeyEntry(alias, password)
			if err != nil {
				flog.Error(err, "unable to get private key entry for", "alias", alias)
				return false
			}
			PKEB, err := b.GetPrivateKeyEntry(alias, password)
			if err != nil {
				flog.Error(err, "unable to get private key entry for", "alias", alias)
				return false
			}
			if !reflect.DeepEqual(PKEA, PKEB) {
				return false
			}
		}
	}
	return true
}

func (r *SecretToKeyStoreReconciler) getKeyStoreFromSecret(secret *corev1.Secret) ([]byte, error) {
	keyStore := keystore.New()
	key, ok := secret.Data[util.Key]
	if !ok {
		return []byte{}, errors.New("tls.key not found")
	}
	crt, ok := secret.Data[util.Cert]
	if !ok {
		return []byte{}, errors.New("tls.crt not found")
	}
	certs := []keystore.Certificate{}
	for p, rest := pem.Decode(crt); p != nil; p, rest = pem.Decode(rest) {
		certs = append(certs, keystore.Certificate{
			Type:    "X.509",
			Content: p.Bytes,
		})
	}
	p, _ := pem.Decode(key)
	if p == nil {
		return []byte{}, errors.New("no block found in key.tls, private key should have at least one pem block")
	}
	if !strings.Contains(p.Type, "PRIVATE KEY") {
		return []byte{}, errors.New("private key block not of type PRIVATE KEY")
	}

	creationTime, err := r.getCreationTimestamp(secret)
	if err != nil {
		r.Log.Error(err, "unable to retrieve creation time")
		return []byte{}, err
	}
	r.Log.Info("retrieved", "creation time", creationTime)

	err = keyStore.SetPrivateKeyEntry("alias", keystore.PrivateKeyEntry{
		CreationTime:     creationTime,
		PrivateKey:       p.Bytes,
		CertificateChain: certs,
	}, []byte(getPassword(secret)))

	if err != nil {
		r.Log.Error(err, "unable to set private key entry")
		return []byte{}, err
	}

	buffer := bytes.Buffer{}
	err = keyStore.Store(&buffer, []byte(getPassword(secret)))
	if err != nil {
		r.Log.Error(err, "unable to encode", "keystore", keyStore)
		return []byte{}, err
	}
	return buffer.Bytes(), nil
}

func (r *SecretToKeyStoreReconciler) getTrustStoreFromSecret(secret *corev1.Secret) ([]byte, error) {
	keyStore := keystore.New()
	ca, ok := secret.Data[util.CA]
	if !ok {
		return []byte{}, errors.New("ca bundle key not found: ca.crt")
	}
	creationTime, err := r.getCreationTimestamp(secret)
	if err != nil {
		r.Log.Error(err, "unable to retrieve creation time")
		return []byte{}, err
	}
	r.Log.Info("retrieved", "creation time", creationTime)
	i := 0
	for p, rest := pem.Decode(ca); p != nil; p, rest = pem.Decode(rest) {
		err := keyStore.SetTrustedCertificateEntry("alias"+strconv.Itoa(i), keystore.TrustedCertificateEntry{
			CreationTime: creationTime,
			Certificate: keystore.Certificate{
				Type:    "X.509",
				Content: p.Bytes,
			},
		})
		if err != nil {
			r.Log.Error(err, "unable to set trusted certifciate entry")
			return []byte{}, err
		}
		// increment counter
		i++
	}
	buffer := bytes.Buffer{}
	err = keyStore.Store(&buffer, []byte(getPassword(secret)))
	if err != nil {
		r.Log.Error(err, "unable to encode ", "truststore", keyStore)
		return []byte{}, err
	}
	return buffer.Bytes(), nil
}

func getPassword(secret *corev1.Secret) string {
	if pwd, ok := secret.GetAnnotations()[keystorepasswordAnnotation]; ok && pwd != "" {
		return pwd
	}
	return defaultpassword
}

func (r *SecretToKeyStoreReconciler) getCreationTimestamp(secret *corev1.Secret) (time.Time, error) {

	if timeStr, ok := secret.GetAnnotations()[storesCreationTiemstamp]; ok {
		creationTime, err := time.Parse(time.RFC3339, timeStr)
		if err != nil {
			r.Log.Error(err, "unable to parse creation time")
			return time.Time{}, err
		}
		return creationTime, nil
	} else {
		now := time.Now()
		secret.GetAnnotations()[storesCreationTiemstamp] = now.Format(time.RFC3339)
		return now, nil
	}
}
