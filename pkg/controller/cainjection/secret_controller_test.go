package cainjection

import (
	"context"
	"testing"

	"github.com/redhat-cop/operator-utils/pkg/util"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/kubectl/pkg/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/stretchr/testify/assert"
)

func TestSecretControllerSecretCreateFromConfigMap(t *testing.T) {
	var (
		name      = "cert-utils-operator"
		namespace = "cert-utils-operator"
	)

	// the configmap to transfer from
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-trust-cm",
			Namespace: namespace,
		},
		Data: map[string]string{
			"ca-bundle.crt": "abc",
		},
	}

	// A secret with configmap injection annotation
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Annotations: map[string]string{
				"cert-utils-operator.redhat-cop.io/injectca-from-configmap": "cert-utils-operator/ca-trust-cm",
			},
		},
		Data: map[string][]byte{
			"tls.crt": nil,
			"tls.key": nil,
		},
		Type: corev1.SecretTypeTLS,
	}

	objs := []runtime.Object{configMap, secret}

	cl := fake.NewFakeClient(objs...)

	fakeRecorder := record.NewFakeRecorder(3)

	reconcileBase := util.NewReconcilerBase(cl, scheme.Scheme, nil, fakeRecorder)
	r := &ReconcileSecret{ReconcilerBase: reconcileBase}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      name,
			Namespace: namespace,
		},
	}
	_, err := r.Reconcile(req)
	if err != nil {
		t.Fatalf("reconcile: (%v)", err)
	}

	// Check that ca.crt was added
	outSecret := &corev1.Secret{}
	cl.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, outSecret)

	// validate ca.crt was set
	assert.Equal(t, []byte("abc"), outSecret.Data["ca.crt"])
}

func TestSecretControllerSecretCreateFromSecret(t *testing.T) {
	var (
		name      = "cert-utils-operator"
		namespace = "cert-utils-operator"
	)

	// the configmap to transfer from
	configMap := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-trust-secret",
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"ca.crt": []byte("abc"),
		},
	}

	// A secret with configmap injection annotation
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Annotations: map[string]string{
				"cert-utils-operator.redhat-cop.io/injectca-from-secret": "cert-utils-operator/ca-trust-secret",
			},
		},
		Data: map[string][]byte{
			"tls.crt": nil,
			"tls.key": nil,
		},
		Type: corev1.SecretTypeTLS,
	}

	objs := []runtime.Object{configMap, secret}

	cl := fake.NewFakeClient(objs...)

	fakeRecorder := record.NewFakeRecorder(3)

	reconcileBase := util.NewReconcilerBase(cl, scheme.Scheme, nil, fakeRecorder)
	r := &ReconcileSecret{ReconcilerBase: reconcileBase}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      name,
			Namespace: namespace,
		},
	}
	_, err := r.Reconcile(req)
	if err != nil {
		t.Fatalf("reconcile: (%v)", err)
	}

	// Check that ca.crt was added
	outSecret := &corev1.Secret{}
	cl.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, outSecret)

	// validate ca.crt was set
	assert.Equal(t, []byte("abc"), outSecret.Data["ca.crt"])
}
