package integration

import (
	"context"
	"testing"
	"time"

	"github.com/redhat-cop/cert-utils-operator/controllers/util"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestCAInjection_ConfigMap(t *testing.T) {
	ctx := context.Background()

	// Create source secret with CA bundle
	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-source-secret",
			Namespace: "default",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			util.CA: []byte("test-ca-bundle-content"),
		},
	}
	if err := k8sClient.Create(ctx, sourceSecret); err != nil {
		t.Fatalf("Failed to create source secret: %v", err)
	}
	defer k8sClient.Delete(ctx, sourceSecret)

	// Create target ConfigMap with injection annotation
	targetCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "target-configmap",
			Namespace: "default",
			Annotations: map[string]string{
				util.CertAnnotationSecret: "default/ca-source-secret",
			},
		},
		Data: map[string]string{
			"existing-key": "existing-value",
		},
	}
	if err := k8sClient.Create(ctx, targetCM); err != nil {
		t.Fatalf("Failed to create target configmap: %v", err)
	}
	defer k8sClient.Delete(ctx, targetCM)

	// Wait for CA to be injected
	waitForCondition(t, func() bool {
		updatedCM := &corev1.ConfigMap{}
		if err := k8sClient.Get(ctx, types.NamespacedName{
			Name:      "target-configmap",
			Namespace: "default",
		}, updatedCM); err != nil {
			return false
		}
		return updatedCM.Data[util.CA] == "test-ca-bundle-content"
	}, 10*time.Second, "CA bundle to be injected into ConfigMap")

	// Verify CA was injected
	updatedCM := &corev1.ConfigMap{}
	if err := k8sClient.Get(ctx, types.NamespacedName{
		Name:      "target-configmap",
		Namespace: "default",
	}, updatedCM); err != nil {
		t.Fatalf("Failed to get updated configmap: %v", err)
	}

	if updatedCM.Data[util.CA] != "test-ca-bundle-content" {
		t.Errorf("CA bundle not injected correctly, got: %v", updatedCM.Data[util.CA])
	}

	// Verify existing data wasn't lost
	if updatedCM.Data["existing-key"] != "existing-value" {
		t.Error("Existing ConfigMap data was lost")
	}
}

func TestCAInjection_Secret(t *testing.T) {
	ctx := context.Background()

	// Create source secret with CA bundle
	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-source-secret-2",
			Namespace: "default",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			util.CA: []byte("test-ca-bundle-secret"),
		},
	}
	if err := k8sClient.Create(ctx, sourceSecret); err != nil {
		t.Fatalf("Failed to create source secret: %v", err)
	}
	defer k8sClient.Delete(ctx, sourceSecret)

	// Create target Secret with injection annotation
	targetSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "target-secret",
			Namespace: "default",
			Annotations: map[string]string{
				util.CertAnnotationSecret: "default/ca-source-secret-2",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"existing-key": []byte("existing-value"),
		},
	}
	if err := k8sClient.Create(ctx, targetSecret); err != nil {
		t.Fatalf("Failed to create target secret: %v", err)
	}
	defer k8sClient.Delete(ctx, targetSecret)

	// Wait for CA to be injected
	waitForCondition(t, func() bool {
		updatedSecret := &corev1.Secret{}
		if err := k8sClient.Get(ctx, types.NamespacedName{
			Name:      "target-secret",
			Namespace: "default",
		}, updatedSecret); err != nil {
			return false
		}
		return string(updatedSecret.Data[util.CA]) == "test-ca-bundle-secret"
	}, 10*time.Second, "CA bundle to be injected into Secret")

	// Verify CA was injected
	updatedSecret := &corev1.Secret{}
	if err := k8sClient.Get(ctx, types.NamespacedName{
		Name:      "target-secret",
		Namespace: "default",
	}, updatedSecret); err != nil {
		t.Fatalf("Failed to get updated secret: %v", err)
	}

	if string(updatedSecret.Data[util.CA]) != "test-ca-bundle-secret" {
		t.Errorf("CA bundle not injected correctly, got: %v", string(updatedSecret.Data[util.CA]))
	}

	// Verify existing data wasn't lost
	if string(updatedSecret.Data["existing-key"]) != "existing-value" {
		t.Error("Existing Secret data was lost")
	}
}

func TestCAInjection_AnnotationRemoval(t *testing.T) {
	ctx := context.Background()

	// Create source secret
	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-source-secret-3",
			Namespace: "default",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			util.CA: []byte("test-ca-bundle-removal"),
		},
	}
	if err := k8sClient.Create(ctx, sourceSecret); err != nil {
		t.Fatalf("Failed to create source secret: %v", err)
	}
	defer k8sClient.Delete(ctx, sourceSecret)

	// Create ConfigMap with annotation
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-removal-cm",
			Namespace: "default",
			Annotations: map[string]string{
				util.CertAnnotationSecret: "default/ca-source-secret-3",
			},
		},
		Data: map[string]string{},
	}
	if err := k8sClient.Create(ctx, cm); err != nil {
		t.Fatalf("Failed to create configmap: %v", err)
	}
	defer k8sClient.Delete(ctx, cm)

	// Wait for CA to be injected
	waitForCondition(t, func() bool {
		updatedCM := &corev1.ConfigMap{}
		if err := k8sClient.Get(ctx, types.NamespacedName{
			Name:      "test-removal-cm",
			Namespace: "default",
		}, updatedCM); err != nil {
			return false
		}
		return updatedCM.Data[util.CA] != ""
	}, 10*time.Second, "CA bundle to be injected")

	// Remove the annotation
	updatedCM := &corev1.ConfigMap{}
	if err := k8sClient.Get(ctx, types.NamespacedName{
		Name:      "test-removal-cm",
		Namespace: "default",
	}, updatedCM); err != nil {
		t.Fatalf("Failed to get configmap: %v", err)
	}

	delete(updatedCM.Annotations, util.CertAnnotationSecret)
	if err := k8sClient.Update(ctx, updatedCM); err != nil {
		t.Fatalf("Failed to update configmap: %v", err)
	}

	// Wait for CA to be removed
	waitForCondition(t, func() bool {
		cm := &corev1.ConfigMap{}
		if err := k8sClient.Get(ctx, types.NamespacedName{
			Name:      "test-removal-cm",
			Namespace: "default",
		}, cm); err != nil {
			return false
		}
		_, exists := cm.Data[util.CA]
		return !exists
	}, 10*time.Second, "CA bundle to be removed")

	// Verify CA was removed
	finalCM := &corev1.ConfigMap{}
	if err := k8sClient.Get(ctx, types.NamespacedName{
		Name:      "test-removal-cm",
		Namespace: "default",
	}, finalCM); err != nil {
		t.Fatalf("Failed to get final configmap: %v", err)
	}

	if _, exists := finalCM.Data[util.CA]; exists {
		t.Error("CA bundle should have been removed when annotation was deleted")
	}
}

func TestCAInjection_SourceSecretUpdate(t *testing.T) {
	ctx := context.Background()

	// Create source secret
	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-source-secret-4",
			Namespace: "default",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			util.CA: []byte("original-ca-bundle"),
		},
	}
	if err := k8sClient.Create(ctx, sourceSecret); err != nil {
		t.Fatalf("Failed to create source secret: %v", err)
	}
	defer k8sClient.Delete(ctx, sourceSecret)

	// Create target ConfigMap
	targetCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-update-cm",
			Namespace: "default",
			Annotations: map[string]string{
				util.CertAnnotationSecret: "default/ca-source-secret-4",
			},
		},
		Data: map[string]string{},
	}
	if err := k8sClient.Create(ctx, targetCM); err != nil {
		t.Fatalf("Failed to create configmap: %v", err)
	}
	defer k8sClient.Delete(ctx, targetCM)

	// Wait for initial CA injection
	waitForCondition(t, func() bool {
		cm := &corev1.ConfigMap{}
		if err := k8sClient.Get(ctx, types.NamespacedName{
			Name:      "test-update-cm",
			Namespace: "default",
		}, cm); err != nil {
			return false
		}
		return cm.Data[util.CA] == "original-ca-bundle"
	}, 10*time.Second, "initial CA bundle to be injected")

	// Update the source secret
	updatedSource := &corev1.Secret{}
	if err := k8sClient.Get(ctx, types.NamespacedName{
		Name:      "ca-source-secret-4",
		Namespace: "default",
	}, updatedSource); err != nil {
		t.Fatalf("Failed to get source secret: %v", err)
	}

	updatedSource.Data[util.CA] = []byte("updated-ca-bundle")
	if err := k8sClient.Update(ctx, updatedSource); err != nil {
		t.Fatalf("Failed to update source secret: %v", err)
	}

	// Wait for CA to be updated in target
	waitForCondition(t, func() bool {
		cm := &corev1.ConfigMap{}
		if err := k8sClient.Get(ctx, types.NamespacedName{
			Name:      "test-update-cm",
			Namespace: "default",
		}, cm); err != nil {
			return false
		}
		return cm.Data[util.CA] == "updated-ca-bundle"
	}, 10*time.Second, "updated CA bundle to be propagated")

	// Verify CA was updated
	finalCM := &corev1.ConfigMap{}
	if err := k8sClient.Get(ctx, types.NamespacedName{
		Name:      "test-update-cm",
		Namespace: "default",
	}, finalCM); err != nil {
		t.Fatalf("Failed to get final configmap: %v", err)
	}

	if finalCM.Data[util.CA] != "updated-ca-bundle" {
		t.Errorf("CA bundle not updated correctly, got: %v", finalCM.Data[util.CA])
	}
}
