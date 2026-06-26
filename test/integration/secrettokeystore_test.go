package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/redhat-cop/cert-utils-operator/controllers/util"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func generateTestCertificate(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return certPEM, keyPEM
}

func TestSecretToKeyStore_Creation(t *testing.T) {
	ctx := context.Background()

	certPEM, keyPEM := generateTestCertificate(t)

	// Create TLS secret with annotation
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-tls-secret",
			Namespace: "default",
			Annotations: map[string]string{
				"cert-utils-operator.redhat-cop.io/generate-java-keystore": "true",
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			util.Cert: certPEM,
			util.Key:  keyPEM,
			util.CA:   certPEM, // Self-signed
		},
	}

	if err := k8sClient.Create(ctx, secret); err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}
	defer k8sClient.Delete(ctx, secret)

	// Wait for keystore to be generated
	waitForCondition(t, func() bool {
		updatedSecret := &corev1.Secret{}
		if err := k8sClient.Get(ctx, types.NamespacedName{
			Name:      "test-tls-secret",
			Namespace: "default",
		}, updatedSecret); err != nil {
			return false
		}
		_, hasKeystore := updatedSecret.Data["keystore.jks"]
		_, hasTruststore := updatedSecret.Data["truststore.jks"]
		return hasKeystore && hasTruststore
	}, 10*time.Second, "keystore and truststore to be generated")

	// Verify keystores were created
	updatedSecret := &corev1.Secret{}
	if err := k8sClient.Get(ctx, types.NamespacedName{
		Name:      "test-tls-secret",
		Namespace: "default",
	}, updatedSecret); err != nil {
		t.Fatalf("Failed to get updated secret: %v", err)
	}

	if _, exists := updatedSecret.Data["keystore.jks"]; !exists {
		t.Error("keystore.jks not created")
	}

	if _, exists := updatedSecret.Data["truststore.jks"]; !exists {
		t.Error("truststore.jks not created")
	}

	// Verify original cert/key still exist
	if _, exists := updatedSecret.Data[util.Cert]; !exists {
		t.Error("Original tls.crt was removed")
	}
	if _, exists := updatedSecret.Data[util.Key]; !exists {
		t.Error("Original tls.key was removed")
	}
}

func TestSecretToKeyStore_AnnotationRemoval(t *testing.T) {
	ctx := context.Background()

	certPEM, keyPEM := generateTestCertificate(t)

	// Create secret with keystore annotation
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-keystore-removal",
			Namespace: "default",
			Annotations: map[string]string{
				"cert-utils-operator.redhat-cop.io/generate-java-keystore": "true",
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			util.Cert: certPEM,
			util.Key:  keyPEM,
			util.CA:   certPEM,
		},
	}

	if err := k8sClient.Create(ctx, secret); err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}
	defer k8sClient.Delete(ctx, secret)

	// Wait for keystores to be created
	waitForCondition(t, func() bool {
		s := &corev1.Secret{}
		if err := k8sClient.Get(ctx, types.NamespacedName{
			Name:      "test-keystore-removal",
			Namespace: "default",
		}, s); err != nil {
			return false
		}
		_, hasKeystore := s.Data["keystore.jks"]
		return hasKeystore
	}, 10*time.Second, "keystores to be created")

	// Remove the annotation
	updatedSecret := &corev1.Secret{}
	if err := k8sClient.Get(ctx, types.NamespacedName{
		Name:      "test-keystore-removal",
		Namespace: "default",
	}, updatedSecret); err != nil {
		t.Fatalf("Failed to get secret: %v", err)
	}

	delete(updatedSecret.Annotations, "cert-utils-operator.redhat-cop.io/generate-java-keystore")
	if err := k8sClient.Update(ctx, updatedSecret); err != nil {
		t.Fatalf("Failed to update secret: %v", err)
	}

	// Wait for keystores to be removed
	waitForCondition(t, func() bool {
		s := &corev1.Secret{}
		if err := k8sClient.Get(ctx, types.NamespacedName{
			Name:      "test-keystore-removal",
			Namespace: "default",
		}, s); err != nil {
			return false
		}
		_, hasKeystore := s.Data["keystore.jks"]
		_, hasTruststore := s.Data["truststore.jks"]
		return !hasKeystore && !hasTruststore
	}, 10*time.Second, "keystores to be removed")

	// Verify keystores were removed
	finalSecret := &corev1.Secret{}
	if err := k8sClient.Get(ctx, types.NamespacedName{
		Name:      "test-keystore-removal",
		Namespace: "default",
	}, finalSecret); err != nil {
		t.Fatalf("Failed to get final secret: %v", err)
	}

	if _, exists := finalSecret.Data["keystore.jks"]; exists {
		t.Error("keystore.jks should have been removed")
	}
	if _, exists := finalSecret.Data["truststore.jks"]; exists {
		t.Error("truststore.jks should have been removed")
	}

	// Verify original cert/key still exist
	if _, exists := finalSecret.Data[util.Cert]; !exists {
		t.Error("Original tls.crt should still exist")
	}
}

func TestCertificateInfo_Generation(t *testing.T) {
	ctx := context.Background()

	certPEM, keyPEM := generateTestCertificate(t)

	// Create TLS secret with cert-info annotation
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-certinfo-secret",
			Namespace: "default",
			Annotations: map[string]string{
				"cert-utils-operator.redhat-cop.io/generate-cert-info": "true",
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			util.Cert: certPEM,
			util.Key:  keyPEM,
		},
	}

	if err := k8sClient.Create(ctx, secret); err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}
	defer k8sClient.Delete(ctx, secret)

	// Wait for cert info to be generated
	waitForCondition(t, func() bool {
		updatedSecret := &corev1.Secret{}
		if err := k8sClient.Get(ctx, types.NamespacedName{
			Name:      "test-certinfo-secret",
			Namespace: "default",
		}, updatedSecret); err != nil {
			return false
		}
		_, hasCertInfo := updatedSecret.Data["tls.crt.info"]
		return hasCertInfo
	}, 10*time.Second, "certificate info to be generated")

	// Verify cert info was created
	updatedSecret := &corev1.Secret{}
	if err := k8sClient.Get(ctx, types.NamespacedName{
		Name:      "test-certinfo-secret",
		Namespace: "default",
	}, updatedSecret); err != nil {
		t.Fatalf("Failed to get updated secret: %v", err)
	}

	certInfo, exists := updatedSecret.Data["tls.crt.info"]
	if !exists {
		t.Fatal("tls.crt.info not created")
	}

	// Verify cert info contains expected fields
	certInfoStr := string(certInfo)
	expectedFields := []string{"Subject:", "CN=test.example.com", "Issuer:", "Serial Number:"}
	for _, field := range expectedFields {
		if !contains(certInfoStr, field) {
			t.Errorf("Certificate info missing expected field: %s", field)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
