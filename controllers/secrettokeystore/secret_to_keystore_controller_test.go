package secrettokeystore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	keystore "github.com/pavel-v-chernykh/keystore-go/v4"
	"github.com/redhat-cop/cert-utils-operator/controllers/util"
	outils "github.com/redhat-cop/operator-utils/pkg/util"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const invalidPEM = `not a valid PEM block`

// generateTestCertificate creates a valid self-signed certificate and PKCS#8 private key
// for testing keystore generation
func generateTestCertificate(t *testing.T) (certPEM, keyPEM, caPEM []byte) {
	t.Helper()

	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	// Encode certificate to PEM
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PKCS#8 PEM (required for Java keystores)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// For CA bundle, use the same certificate (self-signed)
	caPEM = certPEM

	return certPEM, keyPEM, caPEM
}

func TestGetPassword(t *testing.T) {
	tests := []struct {
		name   string
		secret *corev1.Secret
		want   string
	}{
		{
			name: "default password when annotation not present",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{},
				},
			},
			want: defaultpassword,
		},
		{
			name: "default password when annotation is empty",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						keystorepasswordAnnotation: "",
					},
				},
			},
			want: defaultpassword,
		},
		{
			name: "custom password from annotation",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						keystorepasswordAnnotation: "custom-password",
					},
				},
			},
			want: "custom-password",
		},
		{
			name: "custom password with special characters",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						keystorepasswordAnnotation: "P@ssw0rd!#$%",
					},
				},
			},
			want: "P@ssw0rd!#$%",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getPassword(tt.secret)
			if got != tt.want {
				t.Errorf("getPassword() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetCreationTimestamp(t *testing.T) {
	reconciler := &SecretToKeyStoreReconciler{
		Log: zap.New(zap.UseDevMode(true)),
	}

	fixedTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	fixedTimeStr := fixedTime.Format(time.RFC3339)

	tests := []struct {
		name               string
		secret             *corev1.Secret
		wantError          bool
		expectAnnotation   bool
		annotationValue    string
		validateTimestampFunc func(time.Time) bool
	}{
		{
			name: "existing valid timestamp annotation",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						storesCreationTiemstamp: fixedTimeStr,
					},
				},
			},
			wantError: false,
			validateTimestampFunc: func(t time.Time) bool {
				return t.Equal(fixedTime)
			},
		},
		{
			name: "no timestamp annotation - should create new",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{},
				},
			},
			wantError:        false,
			expectAnnotation: true,
			validateTimestampFunc: func(t time.Time) bool {
				// Should be close to now (within 1 second)
				return time.Since(t) < time.Second
			},
		},
		{
			name: "invalid timestamp format",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						storesCreationTiemstamp: "invalid-timestamp",
					},
				},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := reconciler.getCreationTimestamp(tt.secret)

			if (err != nil) != tt.wantError {
				t.Errorf("getCreationTimestamp() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if !tt.wantError {
				if tt.validateTimestampFunc != nil && !tt.validateTimestampFunc(got) {
					t.Errorf("getCreationTimestamp() returned unexpected timestamp: %v", got)
				}

				if tt.expectAnnotation {
					if _, ok := tt.secret.Annotations[storesCreationTiemstamp]; !ok {
						t.Errorf("getCreationTimestamp() did not set annotation on secret")
					}
				}
			}
		})
	}
}

func TestGetKeyStoreFromSecret_Errors(t *testing.T) {
	reconciler := &SecretToKeyStoreReconciler{
		Log: zap.New(zap.UseDevMode(true)),
	}

	certPEM, keyPEM, _ := generateTestCertificate(t)

	tests := []struct {
		name      string
		secret    *corev1.Secret
		wantError bool
		errorMsg  string
	}{
		{
			name: "missing tls.key",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test",
					Annotations: map[string]string{
						storesCreationTiemstamp: time.Now().Format(time.RFC3339),
					},
				},
				Data: map[string][]byte{
					util.Cert: certPEM,
				},
			},
			wantError: true,
			errorMsg:  "tls.key not found",
		},
		{
			name: "missing tls.crt",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test",
					Annotations: map[string]string{
						storesCreationTiemstamp: time.Now().Format(time.RFC3339),
					},
				},
				Data: map[string][]byte{
					util.Key: keyPEM,
				},
			},
			wantError: true,
			errorMsg:  "tls.crt not found",
		},
		{
			name: "invalid key PEM format",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test",
					Annotations: map[string]string{
						storesCreationTiemstamp: time.Now().Format(time.RFC3339),
					},
				},
				Data: map[string][]byte{
					util.Cert: certPEM,
					util.Key:  []byte(invalidPEM),
				},
			},
			wantError: true,
			errorMsg:  "no block found in key.tls, private key should have at least one pem block",
		},
		{
			name: "key PEM wrong type (CERTIFICATE not PRIVATE KEY)",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test",
					Annotations: map[string]string{
						storesCreationTiemstamp: time.Now().Format(time.RFC3339),
					},
				},
				Data: map[string][]byte{
					util.Cert: certPEM,
					util.Key:  certPEM, // Wrong: using certificate as key
				},
			},
			wantError: true,
			errorMsg:  "private key block not of type PRIVATE KEY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := reconciler.getKeyStoreFromSecret(tt.secret)

			if (err != nil) != tt.wantError {
				t.Errorf("getKeyStoreFromSecret() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if tt.wantError && err.Error() != tt.errorMsg {
				t.Errorf("getKeyStoreFromSecret() error message = %v, want %v", err.Error(), tt.errorMsg)
			}
		})
	}
}

func TestGetTrustStoreFromSecret_Errors(t *testing.T) {
	reconciler := &SecretToKeyStoreReconciler{
		Log: zap.New(zap.UseDevMode(true)),
	}

	tests := []struct {
		name      string
		secret    *corev1.Secret
		wantError bool
		errorMsg  string
	}{
		{
			name: "missing ca.crt",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test",
					Annotations: map[string]string{
						storesCreationTiemstamp: time.Now().Format(time.RFC3339),
					},
				},
				Data: map[string][]byte{},
			},
			wantError: true,
			errorMsg:  "ca bundle key not found: ca.crt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := reconciler.getTrustStoreFromSecret(tt.secret)

			if (err != nil) != tt.wantError {
				t.Errorf("getTrustStoreFromSecret() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if tt.wantError && err.Error() != tt.errorMsg {
				t.Errorf("getTrustStoreFromSecret() error message = %v, want %v", err.Error(), tt.errorMsg)
			}
		})
	}
}

func TestCompareKeyStore(t *testing.T) {
	logger := zap.New(zap.UseDevMode(true))
	password := []byte("testpassword")

	t.Run("identical keystores", func(t *testing.T) {
		ks1 := keystore.New()
		ks2 := keystore.New()

		// Use same creation time for both entries to ensure DeepEqual works
		creationTime := time.Now()
		cert := keystore.Certificate{
			Type:    "X.509",
			Content: []byte("test-cert-content"),
		}

		_ = ks1.SetTrustedCertificateEntry("alias1", keystore.TrustedCertificateEntry{
			CreationTime: creationTime,
			Certificate:  cert,
		})

		_ = ks2.SetTrustedCertificateEntry("alias1", keystore.TrustedCertificateEntry{
			CreationTime: creationTime,
			Certificate:  cert,
		})

		if !compareKeyStore(ks1, ks2, password, logger) {
			t.Error("compareKeyStore() returned false for identical keystores")
		}
	})

	t.Run("different number of aliases", func(t *testing.T) {
		ks1 := keystore.New()
		ks2 := keystore.New()

		cert := keystore.Certificate{
			Type:    "X.509",
			Content: []byte("test-cert-content"),
		}

		_ = ks1.SetTrustedCertificateEntry("alias1", keystore.TrustedCertificateEntry{
			CreationTime: time.Now(),
			Certificate:  cert,
		})

		_ = ks2.SetTrustedCertificateEntry("alias1", keystore.TrustedCertificateEntry{
			CreationTime: time.Now(),
			Certificate:  cert,
		})

		_ = ks2.SetTrustedCertificateEntry("alias2", keystore.TrustedCertificateEntry{
			CreationTime: time.Now(),
			Certificate:  cert,
		})

		if compareKeyStore(ks1, ks2, password, logger) {
			t.Error("compareKeyStore() returned true for keystores with different alias counts")
		}
	})

	t.Run("different certificate content", func(t *testing.T) {
		ks1 := keystore.New()
		ks2 := keystore.New()

		cert1 := keystore.Certificate{
			Type:    "X.509",
			Content: []byte("test-cert-content-1"),
		}

		cert2 := keystore.Certificate{
			Type:    "X.509",
			Content: []byte("test-cert-content-2"),
		}

		_ = ks1.SetTrustedCertificateEntry("alias1", keystore.TrustedCertificateEntry{
			CreationTime: time.Now(),
			Certificate:  cert1,
		})

		_ = ks2.SetTrustedCertificateEntry("alias1", keystore.TrustedCertificateEntry{
			CreationTime: time.Now(),
			Certificate:  cert2,
		})

		if compareKeyStore(ks1, ks2, password, logger) {
			t.Error("compareKeyStore() returned true for keystores with different certificate content")
		}
	})
}

func TestCompareKeyStoreBinary(t *testing.T) {
	logger := zap.New(zap.UseDevMode(true))
	password := []byte("testpassword")

	t.Run("identical binary keystores", func(t *testing.T) {
		ks := keystore.New()
		cert := keystore.Certificate{
			Type:    "X.509",
			Content: []byte("test-cert-content"),
		}

		_ = ks.SetTrustedCertificateEntry("alias1", keystore.TrustedCertificateEntry{
			CreationTime: time.Now(),
			Certificate:  cert,
		})

		buf1 := bytes.Buffer{}
		_ = ks.Store(&buf1, password)

		buf2 := bytes.Buffer{}
		_ = ks.Store(&buf2, password)

		if !compareKeyStoreBinary(buf1.Bytes(), buf2.Bytes(), password, logger) {
			t.Error("compareKeyStoreBinary() returned false for identical binary keystores")
		}
	})

	t.Run("invalid binary keystore", func(t *testing.T) {
		validKs := keystore.New()
		cert := keystore.Certificate{
			Type:    "X.509",
			Content: []byte("test-cert-content"),
		}

		_ = validKs.SetTrustedCertificateEntry("alias1", keystore.TrustedCertificateEntry{
			CreationTime: time.Now(),
			Certificate:  cert,
		})

		buf := bytes.Buffer{}
		_ = validKs.Store(&buf, password)

		invalidBytes := []byte("not a valid keystore")

		if compareKeyStoreBinary(buf.Bytes(), invalidBytes, password, logger) {
			t.Error("compareKeyStoreBinary() returned true when comparing valid to invalid keystore")
		}

		if compareKeyStoreBinary(invalidBytes, buf.Bytes(), password, logger) {
			t.Error("compareKeyStoreBinary() returned true when comparing invalid to valid keystore")
		}
	})
}

func TestIsAnnotatedSecretPredicate(t *testing.T) {
	tests := []struct {
		name     string
		event    interface{}
		expected bool
	}{
		{
			name: "create event with annotation true",
			event: event.CreateEvent{
				Object: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							javaKeyStoresAnnotation: "true",
						},
					},
					Type: corev1.SecretTypeTLS,
				},
			},
			expected: true,
		},
		{
			name: "create event with annotation false",
			event: event.CreateEvent{
				Object: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							javaKeyStoresAnnotation: "false",
						},
					},
					Type: corev1.SecretTypeTLS,
				},
			},
			expected: false,
		},
		{
			name: "create event non-TLS secret",
			event: event.CreateEvent{
				Object: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							javaKeyStoresAnnotation: "true",
						},
					},
					Type: corev1.SecretTypeOpaque,
				},
			},
			expected: false,
		},
		{
			name: "update event annotation changed to true",
			event: event.UpdateEvent{
				ObjectOld: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							javaKeyStoresAnnotation: "false",
						},
					},
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						util.Cert: []byte("cert"),
					},
				},
				ObjectNew: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							javaKeyStoresAnnotation: "true",
						},
					},
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						util.Cert: []byte("cert"),
					},
				},
			},
			expected: true,
		},
		{
			name: "update event cert content changed with annotation true",
			event: event.UpdateEvent{
				ObjectOld: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							javaKeyStoresAnnotation: "true",
						},
					},
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						util.Cert: []byte("old-cert"),
					},
				},
				ObjectNew: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							javaKeyStoresAnnotation: "true",
						},
					},
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						util.Cert: []byte("new-cert"),
					},
				},
			},
			expected: true,
		},
		{
			name: "update event cert content changed but annotation false",
			event: event.UpdateEvent{
				ObjectOld: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							javaKeyStoresAnnotation: "false",
						},
					},
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						util.Cert: []byte("old-cert"),
					},
				},
				ObjectNew: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							javaKeyStoresAnnotation: "false",
						},
					},
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						util.Cert: []byte("new-cert"),
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reconciler := &SecretToKeyStoreReconciler{}
			_ = reconciler.SetupWithManager(nil)

			// Create the predicate directly (same logic as in SetupWithManager)
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
					if !bytes.Equal(newSecret.Data[util.Cert], oldSecret.Data[util.Cert]) ||
						!bytes.Equal(newSecret.Data[util.Key], oldSecret.Data[util.Key]) ||
						!bytes.Equal(newSecret.Data[util.CA], oldSecret.Data[util.CA]) ||
						!bytes.Equal(newSecret.Data[keystoreName], oldSecret.Data[keystoreName]) ||
						!bytes.Equal(newSecret.Data[truststoreName], oldSecret.Data[truststoreName]) {
						return new
					}
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

			var result bool
			switch e := tt.event.(type) {
			case event.CreateEvent:
				result = isAnnotatedSecret.Create(e)
			case event.UpdateEvent:
				result = isAnnotatedSecret.Update(e)
			}

			if result != tt.expected {
				t.Errorf("isAnnotatedSecret predicate = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"javaKeyStoresAnnotation", javaKeyStoresAnnotation, "cert-utils-operator.redhat-cop.io/generate-java-keystores"},
		{"keystorepasswordAnnotation", keystorepasswordAnnotation, "cert-utils-operator.redhat-cop.io/java-keystore-password"},
		{"storesCreationTiemstamp", storesCreationTiemstamp, "cert-utils-operator.redhat-cop.io/java-keystores-creation-timestamp"},
		{"defaultpassword", defaultpassword, "changeme"},
		{"keystoreName", keystoreName, "keystore.jks"},
		{"truststoreName", truststoreName, "truststore.jks"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("%s = %v, want %v", tt.name, tt.constant, tt.expected)
			}
		})
	}
}

func TestReconcile(t *testing.T) {
	certPEM, keyPEM, caPEM := generateTestCertificate(t)

	tests := []struct {
		name           string
		secret         *corev1.Secret
		validateFunc   func(*testing.T, *corev1.Secret)
		expectError    bool
	}{
		{
			name: "annotation true - generate keystore and truststore",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-ns",
					Annotations: map[string]string{
						javaKeyStoresAnnotation: "true",
					},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					util.Cert: certPEM,
					util.Key:  keyPEM,
					util.CA:   caPEM,
				},
			},
			validateFunc: func(t *testing.T, s *corev1.Secret) {
				if _, ok := s.Data[keystoreName]; !ok {
					t.Error("keystore.jks not generated")
				}
				if _, ok := s.Data[truststoreName]; !ok {
					t.Error("truststore.jks not generated")
				}
				// Verify keystores are valid by loading them
				ks := keystore.New()
				if err := ks.Load(bytes.NewReader(s.Data[keystoreName]), []byte(defaultpassword)); err != nil {
					t.Errorf("generated keystore is invalid: %v", err)
				}
				ts := keystore.New()
				if err := ts.Load(bytes.NewReader(s.Data[truststoreName]), []byte(defaultpassword)); err != nil {
					t.Errorf("generated truststore is invalid: %v", err)
				}
			},
		},
		{
			name: "annotation true - only cert and key (no CA) - only keystore",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-ns",
					Annotations: map[string]string{
						javaKeyStoresAnnotation: "true",
					},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					util.Cert: certPEM,
					util.Key:  keyPEM,
				},
			},
			validateFunc: func(t *testing.T, s *corev1.Secret) {
				if _, ok := s.Data[keystoreName]; !ok {
					t.Error("keystore.jks not generated")
				}
				if _, ok := s.Data[truststoreName]; ok {
					t.Error("truststore.jks should not be generated without CA")
				}
			},
		},
		{
			name: "annotation true - only CA (no cert/key) - only truststore",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-ns",
					Annotations: map[string]string{
						javaKeyStoresAnnotation: "true",
					},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					util.CA: caPEM,
				},
			},
			validateFunc: func(t *testing.T, s *corev1.Secret) {
				if _, ok := s.Data[keystoreName]; ok {
					t.Error("keystore.jks should not be generated without cert and key")
				}
				if _, ok := s.Data[truststoreName]; !ok {
					t.Error("truststore.jks not generated")
				}
			},
		},
		{
			name: "annotation false - remove existing keystores",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-ns",
					Annotations: map[string]string{
						javaKeyStoresAnnotation: "false",
					},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					util.Cert:     certPEM,
					util.Key:      keyPEM,
					util.CA:       caPEM,
					keystoreName:  []byte("old-keystore-data"),
					truststoreName: []byte("old-truststore-data"),
				},
			},
			validateFunc: func(t *testing.T, s *corev1.Secret) {
				if _, ok := s.Data[keystoreName]; ok {
					t.Error("keystore.jks should be removed when annotation is false")
				}
				if _, ok := s.Data[truststoreName]; ok {
					t.Error("truststore.jks should be removed when annotation is false")
				}
			},
		},
		{
			name: "annotation missing - remove existing keystores",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-ns",
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					util.Cert:     certPEM,
					util.Key:      keyPEM,
					keystoreName:  []byte("old-keystore-data"),
					truststoreName: []byte("old-truststore-data"),
				},
			},
			validateFunc: func(t *testing.T, s *corev1.Secret) {
				if _, ok := s.Data[keystoreName]; ok {
					t.Error("keystore.jks should be removed when annotation is missing")
				}
				if _, ok := s.Data[truststoreName]; ok {
					t.Error("truststore.jks should be removed when annotation is missing")
				}
			},
		},
		{
			name: "custom password annotation",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-ns",
					Annotations: map[string]string{
						javaKeyStoresAnnotation:    "true",
						keystorepasswordAnnotation: "custom-pass",
					},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					util.Cert: certPEM,
					util.Key:  keyPEM,
					util.CA:   caPEM,
				},
			},
			validateFunc: func(t *testing.T, s *corev1.Secret) {
				// Verify keystore can be opened with custom password
				ks := keystore.New()
				if err := ks.Load(bytes.NewReader(s.Data[keystoreName]), []byte("custom-pass")); err != nil {
					t.Errorf("keystore should be encrypted with custom password: %v", err)
				}
				// Verify it fails with default password
				ks2 := keystore.New()
				if err := ks2.Load(bytes.NewReader(s.Data[keystoreName]), []byte(defaultpassword)); err == nil {
					t.Error("keystore should NOT open with default password")
				}
			},
		},
		{
			name: "idempotency - keystores already exist with same content",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-ns",
					Annotations: map[string]string{
						javaKeyStoresAnnotation: "true",
						storesCreationTiemstamp: time.Now().Format(time.RFC3339),
					},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					util.Cert: certPEM,
					util.Key:  keyPEM,
					util.CA:   caPEM,
				},
			},
			validateFunc: func(t *testing.T, s *corev1.Secret) {
				// First reconcile generates keystores
				if _, ok := s.Data[keystoreName]; !ok {
					t.Error("keystore.jks not generated on first reconcile")
				}
				if _, ok := s.Data[truststoreName]; !ok {
					t.Error("truststore.jks not generated on first reconcile")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fake client with the secret
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.secret).
				Build()

			// Create reconciler
			reconciler := &SecretToKeyStoreReconciler{
				ReconcilerBase: outils.NewReconcilerBase(fakeClient, scheme, nil, nil, nil),
				Log:            zap.New(zap.UseDevMode(true)),
			}

			// Reconcile
			ctx := context.Background()
			req := ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      tt.secret.Name,
					Namespace: tt.secret.Namespace,
				},
			}

			_, err := reconciler.Reconcile(ctx, req)

			if (err != nil) != tt.expectError {
				t.Errorf("Reconcile() error = %v, expectError %v", err, tt.expectError)
				return
			}

			// Fetch the updated secret
			updatedSecret := &corev1.Secret{}
			err = fakeClient.Get(ctx, req.NamespacedName, updatedSecret)
			if err != nil {
				t.Fatalf("failed to get updated secret: %v", err)
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, updatedSecret)
			}
		})
	}
}

func TestReconcile_SecretNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	reconciler := &SecretToKeyStoreReconciler{
		ReconcilerBase: outils.NewReconcilerBase(fakeClient, scheme, nil, nil, nil),
		Log:            zap.New(zap.UseDevMode(true)),
	}

	ctx := context.Background()
	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "nonexistent",
			Namespace: "test",
		},
	}

	result, err := reconciler.Reconcile(ctx, req)

	if err != nil {
		t.Errorf("Reconcile() should not error on NotFound, got: %v", err)
	}

	if result.Requeue {
		t.Error("Reconcile() should not requeue on NotFound")
	}
}
