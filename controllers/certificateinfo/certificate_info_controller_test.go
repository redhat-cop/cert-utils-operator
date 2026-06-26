package certificateinfo

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

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

// fakeEventRecorder implements record.EventRecorder for testing
type fakeEventRecorder struct{}

func (f *fakeEventRecorder) Event(object runtime.Object, eventtype, reason, message string) {}
func (f *fakeEventRecorder) Eventf(object runtime.Object, eventtype, reason, messageFmt string, args ...interface{}) {
}
func (f *fakeEventRecorder) AnnotatedEventf(object runtime.Object, annotations map[string]string, eventtype, reason, messageFmt string, args ...interface{}) {
}

// generateTestCertificate creates a valid self-signed certificate for testing
func generateTestCertificate(t *testing.T, cn string) []byte {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
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

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
}

func TestGenerateCertInfo(t *testing.T) {
	reconciler := &CertificateInfoReconciler{
		Log: zap.New(zap.UseDevMode(true)),
	}

	tests := []struct {
		name           string
		pemCert        []byte
		expectedFields []string
	}{
		{
			name:    "single certificate",
			pemCert: generateTestCertificate(t, "test.example.com"),
			expectedFields: []string{
				"Subject:",
				"CN=test.example.com",
				"Issuer:",
				"Serial Number:",
			},
		},
		{
			name: "multiple certificates",
			pemCert: append(
				generateTestCertificate(t, "cert1.example.com"),
				generateTestCertificate(t, "cert2.example.com")...,
			),
			expectedFields: []string{
				"CN=cert1.example.com",
				"CN=cert2.example.com",
			},
		},
		{
			name:           "empty input",
			pemCert:        []byte(""),
			expectedFields: []string{},
		},
		{
			name:           "invalid PEM - returns empty",
			pemCert:        []byte("not a valid pem"),
			expectedFields: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reconciler.generateCertInfo(tt.pemCert)

			for _, field := range tt.expectedFields {
				if !strings.Contains(result, field) {
					t.Errorf("generateCertInfo() output missing expected field: %s", field)
				}
			}

			if len(tt.expectedFields) == 0 && result != "" {
				t.Errorf("generateCertInfo() = %v, want empty string", result)
			}
		})
	}
}

func TestIsAnnotatedSecretPredicate(t *testing.T) {
	tests := []struct {
		name     string
		event    interface{}
		expected bool
	}{
		{
			name: "create event - TLS secret with annotation true",
			event: event.CreateEvent{
				Object: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							certInfoAnnotation: "true",
						},
					},
					Type: corev1.SecretTypeTLS,
				},
			},
			expected: true,
		},
		{
			name: "create event - TLS secret with annotation false",
			event: event.CreateEvent{
				Object: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							certInfoAnnotation: "false",
						},
					},
					Type: corev1.SecretTypeTLS,
				},
			},
			expected: false,
		},
		{
			name: "create event - non-TLS secret with annotation",
			event: event.CreateEvent{
				Object: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							certInfoAnnotation: "true",
						},
					},
					Type: corev1.SecretTypeOpaque,
				},
			},
			expected: false,
		},
		{
			name: "update event - annotation changed to true",
			event: event.UpdateEvent{
				ObjectOld: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							certInfoAnnotation: "false",
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
							certInfoAnnotation: "true",
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
			name: "update event - cert content changed with annotation true",
			event: event.UpdateEvent{
				ObjectOld: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							certInfoAnnotation: "true",
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
							certInfoAnnotation: "true",
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
			name: "update event - cert content changed but annotation false",
			event: event.UpdateEvent{
				ObjectOld: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							certInfoAnnotation: "false",
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
							certInfoAnnotation: "false",
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
		{
			name: "update event - CA content changed",
			event: event.UpdateEvent{
				ObjectOld: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							certInfoAnnotation: "true",
						},
					},
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						util.CA: []byte("old-ca"),
					},
				},
				ObjectNew: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							certInfoAnnotation: "true",
						},
					},
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						util.CA: []byte("new-ca"),
					},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
					oldValue, _ := e.ObjectOld.GetAnnotations()[certInfoAnnotation]
					newValue, _ := e.ObjectNew.GetAnnotations()[certInfoAnnotation]
					old := oldValue == "true"
					new := newValue == "true"
					if !reflect.DeepEqual(newSecret.Data[util.Cert], oldSecret.Data[util.Cert]) ||
						!reflect.DeepEqual(newSecret.Data[util.CA], oldSecret.Data[util.CA]) {
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
					value, _ := e.Object.GetAnnotations()[certInfoAnnotation]
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

func TestReconcile(t *testing.T) {
	certPEM := generateTestCertificate(t, "test.example.com")
	caPEM := generateTestCertificate(t, "ca.example.com")

	tests := []struct {
		name         string
		secret       *corev1.Secret
		validateFunc func(*testing.T, *corev1.Secret)
		expectError  bool
	}{
		{
			name: "annotation true - generate cert info",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-ns",
					Annotations: map[string]string{
						certInfoAnnotation: "true",
					},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					util.Cert: certPEM,
					util.CA:   caPEM,
				},
			},
			validateFunc: func(t *testing.T, s *corev1.Secret) {
				if _, ok := s.Data[certInfo]; !ok {
					t.Error("tls.crt.info not generated")
				}
				if _, ok := s.Data[caInfo]; !ok {
					t.Error("ca.crt.info not generated")
				}
				// Verify cert info contains expected fields
				certInfoStr := string(s.Data[certInfo])
				if !strings.Contains(certInfoStr, "CN=test.example.com") {
					t.Error("cert info missing CN")
				}
				caInfoStr := string(s.Data[caInfo])
				if !strings.Contains(caInfoStr, "CN=ca.example.com") {
					t.Error("CA info missing CN")
				}
			},
		},
		{
			name: "annotation true - only cert (no CA)",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-ns",
					Annotations: map[string]string{
						certInfoAnnotation: "true",
					},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					util.Cert: certPEM,
				},
			},
			validateFunc: func(t *testing.T, s *corev1.Secret) {
				if _, ok := s.Data[certInfo]; !ok {
					t.Error("tls.crt.info not generated")
				}
				if _, ok := s.Data[caInfo]; ok {
					t.Error("ca.crt.info should not be generated without CA")
				}
			},
		},
		{
			name: "annotation false - remove existing info",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-ns",
					Annotations: map[string]string{
						certInfoAnnotation: "false",
					},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					util.Cert: certPEM,
					certInfo:  []byte("old-cert-info"),
					caInfo:    []byte("old-ca-info"),
				},
			},
			validateFunc: func(t *testing.T, s *corev1.Secret) {
				if _, ok := s.Data[certInfo]; ok {
					t.Error("tls.crt.info should be removed when annotation is false")
				}
				if _, ok := s.Data[caInfo]; ok {
					t.Error("ca.crt.info should be removed when annotation is false")
				}
			},
		},
		{
			name: "annotation missing - remove existing info",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-ns",
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					util.Cert: certPEM,
					certInfo:  []byte("old-cert-info"),
					caInfo:    []byte("old-ca-info"),
				},
			},
			validateFunc: func(t *testing.T, s *corev1.Secret) {
				if _, ok := s.Data[certInfo]; ok {
					t.Error("tls.crt.info should be removed when annotation is missing")
				}
				if _, ok := s.Data[caInfo]; ok {
					t.Error("ca.crt.info should be removed when annotation is missing")
				}
			},
		},
		{
			name: "empty cert data - no info generated",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-ns",
					Annotations: map[string]string{
						certInfoAnnotation: "true",
					},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					util.Cert: []byte(""),
				},
			},
			validateFunc: func(t *testing.T, s *corev1.Secret) {
				if _, ok := s.Data[certInfo]; ok {
					t.Error("tls.crt.info should not be generated for empty cert")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.secret).
				Build()

			eventRecorder := &fakeEventRecorder{}
			reconciler := &CertificateInfoReconciler{
				ReconcilerBase: outils.NewReconcilerBase(fakeClient, scheme, nil, eventRecorder, nil),
				Log:            zap.New(zap.UseDevMode(true)),
			}

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

	reconciler := &CertificateInfoReconciler{
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

func TestConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"certInfoAnnotation", certInfoAnnotation, "cert-utils-operator.redhat-cop.io/generate-cert-info"},
		{"certInfo", certInfo, "tls.crt.info"},
		{"caInfo", caInfo, "ca.crt.info"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("%s = %v, want %v", tt.name, tt.constant, tt.expected)
			}
		})
	}
}
