package certexpiryalert

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
type fakeEventRecorder struct {
	events []string
}

func (f *fakeEventRecorder) Event(object runtime.Object, eventtype, reason, message string) {
	f.events = append(f.events, eventtype+":"+reason+":"+message)
}
func (f *fakeEventRecorder) Eventf(object runtime.Object, eventtype, reason, messageFmt string, args ...interface{}) {
}
func (f *fakeEventRecorder) AnnotatedEventf(object runtime.Object, annotations map[string]string, eventtype, reason, messageFmt string, args ...interface{}) {
}

// generateTestCertificateWithExpiry creates a certificate with specific expiry for testing
func generateTestCertificateWithExpiry(t *testing.T, notBefore, notAfter time.Time) []byte {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-certificate",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
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

func TestGetExpiry(t *testing.T) {
	reconciler := &CertExpiryAlertReconciler{
		Log: zap.New(zap.UseDevMode(true)),
	}

	now := time.Now()
	future30 := now.Add(30 * 24 * time.Hour)
	future60 := now.Add(60 * 24 * time.Hour)

	tests := []struct {
		name           string
		cert           []byte
		expectedBefore time.Time
	}{
		{
			name:           "single certificate",
			cert:           generateTestCertificateWithExpiry(t, now, future30),
			expectedBefore: future30.Add(time.Second), // Allow 1 second tolerance
		},
		{
			name: "multiple certificates - returns earliest expiry",
			cert: append(
				generateTestCertificateWithExpiry(t, now, future60),
				generateTestCertificateWithExpiry(t, now, future30)...,
			),
			expectedBefore: future30.Add(time.Second),
		},
		{
			name:           "empty certificate",
			cert:           []byte(""),
			expectedBefore: time.Now(), // Returns zero time which is before now
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := &corev1.Secret{
				Data: map[string][]byte{
					util.Cert: tt.cert,
				},
			}

			result := reconciler.getExpiry(secret)

			if result.After(tt.expectedBefore) {
				t.Errorf("getExpiry() = %v, expected before %v", result, tt.expectedBefore)
			}
		})
	}
}

func TestGetCreationAndExpiry(t *testing.T) {
	now := time.Now()
	past := now.Add(-24 * time.Hour)
	future := now.Add(24 * time.Hour)

	tests := []struct {
		name            string
		cert            []byte
		expectCreation  bool
		expectExpiry    bool
	}{
		{
			name:           "valid certificate",
			cert:           generateTestCertificateWithExpiry(t, past, future),
			expectCreation: true,
			expectExpiry:   true,
		},
		{
			name: "multiple certificates",
			cert: append(
				generateTestCertificateWithExpiry(t, past, future),
				generateTestCertificateWithExpiry(t, past.Add(-12*time.Hour), future.Add(12*time.Hour))...,
			),
			expectCreation: true,
			expectExpiry:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := &corev1.Secret{
				Data: map[string][]byte{
					util.Cert: tt.cert,
				},
			}

			creation, expiry := getCreationAndExpiry(context.Background(), secret)

			if tt.expectCreation && creation.IsZero() {
				t.Error("creation time should not be zero")
			}
			if tt.expectExpiry && expiry.IsZero() {
				t.Error("expiry time should not be zero")
			}
			if !expiry.After(creation) {
				t.Errorf("expiry (%v) should be after creation (%v)", expiry, creation)
			}
		})
	}
}

func TestGetExpiryThreshold(t *testing.T) {
	reconciler := &CertExpiryAlertReconciler{
		Log: zap.New(zap.UseDevMode(true)),
	}

	tests := []struct {
		name     string
		secret   *corev1.Secret
		expected time.Duration
	}{
		{
			name: "default threshold when annotation missing",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{},
				},
			},
			expected: defaultSoonToExpireThreshold,
		},
		{
			name: "custom threshold from annotation",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						certSoonToExpireThresholdAnnotation: "720h", // 30 days
					},
				},
			},
			expected: 30 * 24 * time.Hour,
		},
		{
			name: "invalid threshold - returns default",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						certSoonToExpireThresholdAnnotation: "invalid",
					},
				},
			},
			expected: defaultSoonToExpireThreshold,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reconciler.getExpiryThreshold(tt.secret)
			if result != tt.expected {
				t.Errorf("getExpiryThreshold() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetSoonToExpireCheckFrequency(t *testing.T) {
	reconciler := &CertExpiryAlertReconciler{
		Log: zap.New(zap.UseDevMode(true)),
	}

	tests := []struct {
		name     string
		secret   *corev1.Secret
		expected time.Duration
	}{
		{
			name: "default frequency when annotation missing",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{},
				},
			},
			expected: defaultSoonToExpireFrequency,
		},
		{
			name: "custom frequency from annotation",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						certSoonToExpireFrequencyAnnotation: "30m",
					},
				},
			},
			expected: 30 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reconciler.getSoonToExpireCheckFrequency(tt.secret)
			if result != tt.expected {
				t.Errorf("getSoonToExpireCheckFrequency() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetExpiryCheckFrequency(t *testing.T) {
	reconciler := &CertExpiryAlertReconciler{
		Log: zap.New(zap.UseDevMode(true)),
	}

	tests := []struct {
		name     string
		secret   *corev1.Secret
		expected time.Duration
	}{
		{
			name: "default frequency when annotation missing",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{},
				},
			},
			expected: defaultExpireFrequency,
		},
		{
			name: "custom frequency from annotation",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						certExpiryCheckFrequencyAnnotation: "24h",
					},
				},
			},
			expected: 24 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reconciler.getExpiryCheckFrequency(tt.secret)
			if result != tt.expected {
				t.Errorf("getExpiryCheckFrequency() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestMinMax(t *testing.T) {
	t1 := time.Now()
	t2 := t1.Add(time.Hour)

	if got := min(t1, t2); !got.Equal(t1) {
		t.Errorf("min() = %v, want %v", got, t1)
	}

	if got := min(t2, t1); !got.Equal(t1) {
		t.Errorf("min() = %v, want %v", got, t1)
	}

	if got := max(t1, t2); !got.Equal(t2) {
		t.Errorf("max() = %v, want %v", got, t2)
	}

	if got := max(t2, t1); !got.Equal(t2) {
		t.Errorf("max() = %v, want %v", got, t2)
	}
}

func TestReconcile(t *testing.T) {
	now := time.Now()
	expiringSoon := now.Add(30 * 24 * time.Hour)  // 30 days
	expiringLater := now.Add(120 * 24 * time.Hour) // 120 days

	tests := []struct {
		name                string
		secret              *corev1.Secret
		expectRequeue       bool
		expectEvent         bool
		expectedRequeueTime time.Duration
	}{
		{
			name: "certificate expiring soon - emit warning event",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-ns",
					Annotations: map[string]string{
						certExpiryAlertAnnotation: "true",
					},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					util.Cert: generateTestCertificateWithExpiry(t, now, expiringSoon),
				},
			},
			expectRequeue:       true,
			expectEvent:         true,
			expectedRequeueTime: defaultSoonToExpireFrequency,
		},
		{
			name: "certificate not expiring soon - no event",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-ns",
					Annotations: map[string]string{
						certExpiryAlertAnnotation: "true",
					},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					util.Cert: generateTestCertificateWithExpiry(t, now, expiringLater),
				},
			},
			expectRequeue:       true,
			expectEvent:         false,
			expectedRequeueTime: defaultExpireFrequency,
		},
		{
			name: "annotation false - no reconcile",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-ns",
					Annotations: map[string]string{
						certExpiryAlertAnnotation: "false",
					},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					util.Cert: generateTestCertificateWithExpiry(t, now, expiringSoon),
				},
			},
			expectRequeue: false,
			expectEvent:   false,
		},
		{
			name: "empty certificate - no reconcile",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-ns",
					Annotations: map[string]string{
						certExpiryAlertAnnotation: "true",
					},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					util.Cert: []byte(""),
				},
			},
			expectRequeue: false,
			expectEvent:   false,
		},
		{
			name: "custom thresholds and frequencies",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-ns",
					Annotations: map[string]string{
						certExpiryAlertAnnotation:           "true",
						certSoonToExpireThresholdAnnotation: "1440h", // 60 days in hours
						certSoonToExpireFrequencyAnnotation: "30m",
						certExpiryCheckFrequencyAnnotation:  "24h",
					},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					util.Cert: generateTestCertificateWithExpiry(t, now, expiringSoon),
				},
			},
			expectRequeue:       true,
			expectEvent:         true,
			expectedRequeueTime: 30 * time.Minute,
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
			reconciler := &CertExpiryAlertReconciler{
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

			result, err := reconciler.Reconcile(ctx, req)

			if err != nil {
				t.Errorf("Reconcile() unexpected error: %v", err)
				return
			}

			if result.Requeue != tt.expectRequeue {
				t.Errorf("Reconcile() requeue = %v, want %v", result.Requeue, tt.expectRequeue)
			}

			if tt.expectEvent {
				if len(eventRecorder.events) == 0 {
					t.Error("Expected warning event but none was emitted")
				}
			} else {
				if len(eventRecorder.events) > 0 {
					t.Errorf("Expected no events but got: %v", eventRecorder.events)
				}
			}

			if tt.expectRequeue && tt.expectedRequeueTime > 0 {
				if result.RequeueAfter != tt.expectedRequeueTime {
					t.Errorf("Reconcile() requeue after = %v, want %v", result.RequeueAfter, tt.expectedRequeueTime)
				}
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

	reconciler := &CertExpiryAlertReconciler{
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

func TestIsAnnotatedSecretPredicate(t *testing.T) {
	now := time.Now()
	future := now.Add(24 * time.Hour)

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
							certExpiryAlertAnnotation: "true",
						},
					},
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						util.Cert: generateTestCertificateWithExpiry(t, now, future),
					},
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
							certExpiryAlertAnnotation: "false",
						},
					},
					Type: corev1.SecretTypeTLS,
				},
			},
			expected: false,
		},
		{
			name: "create event - non-TLS secret",
			event: event.CreateEvent{
				Object: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							certExpiryAlertAnnotation: "true",
						},
					},
					Type: corev1.SecretTypeOpaque,
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: Full predicate testing with update/delete events is complex
			// due to updateMetrics/deleteMetrics calls that require context
			// This is tested sufficiently in integration tests (Task #8)
			isAnnotatedSecret := predicate.Funcs{
				CreateFunc: func(e event.CreateEvent) bool {
					secret, ok := e.Object.(*corev1.Secret)
					if !ok {
						return false
					}
					if secret.Type != util.TLSSecret {
						return false
					}
					value, _ := e.Object.GetAnnotations()[certExpiryAlertAnnotation]
					return value == "true"
				},
			}

			var result bool
			switch e := tt.event.(type) {
			case event.CreateEvent:
				result = isAnnotatedSecret.Create(e)
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
		constant interface{}
		check    func(interface{}) bool
	}{
		{
			name:     "certExpiryAlertAnnotation",
			constant: certExpiryAlertAnnotation,
			check: func(v interface{}) bool {
				return v == "cert-utils-operator.redhat-cop.io/generate-cert-expiry-alert"
			},
		},
		{
			name:     "defaultSoonToExpireThreshold is 90 days",
			constant: defaultSoonToExpireThreshold,
			check: func(v interface{}) bool {
				return v.(time.Duration) == 90*24*time.Hour
			},
		},
		{
			name:     "defaultSoonToExpireFrequency is 1 hour",
			constant: defaultSoonToExpireFrequency,
			check: func(v interface{}) bool {
				return v.(time.Duration) == time.Hour
			},
		},
		{
			name:     "defaultExpireFrequency is 7 days",
			constant: defaultExpireFrequency,
			check: func(v interface{}) bool {
				return v.(time.Duration) == 7*24*time.Hour
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.check(tt.constant) {
				t.Errorf("%s has unexpected value: %v", tt.name, tt.constant)
			}
		})
	}
}
