package cainjection

import (
	"context"
	"testing"

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
)

func TestReconcile_Secret(t *testing.T) {
	tests := []struct {
		name         string
		targetSecret *corev1.Secret
		sourceSecret *corev1.Secret
		validateFunc func(*testing.T, *corev1.Secret)
		expectError  bool
	}{
		{
			name: "inject CA from source secret into target secret",
			targetSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "target-secret",
					Namespace: "test-ns",
					Annotations: map[string]string{
						util.CertAnnotationSecret: "test-ns/source-secret",
					},
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					"existing-key": []byte("existing-value"),
				},
			},
			sourceSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "source-secret",
					Namespace: "test-ns",
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					util.CA: []byte("test-ca-bundle"),
				},
			},
			validateFunc: func(t *testing.T, s *corev1.Secret) {
				if string(s.Data[util.CA]) != "test-ca-bundle" {
					t.Errorf("Secret CA = %v, want %v", string(s.Data[util.CA]), "test-ca-bundle")
				}
			},
		},
		{
			name: "remove CA when annotation removed",
			targetSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "target-secret",
					Namespace: "test-ns",
					// No annotation
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					util.CA: []byte("old-ca-bundle"),
				},
			},
			validateFunc: func(t *testing.T, s *corev1.Secret) {
				if _, exists := s.Data[util.CA]; exists {
					t.Error("CA should be removed when annotation is missing")
				}
			},
		},
		{
			name: "remove CA when source secret has no CA",
			targetSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "target-secret",
					Namespace: "test-ns",
					Annotations: map[string]string{
						util.CertAnnotationSecret: "test-ns/source-secret",
					},
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					util.CA: []byte("old-ca-bundle"),
				},
			},
			sourceSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "source-secret",
					Namespace: "test-ns",
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					// No CA field
				},
			},
			validateFunc: func(t *testing.T, s *corev1.Secret) {
				if _, exists := s.Data[util.CA]; exists {
					t.Error("CA should be removed when source secret has no CA")
				}
			},
		},
		{
			name: "update CA when source secret changes",
			targetSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "target-secret",
					Namespace: "test-ns",
					Annotations: map[string]string{
						util.CertAnnotationSecret: "test-ns/source-secret",
					},
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					util.CA: []byte("old-ca-bundle"),
				},
			},
			sourceSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "source-secret",
					Namespace: "test-ns",
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					util.CA: []byte("new-ca-bundle"),
				},
			},
			validateFunc: func(t *testing.T, s *corev1.Secret) {
				if string(s.Data[util.CA]) != "new-ca-bundle" {
					t.Errorf("Secret CA = %v, want %v", string(s.Data[util.CA]), "new-ca-bundle")
				}
			},
		},
		{
			name: "invalid secret name - error",
			targetSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "target-secret",
					Namespace: "test-ns",
					Annotations: map[string]string{
						util.CertAnnotationSecret: "invalid-no-slash",
					},
				},
				Type: corev1.SecretTypeOpaque,
			},
			expectError: true,
		},
		{
			name: "source secret not found - error",
			targetSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "target-secret",
					Namespace: "test-ns",
					Annotations: map[string]string{
						util.CertAnnotationSecret: "test-ns/nonexistent",
					},
				},
				Type: corev1.SecretTypeOpaque,
			},
			expectError: true,
		},
		{
			name: "cross-namespace CA injection",
			targetSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "target-secret",
					Namespace: "target-ns",
					Annotations: map[string]string{
						util.CertAnnotationSecret: "source-ns/source-secret",
					},
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					"existing-key": []byte("existing-value"),
				},
			},
			sourceSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "source-secret",
					Namespace: "source-ns",
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					util.CA: []byte("cross-ns-ca-bundle"),
				},
			},
			validateFunc: func(t *testing.T, s *corev1.Secret) {
				if string(s.Data[util.CA]) != "cross-ns-ca-bundle" {
					t.Errorf("Secret CA = %v, want %v", string(s.Data[util.CA]), "cross-ns-ca-bundle")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)

			objects := []runtime.Object{tt.targetSecret}
			if tt.sourceSecret != nil {
				objects = append(objects, tt.sourceSecret)
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(objects...).
				Build()

			eventRecorder := &fakeEventRecorder{}
			reconciler := &SecretReconciler{
				ReconcilerBase: outils.NewReconcilerBase(fakeClient, scheme, nil, eventRecorder, nil),
				Log:            zap.New(zap.UseDevMode(true)),
			}

			ctx := context.Background()
			req := ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      tt.targetSecret.Name,
					Namespace: tt.targetSecret.Namespace,
				},
			}

			_, err := reconciler.Reconcile(ctx, req)

			if (err != nil) != tt.expectError {
				t.Errorf("Reconcile() error = %v, expectError %v", err, tt.expectError)
				return
			}

			if !tt.expectError && tt.validateFunc != nil {
				updatedSecret := &corev1.Secret{}
				err = fakeClient.Get(ctx, req.NamespacedName, updatedSecret)
				if err != nil {
					t.Fatalf("failed to get updated secret: %v", err)
				}
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

	reconciler := &SecretReconciler{
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

func TestIsAnnotatedForSecretCAInjection_Secret(t *testing.T) {
	tests := []struct {
		name     string
		event    interface{}
		expected bool
	}{
		{
			name: "create event - secret with annotation",
			event: event.CreateEvent{
				Object: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							util.CertAnnotationSecret: "test-ns/test-secret",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "create event - secret without annotation",
			event: event.CreateEvent{
				Object: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{},
				},
			},
			expected: false,
		},
		{
			name: "update event - annotation added",
			event: event.UpdateEvent{
				ObjectOld: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{},
				},
				ObjectNew: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							util.CertAnnotationSecret: "test-ns/test-secret",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "update event - annotation changed",
			event: event.UpdateEvent{
				ObjectOld: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							util.CertAnnotationSecret: "test-ns/old-secret",
						},
					},
				},
				ObjectNew: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							util.CertAnnotationSecret: "test-ns/new-secret",
						},
					},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result bool
			switch e := tt.event.(type) {
			case event.CreateEvent:
				result = util.IsAnnotatedForSecretCAInjection.Create(e)
			case event.UpdateEvent:
				result = util.IsAnnotatedForSecretCAInjection.Update(e)
			}

			if result != tt.expected {
				t.Errorf("IsAnnotatedForSecretCAInjection predicate = %v, want %v", result, tt.expected)
			}
		})
	}
}
