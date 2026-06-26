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

// fakeEventRecorder implements record.EventRecorder for testing
type fakeEventRecorder struct{}

func (f *fakeEventRecorder) Event(object runtime.Object, eventtype, reason, message string) {}
func (f *fakeEventRecorder) Eventf(object runtime.Object, eventtype, reason, messageFmt string, args ...interface{}) {
}
func (f *fakeEventRecorder) AnnotatedEventf(object runtime.Object, annotations map[string]string, eventtype, reason, messageFmt string, args ...interface{}) {
}

func TestReconcile_ConfigMap(t *testing.T) {
	tests := []struct {
		name         string
		configMap    *corev1.ConfigMap
		secret       *corev1.Secret
		validateFunc func(*testing.T, *corev1.ConfigMap)
		expectError  bool
	}{
		{
			name: "inject CA from secret into configmap",
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cm",
					Namespace: "test-ns",
					Annotations: map[string]string{
						util.CertAnnotationSecret: "test-ns/test-secret",
					},
				},
				Data: map[string]string{},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-ns",
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					util.CA: []byte("test-ca-bundle"),
				},
			},
			validateFunc: func(t *testing.T, cm *corev1.ConfigMap) {
				if cm.Data[util.CA] != "test-ca-bundle" {
					t.Errorf("ConfigMap CA = %v, want %v", cm.Data[util.CA], "test-ca-bundle")
				}
			},
		},
		{
			name: "remove CA when annotation removed",
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cm",
					Namespace: "test-ns",
					// No annotation
				},
				Data: map[string]string{
					util.CA: "old-ca-bundle",
				},
			},
			validateFunc: func(t *testing.T, cm *corev1.ConfigMap) {
				if _, exists := cm.Data[util.CA]; exists {
					t.Error("CA should be removed when annotation is missing")
				}
			},
		},
		{
			name: "remove CA when secret has no CA",
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cm",
					Namespace: "test-ns",
					Annotations: map[string]string{
						util.CertAnnotationSecret: "test-ns/test-secret",
					},
				},
				Data: map[string]string{
					util.CA: "old-ca-bundle",
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-ns",
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					// No CA field
				},
			},
			validateFunc: func(t *testing.T, cm *corev1.ConfigMap) {
				if _, exists := cm.Data[util.CA]; exists {
					t.Error("CA should be removed when secret has no CA")
				}
			},
		},
		{
			name: "initialize Data map if nil",
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cm",
					Namespace: "test-ns",
					Annotations: map[string]string{
						util.CertAnnotationSecret: "test-ns/test-secret",
					},
				},
				// Data is nil
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-ns",
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					util.CA: []byte("test-ca-bundle"),
				},
			},
			validateFunc: func(t *testing.T, cm *corev1.ConfigMap) {
				if cm.Data == nil {
					t.Error("Data map should be initialized")
				}
				if cm.Data[util.CA] != "test-ca-bundle" {
					t.Errorf("ConfigMap CA = %v, want %v", cm.Data[util.CA], "test-ca-bundle")
				}
			},
		},
		{
			name: "update CA when secret changes",
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cm",
					Namespace: "test-ns",
					Annotations: map[string]string{
						util.CertAnnotationSecret: "test-ns/test-secret",
					},
				},
				Data: map[string]string{
					util.CA: "old-ca-bundle",
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-ns",
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					util.CA: []byte("new-ca-bundle"),
				},
			},
			validateFunc: func(t *testing.T, cm *corev1.ConfigMap) {
				if cm.Data[util.CA] != "new-ca-bundle" {
					t.Errorf("ConfigMap CA = %v, want %v", cm.Data[util.CA], "new-ca-bundle")
				}
			},
		},
		{
			name: "invalid secret name - error",
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cm",
					Namespace: "test-ns",
					Annotations: map[string]string{
						util.CertAnnotationSecret: "invalid-no-slash",
					},
				},
			},
			expectError: true,
		},
		{
			name: "secret not found - error",
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cm",
					Namespace: "test-ns",
					Annotations: map[string]string{
						util.CertAnnotationSecret: "test-ns/nonexistent",
					},
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)

			objects := []runtime.Object{tt.configMap}
			if tt.secret != nil {
				objects = append(objects, tt.secret)
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(objects...).
				Build()

			eventRecorder := &fakeEventRecorder{}
			reconciler := &ConfigmapReconciler{
				ReconcilerBase: outils.NewReconcilerBase(fakeClient, scheme, nil, eventRecorder, nil),
				Log:            zap.New(zap.UseDevMode(true)),
			}

			ctx := context.Background()
			req := ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      tt.configMap.Name,
					Namespace: tt.configMap.Namespace,
				},
			}

			_, err := reconciler.Reconcile(ctx, req)

			if (err != nil) != tt.expectError {
				t.Errorf("Reconcile() error = %v, expectError %v", err, tt.expectError)
				return
			}

			if !tt.expectError && tt.validateFunc != nil {
				updatedCM := &corev1.ConfigMap{}
				err = fakeClient.Get(ctx, req.NamespacedName, updatedCM)
				if err != nil {
					t.Fatalf("failed to get updated configmap: %v", err)
				}
				tt.validateFunc(t, updatedCM)
			}
		})
	}
}

func TestReconcile_ConfigMapNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	reconciler := &ConfigmapReconciler{
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

func TestIsAnnotatedForSecretCAInjection_ConfigMap(t *testing.T) {
	tests := []struct {
		name     string
		event    interface{}
		expected bool
	}{
		{
			name: "create event - configmap with annotation",
			event: event.CreateEvent{
				Object: &corev1.ConfigMap{
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
			name: "create event - configmap without annotation",
			event: event.CreateEvent{
				Object: &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{},
				},
			},
			expected: false,
		},
		{
			name: "update event - annotation added",
			event: event.UpdateEvent{
				ObjectOld: &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{},
				},
				ObjectNew: &corev1.ConfigMap{
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
			name: "update event - annotation unchanged",
			event: event.UpdateEvent{
				ObjectOld: &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							util.CertAnnotationSecret: "test-ns/test-secret",
						},
					},
				},
				ObjectNew: &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							util.CertAnnotationSecret: "test-ns/test-secret",
						},
					},
				},
			},
			expected: false,
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
