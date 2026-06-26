package cainjection

import (
	"context"
	"testing"

	"github.com/redhat-cop/cert-utils-operator/controllers/util"
	outils "github.com/redhat-cop/operator-utils/pkg/util"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	crd "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// TestReconcile_MutatingWebhook tests the MutatingWebhookConfiguration controller
func TestReconcile_MutatingWebhook(t *testing.T) {
	tests := []struct {
		name         string
		webhook      *admissionregistrationv1.MutatingWebhookConfiguration
		secret       *corev1.Secret
		validateFunc func(*testing.T, *admissionregistrationv1.MutatingWebhookConfiguration)
		expectError  bool
	}{
		{
			name: "inject CA into all webhooks",
			webhook: &admissionregistrationv1.MutatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-webhook",
					Annotations: map[string]string{
						util.CertAnnotationSecret: "test-ns/test-secret",
					},
				},
				Webhooks: []admissionregistrationv1.MutatingWebhook{
					{
						Name: "webhook1.example.com",
						ClientConfig: admissionregistrationv1.WebhookClientConfig{
							CABundle: []byte("old-ca"),
						},
					},
					{
						Name: "webhook2.example.com",
						ClientConfig: admissionregistrationv1.WebhookClientConfig{
							CABundle: []byte("old-ca"),
						},
					},
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
			validateFunc: func(t *testing.T, mwc *admissionregistrationv1.MutatingWebhookConfiguration) {
				for i, webhook := range mwc.Webhooks {
					if string(webhook.ClientConfig.CABundle) != "new-ca-bundle" {
						t.Errorf("Webhook %d CA = %v, want %v", i, string(webhook.ClientConfig.CABundle), "new-ca-bundle")
					}
				}
			},
		},
		{
			name: "clear CA bundles when annotation removed",
			webhook: &admissionregistrationv1.MutatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-webhook",
					// No annotation
				},
				Webhooks: []admissionregistrationv1.MutatingWebhook{
					{
						Name: "webhook1.example.com",
						ClientConfig: admissionregistrationv1.WebhookClientConfig{
							CABundle: []byte("old-ca"),
						},
					},
				},
			},
			validateFunc: func(t *testing.T, mwc *admissionregistrationv1.MutatingWebhookConfiguration) {
				for i, webhook := range mwc.Webhooks {
					if len(webhook.ClientConfig.CABundle) != 0 {
						t.Errorf("Webhook %d CA should be cleared, got %v", i, string(webhook.ClientConfig.CABundle))
					}
				}
			},
		},
		{
			name: "invalid secret name - error",
			webhook: &admissionregistrationv1.MutatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-webhook",
					Annotations: map[string]string{
						util.CertAnnotationSecret: "invalid-no-slash",
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
			_ = admissionregistrationv1.AddToScheme(scheme)

			objects := []runtime.Object{tt.webhook}
			if tt.secret != nil {
				objects = append(objects, tt.secret)
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(objects...).
				Build()

			eventRecorder := &fakeEventRecorder{}
			reconciler := &MutatingWebhookConfigurationReconciler{
				ReconcilerBase: outils.NewReconcilerBase(fakeClient, scheme, nil, eventRecorder, nil),
				Log:            zap.New(zap.UseDevMode(true)),
			}

			ctx := context.Background()
			req := ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name: tt.webhook.Name,
				},
			}

			_, err := reconciler.Reconcile(ctx, req)

			if (err != nil) != tt.expectError {
				t.Errorf("Reconcile() error = %v, expectError %v", err, tt.expectError)
				return
			}

			if !tt.expectError && tt.validateFunc != nil {
				updated := &admissionregistrationv1.MutatingWebhookConfiguration{}
				err = fakeClient.Get(ctx, req.NamespacedName, updated)
				if err != nil {
					t.Fatalf("failed to get updated webhook: %v", err)
				}
				tt.validateFunc(t, updated)
			}
		})
	}
}

// TestReconcile_ValidatingWebhook tests the ValidatingWebhookConfiguration controller
func TestReconcile_ValidatingWebhook(t *testing.T) {
	tests := []struct {
		name         string
		webhook      *admissionregistrationv1.ValidatingWebhookConfiguration
		secret       *corev1.Secret
		validateFunc func(*testing.T, *admissionregistrationv1.ValidatingWebhookConfiguration)
		expectError  bool
	}{
		{
			name: "inject CA into all webhooks",
			webhook: &admissionregistrationv1.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-webhook",
					Annotations: map[string]string{
						util.CertAnnotationSecret: "test-ns/test-secret",
					},
				},
				Webhooks: []admissionregistrationv1.ValidatingWebhook{
					{
						Name: "webhook1.example.com",
						ClientConfig: admissionregistrationv1.WebhookClientConfig{
							CABundle: []byte("old-ca"),
						},
					},
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
			validateFunc: func(t *testing.T, vwc *admissionregistrationv1.ValidatingWebhookConfiguration) {
				for i, webhook := range vwc.Webhooks {
					if string(webhook.ClientConfig.CABundle) != "new-ca-bundle" {
						t.Errorf("Webhook %d CA = %v, want %v", i, string(webhook.ClientConfig.CABundle), "new-ca-bundle")
					}
				}
			},
		},
		{
			name: "clear CA bundles when annotation removed",
			webhook: &admissionregistrationv1.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-webhook",
				},
				Webhooks: []admissionregistrationv1.ValidatingWebhook{
					{
						Name: "webhook1.example.com",
						ClientConfig: admissionregistrationv1.WebhookClientConfig{
							CABundle: []byte("old-ca"),
						},
					},
				},
			},
			validateFunc: func(t *testing.T, vwc *admissionregistrationv1.ValidatingWebhookConfiguration) {
				for i, webhook := range vwc.Webhooks {
					if len(webhook.ClientConfig.CABundle) != 0 {
						t.Errorf("Webhook %d CA should be cleared, got %v", i, string(webhook.ClientConfig.CABundle))
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)
			_ = admissionregistrationv1.AddToScheme(scheme)

			objects := []runtime.Object{tt.webhook}
			if tt.secret != nil {
				objects = append(objects, tt.secret)
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(objects...).
				Build()

			eventRecorder := &fakeEventRecorder{}
			reconciler := &ValidatingWebhookConfigurationReconciler{
				ReconcilerBase: outils.NewReconcilerBase(fakeClient, scheme, nil, eventRecorder, nil),
				Log:            zap.New(zap.UseDevMode(true)),
			}

			ctx := context.Background()
			req := ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name: tt.webhook.Name,
				},
			}

			_, err := reconciler.Reconcile(ctx, req)

			if (err != nil) != tt.expectError {
				t.Errorf("Reconcile() error = %v, expectError %v", err, tt.expectError)
				return
			}

			if !tt.expectError && tt.validateFunc != nil {
				updated := &admissionregistrationv1.ValidatingWebhookConfiguration{}
				err = fakeClient.Get(ctx, req.NamespacedName, updated)
				if err != nil {
					t.Fatalf("failed to get updated webhook: %v", err)
				}
				tt.validateFunc(t, updated)
			}
		})
	}
}

// TestReconcile_CRD tests the CustomResourceDefinition controller
func TestReconcile_CRD(t *testing.T) {
	tests := []struct {
		name         string
		crd          *crd.CustomResourceDefinition
		secret       *corev1.Secret
		validateFunc func(*testing.T, *crd.CustomResourceDefinition)
		expectError  bool
	}{
		{
			name: "inject CA into conversion webhook",
			crd: &crd.CustomResourceDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test.example.com",
					Annotations: map[string]string{
						util.CertAnnotationSecret: "test-ns/test-secret",
					},
				},
				Spec: crd.CustomResourceDefinitionSpec{
					Conversion: &crd.CustomResourceConversion{
						Webhook: &crd.WebhookConversion{
							ClientConfig: &crd.WebhookClientConfig{
								CABundle: []byte("old-ca"),
							},
						},
					},
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
			validateFunc: func(t *testing.T, c *crd.CustomResourceDefinition) {
				if string(c.Spec.Conversion.Webhook.ClientConfig.CABundle) != "new-ca-bundle" {
					t.Errorf("CRD CA = %v, want %v", string(c.Spec.Conversion.Webhook.ClientConfig.CABundle), "new-ca-bundle")
				}
			},
		},
		{
			name: "clear CA when annotation removed",
			crd: &crd.CustomResourceDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test.example.com",
				},
				Spec: crd.CustomResourceDefinitionSpec{
					Conversion: &crd.CustomResourceConversion{
						Webhook: &crd.WebhookConversion{
							ClientConfig: &crd.WebhookClientConfig{
								CABundle: []byte("old-ca"),
							},
						},
					},
				},
			},
			validateFunc: func(t *testing.T, c *crd.CustomResourceDefinition) {
				if len(c.Spec.Conversion.Webhook.ClientConfig.CABundle) != 0 {
					t.Errorf("CRD CA should be cleared, got %v", string(c.Spec.Conversion.Webhook.ClientConfig.CABundle))
				}
			},
		},
		{
			name: "no update when conversion webhook is nil",
			crd: &crd.CustomResourceDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test.example.com",
					Annotations: map[string]string{
						util.CertAnnotationSecret: "test-ns/test-secret",
					},
				},
				Spec: crd.CustomResourceDefinitionSpec{
					Conversion: &crd.CustomResourceConversion{
						Webhook: nil,
					},
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
			validateFunc: func(t *testing.T, c *crd.CustomResourceDefinition) {
				if c.Spec.Conversion.Webhook != nil {
					t.Error("Webhook should remain nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)
			_ = crd.AddToScheme(scheme)

			objects := []runtime.Object{tt.crd}
			if tt.secret != nil {
				objects = append(objects, tt.secret)
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(objects...).
				Build()

			eventRecorder := &fakeEventRecorder{}
			reconciler := &CRDReconciler{
				ReconcilerBase: outils.NewReconcilerBase(fakeClient, scheme, nil, eventRecorder, nil),
				Log:            zap.New(zap.UseDevMode(true)),
			}

			ctx := context.Background()
			req := ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name: tt.crd.Name,
				},
			}

			_, err := reconciler.Reconcile(ctx, req)

			if (err != nil) != tt.expectError {
				t.Errorf("Reconcile() error = %v, expectError %v", err, tt.expectError)
				return
			}

			if !tt.expectError && tt.validateFunc != nil {
				updated := &crd.CustomResourceDefinition{}
				err = fakeClient.Get(ctx, req.NamespacedName, updated)
				if err != nil {
					t.Fatalf("failed to get updated CRD: %v", err)
				}
				tt.validateFunc(t, updated)
			}
		})
	}
}

// TestReconcile_APIService tests the APIService controller
func TestReconcile_APIService(t *testing.T) {
	tests := []struct {
		name         string
		apiService   *apiregistrationv1.APIService
		secret       *corev1.Secret
		validateFunc func(*testing.T, *apiregistrationv1.APIService)
		expectError  bool
	}{
		{
			name: "inject CA into APIService",
			apiService: &apiregistrationv1.APIService{
				ObjectMeta: metav1.ObjectMeta{
					Name: "v1.test.example.com",
					Annotations: map[string]string{
						util.CertAnnotationSecret: "test-ns/test-secret",
					},
				},
				Spec: apiregistrationv1.APIServiceSpec{
					CABundle: []byte("old-ca"),
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
			validateFunc: func(t *testing.T, a *apiregistrationv1.APIService) {
				if string(a.Spec.CABundle) != "new-ca-bundle" {
					t.Errorf("APIService CA = %v, want %v", string(a.Spec.CABundle), "new-ca-bundle")
				}
			},
		},
		{
			name: "clear CA when annotation removed",
			apiService: &apiregistrationv1.APIService{
				ObjectMeta: metav1.ObjectMeta{
					Name: "v1.test.example.com",
				},
				Spec: apiregistrationv1.APIServiceSpec{
					CABundle: []byte("old-ca"),
				},
			},
			validateFunc: func(t *testing.T, a *apiregistrationv1.APIService) {
				if len(a.Spec.CABundle) != 0 {
					t.Errorf("APIService CA should be cleared, got %v", string(a.Spec.CABundle))
				}
			},
		},
		{
			name: "update CA when secret changes",
			apiService: &apiregistrationv1.APIService{
				ObjectMeta: metav1.ObjectMeta{
					Name: "v1.test.example.com",
					Annotations: map[string]string{
						util.CertAnnotationSecret: "test-ns/test-secret",
					},
				},
				Spec: apiregistrationv1.APIServiceSpec{
					CABundle: []byte("old-ca"),
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-ns",
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					util.CA: []byte("updated-ca-bundle"),
				},
			},
			validateFunc: func(t *testing.T, a *apiregistrationv1.APIService) {
				if string(a.Spec.CABundle) != "updated-ca-bundle" {
					t.Errorf("APIService CA = %v, want %v", string(a.Spec.CABundle), "updated-ca-bundle")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)
			_ = apiregistrationv1.AddToScheme(scheme)

			objects := []runtime.Object{tt.apiService}
			if tt.secret != nil {
				objects = append(objects, tt.secret)
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(objects...).
				Build()

			eventRecorder := &fakeEventRecorder{}
			reconciler := &APIServiceReconciler{
				ReconcilerBase: outils.NewReconcilerBase(fakeClient, scheme, nil, eventRecorder, nil),
				Log:            zap.New(zap.UseDevMode(true)),
			}

			ctx := context.Background()
			req := ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name: tt.apiService.Name,
				},
			}

			_, err := reconciler.Reconcile(ctx, req)

			if (err != nil) != tt.expectError {
				t.Errorf("Reconcile() error = %v, expectError %v", err, tt.expectError)
				return
			}

			if !tt.expectError && tt.validateFunc != nil {
				updated := &apiregistrationv1.APIService{}
				err = fakeClient.Get(ctx, req.NamespacedName, updated)
				if err != nil {
					t.Fatalf("failed to get updated APIService: %v", err)
				}
				tt.validateFunc(t, updated)
			}
		})
	}
}

// Test predicate behavior for webhook configurations
func TestIsAnnotatedForSecretCAInjection_Webhooks(t *testing.T) {
	tests := []struct {
		name     string
		event    interface{}
		expected bool
	}{
		{
			name: "mutating webhook - create with annotation",
			event: event.CreateEvent{
				Object: &admissionregistrationv1.MutatingWebhookConfiguration{
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
			name: "validating webhook - create with annotation",
			event: event.CreateEvent{
				Object: &admissionregistrationv1.ValidatingWebhookConfiguration{
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
			name: "crd - create with annotation",
			event: event.CreateEvent{
				Object: &crd.CustomResourceDefinition{
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
			name: "apiservice - create with annotation",
			event: event.CreateEvent{
				Object: &apiregistrationv1.APIService{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							util.CertAnnotationSecret: "test-ns/test-secret",
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
			}

			if result != tt.expected {
				t.Errorf("IsAnnotatedForSecretCAInjection predicate = %v, want %v", result, tt.expected)
			}
		})
	}
}
