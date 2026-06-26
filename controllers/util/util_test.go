package util

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

func TestValidateSecretName(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantError bool
	}{
		{
			name:      "valid namespaced secret name",
			input:     "namespace/secret-name",
			wantError: false,
		},
		{
			name:      "valid with multiple slashes (uses first)",
			input:     "namespace/secret/with/slashes",
			wantError: false,
		},
		{
			name:      "invalid - no namespace separator",
			input:     "just-a-secret-name",
			wantError: true,
		},
		{
			name:      "invalid - empty string",
			input:     "",
			wantError: true,
		},
		{
			name:      "valid - minimal format",
			input:     "n/s",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSecretName(tt.input)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateSecretName() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateConfigMapName(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantError bool
	}{
		{
			name:      "valid namespaced configmap name",
			input:     "namespace/configmap-name",
			wantError: false,
		},
		{
			name:      "valid with multiple slashes (uses first)",
			input:     "namespace/configmap/with/slashes",
			wantError: false,
		},
		{
			name:      "invalid - no namespace separator",
			input:     "just-a-configmap-name",
			wantError: true,
		},
		{
			name:      "invalid - empty string",
			input:     "",
			wantError: true,
		},
		{
			name:      "valid - minimal format",
			input:     "n/c",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfigMapName(tt.input)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateConfigMapName() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestGetSecretCA(t *testing.T) {
	tests := []struct {
		name           string
		secretName     string
		secretNS       string
		existingSecret *corev1.Secret
		wantCA         []byte
		wantError      bool
	}{
		{
			name:       "successfully retrieve CA from TLS secret",
			secretName: "test-secret",
			secretNS:   "test-namespace",
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-namespace",
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					"tls.crt": []byte("cert-data"),
					"tls.key": []byte("key-data"),
					"ca.crt":  []byte("ca-bundle-data"),
				},
			},
			wantCA:    []byte("ca-bundle-data"),
			wantError: false,
		},
		{
			name:       "CA field is empty",
			secretName: "test-secret",
			secretNS:   "test-namespace",
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-namespace",
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					"tls.crt": []byte("cert-data"),
					"tls.key": []byte("key-data"),
				},
			},
			wantCA:    nil,
			wantError: false,
		},
		{
			name:           "secret does not exist",
			secretName:     "nonexistent-secret",
			secretNS:       "test-namespace",
			existingSecret: nil,
			wantCA:         []byte{},
			wantError:      true,
		},
		{
			name:       "secret in different namespace",
			secretName: "test-secret",
			secretNS:   "wrong-namespace",
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-namespace",
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					"ca.crt": []byte("ca-bundle-data"),
				},
			},
			wantCA:    []byte{},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)

			var objects []client.Object
			if tt.existingSecret != nil {
				objects = append(objects, tt.existingSecret)
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(objects...).
				Build()

			gotCA, err := GetSecretCA(fakeClient, tt.secretName, tt.secretNS)

			if (err != nil) != tt.wantError {
				t.Errorf("GetSecretCA() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if !tt.wantError && string(gotCA) != string(tt.wantCA) {
				t.Errorf("GetSecretCA() = %v, want %v", string(gotCA), string(tt.wantCA))
			}
		})
	}
}

func TestIsAnnotatedForSecretCAInjection(t *testing.T) {
	tests := []struct {
		name     string
		event    interface{}
		expected bool
	}{
		{
			name: "create event with annotation",
			event: event.CreateEvent{
				Object: &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-cm",
						Namespace: "test",
						Annotations: map[string]string{
							CertAnnotationSecret: "test-ns/test-secret",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "create event without annotation",
			event: event.CreateEvent{
				Object: &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-cm",
						Namespace: "test",
					},
				},
			},
			expected: false,
		},
		{
			name: "update event annotation added",
			event: event.UpdateEvent{
				ObjectOld: &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-cm",
						Namespace: "test",
					},
				},
				ObjectNew: &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-cm",
						Namespace: "test",
						Annotations: map[string]string{
							CertAnnotationSecret: "test-ns/test-secret",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "update event annotation changed",
			event: event.UpdateEvent{
				ObjectOld: &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-cm",
						Namespace: "test",
						Annotations: map[string]string{
							CertAnnotationSecret: "test-ns/old-secret",
						},
					},
				},
				ObjectNew: &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-cm",
						Namespace: "test",
						Annotations: map[string]string{
							CertAnnotationSecret: "test-ns/new-secret",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "update event annotation unchanged",
			event: event.UpdateEvent{
				ObjectOld: &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-cm",
						Namespace: "test",
						Annotations: map[string]string{
							CertAnnotationSecret: "test-ns/test-secret",
						},
					},
				},
				ObjectNew: &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-cm",
						Namespace: "test",
						Annotations: map[string]string{
							CertAnnotationSecret: "test-ns/test-secret",
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
				result = IsAnnotatedForSecretCAInjection.Create(e)
			case event.UpdateEvent:
				result = IsAnnotatedForSecretCAInjection.Update(e)
			}

			if result != tt.expected {
				t.Errorf("IsAnnotatedForSecretCAInjection predicate = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsCAContentChanged(t *testing.T) {
	tests := []struct {
		name     string
		event    interface{}
		expected bool
	}{
		{
			name: "create event with TLS secret",
			event: event.CreateEvent{
				Object: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-secret",
						Namespace: "test",
					},
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						"ca.crt": []byte("ca-data"),
					},
				},
			},
			expected: true,
		},
		{
			name: "create event with non-TLS secret",
			event: event.CreateEvent{
				Object: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-secret",
						Namespace: "test",
					},
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						"ca.crt": []byte("ca-data"),
					},
				},
			},
			expected: false,
		},
		{
			name: "create event with non-secret object",
			event: event.CreateEvent{
				Object: &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-cm",
						Namespace: "test",
					},
				},
			},
			expected: false,
		},
		{
			name: "update event CA content changed",
			event: event.UpdateEvent{
				ObjectOld: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-secret",
						Namespace: "test",
					},
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						"ca.crt": []byte("old-ca-data"),
					},
				},
				ObjectNew: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-secret",
						Namespace: "test",
					},
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						"ca.crt": []byte("new-ca-data"),
					},
				},
			},
			expected: true,
		},
		{
			name: "update event CA content unchanged",
			event: event.UpdateEvent{
				ObjectOld: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-secret",
						Namespace: "test",
					},
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						"ca.crt": []byte("same-ca-data"),
					},
				},
				ObjectNew: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-secret",
						Namespace: "test",
					},
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						"ca.crt": []byte("same-ca-data"),
					},
				},
			},
			expected: false,
		},
		{
			name: "update event non-TLS secret",
			event: event.UpdateEvent{
				ObjectOld: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-secret",
						Namespace: "test",
					},
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						"ca.crt": []byte("old-ca-data"),
					},
				},
				ObjectNew: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-secret",
						Namespace: "test",
					},
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						"ca.crt": []byte("new-ca-data"),
					},
				},
			},
			expected: false,
		},
		{
			name: "update event CA added",
			event: event.UpdateEvent{
				ObjectOld: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-secret",
						Namespace: "test",
					},
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{},
				},
				ObjectNew: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-secret",
						Namespace: "test",
					},
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						"ca.crt": []byte("new-ca-data"),
					},
				},
			},
			expected: true,
		},
		{
			name: "update event CA removed",
			event: event.UpdateEvent{
				ObjectOld: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-secret",
						Namespace: "test",
					},
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						"ca.crt": []byte("ca-data"),
					},
				},
				ObjectNew: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-secret",
						Namespace: "test",
					},
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{},
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
				result = IsCAContentChanged.Create(e)
			case event.UpdateEvent:
				result = IsCAContentChanged.Update(e)
			}

			if result != tt.expected {
				t.Errorf("IsCAContentChanged predicate = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestConstants(t *testing.T) {
	// Verify that constants have expected values
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"TLSSecret constant", TLSSecret, "kubernetes.io/tls"},
		{"AnnotationBase constant", AnnotationBase, "cert-utils-operator.redhat-cop.io"},
		{"Cert constant", Cert, "tls.crt"},
		{"Key constant", Key, "tls.key"},
		{"CA constant", CA, "ca.crt"},
		{"CABundle constant", CABundle, "ca-bundle.crt"},
		{"CertAnnotationSecret constant", CertAnnotationSecret, "cert-utils-operator.redhat-cop.io/injectca-from-secret"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("%s = %v, want %v", tt.name, tt.constant, tt.expected)
			}
		})
	}
}
