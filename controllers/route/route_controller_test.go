package route

import (
	"testing"

	routev1 "github.com/openshift/api/route/v1"
	"github.com/redhat-cop/cert-utils-operator/controllers/util"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

func TestPopulateRouteWithCertificates(t *testing.T) {
	tests := []struct {
		name         string
		route        *routev1.Route
		secret       *corev1.Secret
		expectUpdate bool
		validateFunc func(*testing.T, *routev1.Route)
	}{
		{
			name: "edge termination - populate all fields",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						injectCAAnnotation: "true",
					},
				},
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination: "edge",
					},
				},
			},
			secret: &corev1.Secret{
				Data: map[string][]byte{
					util.Key:  []byte("test-key"),
					util.Cert: []byte("test-cert"),
					util.CA:   []byte("test-ca"),
				},
			},
			expectUpdate: true,
			validateFunc: func(t *testing.T, r *routev1.Route) {
				if r.Spec.TLS.Key != "test-key" {
					t.Errorf("Key = %v, want test-key", r.Spec.TLS.Key)
				}
				if r.Spec.TLS.Certificate != "test-cert" {
					t.Errorf("Certificate = %v, want test-cert", r.Spec.TLS.Certificate)
				}
				if r.Spec.TLS.CACertificate != "test-ca" {
					t.Errorf("CACertificate = %v, want test-ca", r.Spec.TLS.CACertificate)
				}
			},
		},
		{
			name: "reencrypt termination - populate all fields",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						injectCAAnnotation: "true",
					},
				},
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination: "reencrypt",
					},
				},
			},
			secret: &corev1.Secret{
				Data: map[string][]byte{
					util.Key:  []byte("test-key"),
					util.Cert: []byte("test-cert"),
					util.CA:   []byte("test-ca"),
				},
			},
			expectUpdate: true,
			validateFunc: func(t *testing.T, r *routev1.Route) {
				if r.Spec.TLS.Key != "test-key" {
					t.Errorf("Key = %v, want test-key", r.Spec.TLS.Key)
				}
				if r.Spec.TLS.Certificate != "test-cert" {
					t.Errorf("Certificate = %v, want test-cert", r.Spec.TLS.Certificate)
				}
				if r.Spec.TLS.CACertificate != "test-ca" {
					t.Errorf("CACertificate = %v, want test-ca", r.Spec.TLS.CACertificate)
				}
			},
		},
		{
			name: "inject-CA annotation false - skip CA injection",
			route: &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						injectCAAnnotation: "false",
					},
				},
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination: "edge",
					},
				},
			},
			secret: &corev1.Secret{
				Data: map[string][]byte{
					util.Key:  []byte("test-key"),
					util.Cert: []byte("test-cert"),
					util.CA:   []byte("test-ca"),
				},
			},
			expectUpdate: true,
			validateFunc: func(t *testing.T, r *routev1.Route) {
				if r.Spec.TLS.Key != "test-key" {
					t.Errorf("Key = %v, want test-key", r.Spec.TLS.Key)
				}
				if r.Spec.TLS.Certificate != "test-cert" {
					t.Errorf("Certificate = %v, want test-cert", r.Spec.TLS.Certificate)
				}
				if r.Spec.TLS.CACertificate != "" {
					t.Errorf("CACertificate = %v, want empty (inject-CA=false)", r.Spec.TLS.CACertificate)
				}
			},
		},
		{
			name: "passthrough termination - no updates",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination: "passthrough",
					},
				},
			},
			secret: &corev1.Secret{
				Data: map[string][]byte{
					util.Key:  []byte("test-key"),
					util.Cert: []byte("test-cert"),
					util.CA:   []byte("test-ca"),
				},
			},
			expectUpdate: false,
			validateFunc: func(t *testing.T, r *routev1.Route) {
				if r.Spec.TLS.Key != "" {
					t.Errorf("Key should be empty for passthrough, got %v", r.Spec.TLS.Key)
				}
				if r.Spec.TLS.Certificate != "" {
					t.Errorf("Certificate should be empty for passthrough, got %v", r.Spec.TLS.Certificate)
				}
			},
		},
		{
			name: "already populated with same values - no update",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination:   "edge",
						Key:           "test-key",
						Certificate:   "test-cert",
						CACertificate: "test-ca",
					},
				},
			},
			secret: &corev1.Secret{
				Data: map[string][]byte{
					util.Key:  []byte("test-key"),
					util.Cert: []byte("test-cert"),
					util.CA:   []byte("test-ca"),
				},
			},
			expectUpdate: false,
		},
		{
			name: "missing secret data fields - partial update",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination: "edge",
					},
				},
			},
			secret: &corev1.Secret{
				Data: map[string][]byte{
					util.Key: []byte("test-key"),
					// Missing Cert and CA
				},
			},
			expectUpdate: true,
			validateFunc: func(t *testing.T, r *routev1.Route) {
				if r.Spec.TLS.Key != "test-key" {
					t.Errorf("Key = %v, want test-key", r.Spec.TLS.Key)
				}
				if r.Spec.TLS.Certificate != "" {
					t.Errorf("Certificate should be empty when not in secret, got %v", r.Spec.TLS.Certificate)
				}
			},
		},
		{
			name: "empty secret data values - no update",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination: "edge",
					},
				},
			},
			secret: &corev1.Secret{
				Data: map[string][]byte{
					util.Key:  []byte(""),
					util.Cert: []byte(""),
					util.CA:   []byte(""),
				},
			},
			expectUpdate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := populateRouteWithCertifcates(tt.route, tt.secret)
			if got != tt.expectUpdate {
				t.Errorf("populateRouteWithCertifcates() = %v, want %v", got, tt.expectUpdate)
			}
			if tt.validateFunc != nil {
				tt.validateFunc(t, tt.route)
			}
		})
	}
}

func TestPopulateRouteDestCA(t *testing.T) {
	tests := []struct {
		name         string
		route        *routev1.Route
		secret       *corev1.Secret
		expectUpdate bool
		wantDestCA   string
	}{
		{
			name: "populate destination CA",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{},
				},
			},
			secret: &corev1.Secret{
				Data: map[string][]byte{
					util.CA: []byte("dest-ca-bundle"),
				},
			},
			expectUpdate: true,
			wantDestCA:   "dest-ca-bundle",
		},
		{
			name: "already populated with same value - no update",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						DestinationCACertificate: "dest-ca-bundle",
					},
				},
			},
			secret: &corev1.Secret{
				Data: map[string][]byte{
					util.CA: []byte("dest-ca-bundle"),
				},
			},
			expectUpdate: false,
			wantDestCA:   "dest-ca-bundle",
		},
		{
			name: "update with different value",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						DestinationCACertificate: "old-ca",
					},
				},
			},
			secret: &corev1.Secret{
				Data: map[string][]byte{
					util.CA: []byte("new-ca"),
				},
			},
			expectUpdate: true,
			wantDestCA:   "new-ca",
		},
		{
			name: "missing CA in secret - no update",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{},
				},
			},
			secret: &corev1.Secret{
				Data: map[string][]byte{},
			},
			expectUpdate: false,
			wantDestCA:   "",
		},
		{
			name: "empty CA value - no update",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{},
				},
			},
			secret: &corev1.Secret{
				Data: map[string][]byte{
					util.CA: []byte(""),
				},
			},
			expectUpdate: false,
			wantDestCA:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := populateRouteDestCA(tt.route, tt.secret)
			if got != tt.expectUpdate {
				t.Errorf("populateRouteDestCA() = %v, want %v", got, tt.expectUpdate)
			}
			if tt.route.Spec.TLS.DestinationCACertificate != tt.wantDestCA {
				t.Errorf("DestinationCACertificate = %v, want %v",
					tt.route.Spec.TLS.DestinationCACertificate, tt.wantDestCA)
			}
		})
	}
}

func TestIsAnnotatedAndSecureRoutePredicate(t *testing.T) {
	tests := []struct {
		name     string
		event    interface{}
		expected bool
	}{
		{
			name: "create event - edge route with cert annotation",
			event: event.CreateEvent{
				Object: &routev1.Route{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							certAnnotation: "my-secret",
						},
					},
					Spec: routev1.RouteSpec{
						TLS: &routev1.TLSConfig{
							Termination: "edge",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "create event - reencrypt route with destCA annotation",
			event: event.CreateEvent{
				Object: &routev1.Route{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							destCAAnnotation: "ca-secret",
						},
					},
					Spec: routev1.RouteSpec{
						TLS: &routev1.TLSConfig{
							Termination: "reencrypt",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "create event - passthrough route with annotation - ignored",
			event: event.CreateEvent{
				Object: &routev1.Route{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							certAnnotation: "my-secret",
						},
					},
					Spec: routev1.RouteSpec{
						TLS: &routev1.TLSConfig{
							Termination: "passthrough",
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "create event - no TLS config",
			event: event.CreateEvent{
				Object: &routev1.Route{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							certAnnotation: "my-secret",
						},
					},
					Spec: routev1.RouteSpec{
						TLS: nil,
					},
				},
			},
			expected: false,
		},
		{
			name: "create event - no annotations",
			event: event.CreateEvent{
				Object: &routev1.Route{
					ObjectMeta: metav1.ObjectMeta{},
					Spec: routev1.RouteSpec{
						TLS: &routev1.TLSConfig{
							Termination: "edge",
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "update event - annotation added",
			event: event.UpdateEvent{
				ObjectOld: &routev1.Route{
					ObjectMeta: metav1.ObjectMeta{},
					Spec: routev1.RouteSpec{
						TLS: &routev1.TLSConfig{
							Termination: "edge",
						},
					},
				},
				ObjectNew: &routev1.Route{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							certAnnotation: "my-secret",
						},
					},
					Spec: routev1.RouteSpec{
						TLS: &routev1.TLSConfig{
							Termination: "edge",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "update event - annotation changed",
			event: event.UpdateEvent{
				ObjectOld: &routev1.Route{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							certAnnotation: "old-secret",
						},
					},
					Spec: routev1.RouteSpec{
						TLS: &routev1.TLSConfig{
							Termination: "edge",
						},
					},
				},
				ObjectNew: &routev1.Route{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							certAnnotation: "new-secret",
						},
					},
					Spec: routev1.RouteSpec{
						TLS: &routev1.TLSConfig{
							Termination: "edge",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "update event - certificate content changed",
			event: event.UpdateEvent{
				ObjectOld: &routev1.Route{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							certAnnotation: "my-secret",
						},
					},
					Spec: routev1.RouteSpec{
						TLS: &routev1.TLSConfig{
							Termination: "edge",
							Certificate: "old-cert",
						},
					},
				},
				ObjectNew: &routev1.Route{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							certAnnotation: "my-secret",
						},
					},
					Spec: routev1.RouteSpec{
						TLS: &routev1.TLSConfig{
							Termination: "edge",
							Certificate: "new-cert",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "update event - destCA annotation changed",
			event: event.UpdateEvent{
				ObjectOld: &routev1.Route{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							destCAAnnotation: "old-ca-secret",
						},
					},
					Spec: routev1.RouteSpec{
						TLS: &routev1.TLSConfig{
							Termination: "reencrypt",
						},
					},
				},
				ObjectNew: &routev1.Route{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							destCAAnnotation: "new-ca-secret",
						},
					},
					Spec: routev1.RouteSpec{
						TLS: &routev1.TLSConfig{
							Termination: "reencrypt",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "update event - no relevant changes",
			event: event.UpdateEvent{
				ObjectOld: &routev1.Route{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							certAnnotation: "my-secret",
						},
					},
					Spec: routev1.RouteSpec{
						Host: "old.example.com",
						TLS: &routev1.TLSConfig{
							Termination: "edge",
							Certificate: "cert",
						},
					},
				},
				ObjectNew: &routev1.Route{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							certAnnotation: "my-secret",
						},
					},
					Spec: routev1.RouteSpec{
						Host: "new.example.com", // Host changed but certs same
						TLS: &routev1.TLSConfig{
							Termination: "edge",
							Certificate: "cert",
						},
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isAnnotatedAndSecureRoute := predicate.Funcs{
				UpdateFunc: func(e event.UpdateEvent) bool {
					newRoute, ok := e.ObjectNew.DeepCopyObject().(*routev1.Route)
					if !ok || newRoute.Spec.TLS == nil || !(newRoute.Spec.TLS.Termination == "edge" || newRoute.Spec.TLS.Termination == "reencrypt") {
						return false
					}
					oldSecret, _ := e.ObjectOld.GetAnnotations()[certAnnotation]
					newSecret, _ := e.ObjectNew.GetAnnotations()[certAnnotation]
					if oldSecret != newSecret {
						return true
					}
					oldRoute, _ := e.ObjectOld.DeepCopyObject().(*routev1.Route)
					if newSecret != "" {
						if newRoute.Spec.TLS.Key != oldRoute.Spec.TLS.Key {
							return true
						}
						if newRoute.Spec.TLS.Certificate != oldRoute.Spec.TLS.Certificate {
							return true
						}
						if newRoute.Spec.TLS.CACertificate != oldRoute.Spec.TLS.CACertificate {
							return true
						}
					}
					oldCASecret, _ := e.ObjectOld.GetAnnotations()[destCAAnnotation]
					newCASecret, _ := e.ObjectNew.GetAnnotations()[destCAAnnotation]
					if newCASecret != oldCASecret {
						return true
					}
					if newCASecret != "" {
						if newRoute.Spec.TLS.DestinationCACertificate != oldRoute.Spec.TLS.DestinationCACertificate {
							return true
						}
					}
					return false
				},
				CreateFunc: func(e event.CreateEvent) bool {
					route, ok := e.Object.DeepCopyObject().(*routev1.Route)
					if !ok || route.Spec.TLS == nil || !(route.Spec.TLS.Termination == "edge" || route.Spec.TLS.Termination == "reencrypt") {
						return false
					}
					_, ok = e.Object.GetAnnotations()[certAnnotation]
					_, okca := e.Object.GetAnnotations()[destCAAnnotation]
					return ok || okca
				},
			}

			var result bool
			switch e := tt.event.(type) {
			case event.CreateEvent:
				result = isAnnotatedAndSecureRoute.Create(e)
			case event.UpdateEvent:
				result = isAnnotatedAndSecureRoute.Update(e)
			}

			if result != tt.expected {
				t.Errorf("isAnnotatedAndSecureRoute predicate = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsContentChangedPredicate(t *testing.T) {
	tests := []struct {
		name     string
		event    interface{}
		expected bool
	}{
		{
			name: "create event - TLS secret",
			event: event.CreateEvent{
				Object: &corev1.Secret{
					Type: corev1.SecretTypeTLS,
				},
			},
			expected: true,
		},
		{
			name: "create event - non-TLS secret",
			event: event.CreateEvent{
				Object: &corev1.Secret{
					Type: corev1.SecretTypeOpaque,
				},
			},
			expected: false,
		},
		{
			name: "update event - cert changed",
			event: event.UpdateEvent{
				ObjectOld: &corev1.Secret{
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						util.Cert: []byte("old-cert"),
					},
				},
				ObjectNew: &corev1.Secret{
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						util.Cert: []byte("new-cert"),
					},
				},
			},
			expected: true,
		},
		{
			name: "update event - key changed",
			event: event.UpdateEvent{
				ObjectOld: &corev1.Secret{
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						util.Key: []byte("old-key"),
					},
				},
				ObjectNew: &corev1.Secret{
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						util.Key: []byte("new-key"),
					},
				},
			},
			expected: true,
		},
		{
			name: "update event - CA changed",
			event: event.UpdateEvent{
				ObjectOld: &corev1.Secret{
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						util.CA: []byte("old-ca"),
					},
				},
				ObjectNew: &corev1.Secret{
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						util.CA: []byte("new-ca"),
					},
				},
			},
			expected: true,
		},
		{
			name: "update event - no content changes",
			event: event.UpdateEvent{
				ObjectOld: &corev1.Secret{
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						util.Cert: []byte("same-cert"),
						util.Key:  []byte("same-key"),
						util.CA:   []byte("same-ca"),
					},
				},
				ObjectNew: &corev1.Secret{
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{
						util.Cert: []byte("same-cert"),
						util.Key:  []byte("same-key"),
						util.CA:   []byte("same-ca"),
					},
				},
			},
			expected: false,
		},
		{
			name: "update event - non-TLS secret",
			event: event.UpdateEvent{
				ObjectOld: &corev1.Secret{
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						util.Cert: []byte("old-cert"),
					},
				},
				ObjectNew: &corev1.Secret{
					Type: corev1.SecretTypeOpaque,
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
			isContentChanged := predicate.Funcs{
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
					return string(newSecret.Data[util.Cert]) != string(oldSecret.Data[util.Cert]) ||
						string(newSecret.Data[util.Key]) != string(oldSecret.Data[util.Key]) ||
						string(newSecret.Data[util.CA]) != string(oldSecret.Data[util.CA])
				},
				CreateFunc: func(e event.CreateEvent) bool {
					secret, ok := e.Object.(*corev1.Secret)
					if !ok {
						return false
					}
					if secret.Type != util.TLSSecret {
						return false
					}
					return true
				},
			}

			var result bool
			switch e := tt.event.(type) {
			case event.CreateEvent:
				result = isContentChanged.Create(e)
			case event.UpdateEvent:
				result = isContentChanged.Update(e)
			}

			if result != tt.expected {
				t.Errorf("isContentChanged predicate = %v, want %v", result, tt.expected)
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
		{"certAnnotation", certAnnotation, "cert-utils-operator.redhat-cop.io/certs-from-secret"},
		{"destCAAnnotation", destCAAnnotation, "cert-utils-operator.redhat-cop.io/destinationCA-from-secret"},
		{"injectCAAnnotation", injectCAAnnotation, "cert-utils-operator.redhat-cop.io/inject-CA"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("%s = %v, want %v", tt.name, tt.constant, tt.expected)
			}
		})
	}
}
