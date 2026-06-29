package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	routev1 "github.com/openshift/api/route/v1"
	"github.com/redhat-cop/cert-utils-operator/controllers/cainjection"
	"github.com/redhat-cop/cert-utils-operator/controllers/certexpiryalert"
	"github.com/redhat-cop/cert-utils-operator/controllers/certificateinfo"
	"github.com/redhat-cop/cert-utils-operator/controllers/secrettokeystore"
	outils "github.com/redhat-cop/operator-utils/pkg/util"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	crd "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	testEnv   *envtest.Environment
	k8sClient client.Client
	ctx       context.Context
	cancel    context.CancelFunc
)

func TestMain(m *testing.M) {
	logf.SetLogger(zap.New(zap.UseDevMode(true)))

	ctx, cancel = context.WithCancel(context.TODO())

	// Use kind cluster if available, otherwise fall back to envtest
	cfg, err := ctrl.GetConfig()
	if err != nil {
		// Fallback to envtest for local development
		testEnv = &envtest.Environment{
			CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
			ErrorIfCRDPathMissing: false,
		}
		cfg, err = testEnv.Start()
		if err != nil {
			panic(err)
		}
	}

	// Setup scheme
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		panic(err)
	}
	if err := routev1.AddToScheme(scheme); err != nil {
		panic(err)
	}
	if err := admissionregistrationv1.AddToScheme(scheme); err != nil {
		panic(err)
	}
	if err := crd.AddToScheme(scheme); err != nil {
		panic(err)
	}
	if err := apiregistrationv1.AddToScheme(scheme); err != nil {
		panic(err)
	}

	// Create Kubernetes client
	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		panic(err)
	}

	// Setup controller manager
	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: "0", // Disable metrics server to avoid port conflicts
	})
	if err != nil {
		panic(err)
	}

	// Setup controllers
	if err := (&secrettokeystore.SecretToKeyStoreReconciler{
		ReconcilerBase: outils.NewReconcilerBase(k8sManager.GetClient(), k8sManager.GetScheme(), k8sManager.GetConfig(), k8sManager.GetEventRecorderFor("SecretToKeyStore"), nil),
		Log:            ctrl.Log.WithName("controllers").WithName("SecretToKeyStore"),
	}).SetupWithManager(k8sManager); err != nil {
		panic(err)
	}

	if err := (&certificateinfo.CertificateInfoReconciler{
		ReconcilerBase: outils.NewReconcilerBase(k8sManager.GetClient(), k8sManager.GetScheme(), k8sManager.GetConfig(), k8sManager.GetEventRecorderFor("CertificateInfo"), nil),
		Log:            ctrl.Log.WithName("controllers").WithName("CertificateInfo"),
	}).SetupWithManager(k8sManager); err != nil {
		panic(err)
	}

	if err := (&certexpiryalert.CertExpiryAlertReconciler{
		ReconcilerBase: outils.NewReconcilerBase(k8sManager.GetClient(), k8sManager.GetScheme(), k8sManager.GetConfig(), k8sManager.GetEventRecorderFor("CertExpiryAlert"), nil),
		Log:            ctrl.Log.WithName("controllers").WithName("CertExpiryAlert"),
	}).SetupWithManager(k8sManager); err != nil {
		panic(err)
	}

	if err := (&cainjection.ConfigmapReconciler{
		ReconcilerBase: outils.NewReconcilerBase(k8sManager.GetClient(), k8sManager.GetScheme(), k8sManager.GetConfig(), k8sManager.GetEventRecorderFor("ConfigMapCAInjection"), nil),
		Log:            ctrl.Log.WithName("controllers").WithName("ConfigMapCAInjection"),
	}).SetupWithManager(k8sManager); err != nil {
		panic(err)
	}

	if err := (&cainjection.SecretReconciler{
		ReconcilerBase: outils.NewReconcilerBase(k8sManager.GetClient(), k8sManager.GetScheme(), k8sManager.GetConfig(), k8sManager.GetEventRecorderFor("SecretCAInjection"), nil),
		Log:            ctrl.Log.WithName("controllers").WithName("SecretCAInjection"),
	}).SetupWithManager(k8sManager); err != nil {
		panic(err)
	}

	// Start the manager in a goroutine
	go func() {
		if err := k8sManager.Start(ctx); err != nil {
			panic(err)
		}
	}()

	// Wait for cache to sync
	time.Sleep(2 * time.Second)

	// Run tests
	code := m.Run()

	// Teardown
	cancel()
	if testEnv != nil {
		if err := testEnv.Stop(); err != nil {
			panic(err)
		}
	}

	os.Exit(code)
}

// Helper function to wait for a condition
func waitForCondition(t *testing.T, checkFunc func() bool, timeout time.Duration, message string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if checkFunc() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("Timeout waiting for: %s", message)
}
