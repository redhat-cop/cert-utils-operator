/*
Copyright 2020 Red Hat Community of Practice.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"flag"
	"os"

	"github.com/redhat-cop/cert-utils-operator/controllers/cainjection"
	"github.com/redhat-cop/cert-utils-operator/controllers/certexpiryalert"
	"github.com/redhat-cop/cert-utils-operator/controllers/certificateinfo"
	"github.com/redhat-cop/cert-utils-operator/controllers/configmaptokeystore"
	"github.com/redhat-cop/cert-utils-operator/controllers/route"
	"github.com/redhat-cop/cert-utils-operator/controllers/secrettokeystore"
	outils "github.com/redhat-cop/operator-utils/pkg/util"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	routev1 "github.com/openshift/api/route/v1"
	crd "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/discovery"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(routev1.AddToScheme(scheme))
	utilruntime.Must(crd.AddToScheme(scheme))
	utilruntime.Must(apiregistrationv1.AddToScheme(scheme))

	// +kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                     scheme,
		MetricsBindAddress:         metricsAddr,
		Port:                       9443,
		HealthProbeBindAddress:     probeAddr,
		LeaderElection:             enableLeaderElection,
		LeaderElectionID:           "b7831733.redhat.io",
		LeaderElectionResourceLock: "configmaps",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err = (&cainjection.APIServiceReconciler{
		ReconcilerBase: outils.NewFromManager(mgr, mgr.GetEventRecorderFor("apiservice_ca_injection_controller")),
		Log:            ctrl.Log.WithName("controllers").WithName("apiservice_ca_injection_controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "apiservice_ca_injection_controller")
		os.Exit(1)
	}

	if err = (&cainjection.ConfigmapReconciler{
		ReconcilerBase: outils.NewFromManager(mgr, mgr.GetEventRecorderFor("configmap_ca_injection_controller")),
		Log:            ctrl.Log.WithName("controllers").WithName("configmap_ca_injection_controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "configmap_ca_injection_controller")
		os.Exit(1)
	}

	if err = (&cainjection.CRDReconciler{
		ReconcilerBase: outils.NewFromManager(mgr, mgr.GetEventRecorderFor("crd_ca_injection_controller")),
		Log:            ctrl.Log.WithName("controllers").WithName("crd_ca_injection_controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "crd_ca_injection_controller")
		os.Exit(1)
	}

	if err = (&cainjection.MutatingWebhookConfigurationReconciler{
		ReconcilerBase: outils.NewFromManager(mgr, mgr.GetEventRecorderFor("mutating_webhook_ca_injection_controller")),
		Log:            ctrl.Log.WithName("controllers").WithName("mutating_webhook_ca_injection_controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "mutating_webhook_ca_injection_controller")
		os.Exit(1)
	}

	if err = (&cainjection.SecretReconciler{
		ReconcilerBase: outils.NewFromManager(mgr, mgr.GetEventRecorderFor("secret_ca_injection_controller")),
		Log:            ctrl.Log.WithName("controllers").WithName("secret_ca_injection_controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "secret_ca_injection_controller")
		os.Exit(1)
	}

	if err = (&cainjection.ValidatingWebhookConfigurationReconciler{
		ReconcilerBase: outils.NewFromManager(mgr, mgr.GetEventRecorderFor("validating_webhook_ca_injection_controller")),
		Log:            ctrl.Log.WithName("controllers").WithName("validating_webhook_ca_injection_controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "validating_webhook_ca_injection_controller")
		os.Exit(1)
	}

	if err = (&certexpiryalert.CertExpiryAlertReconciler{
		ReconcilerBase: outils.NewFromManager(mgr, mgr.GetEventRecorderFor("certexpiryalert_controller")),
		Log:            ctrl.Log.WithName("controllers").WithName("certexpiryalert_controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "certexpiryalert_controller")
		os.Exit(1)
	}

	if err = (&configmaptokeystore.ConfigMapToKeystoreReconciler{
		ReconcilerBase: outils.NewFromManager(mgr, mgr.GetEventRecorderFor("configmap_to_keystore_controller")),
		Log:            ctrl.Log.WithName("controllers").WithName("configmap_to_keystore_controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "configmap_to_keystore_controller")
		os.Exit(1)
	}

	if err = (&certificateinfo.CertificateInfoReconciler{
		ReconcilerBase: outils.NewFromManager(mgr, mgr.GetEventRecorderFor("certificate_info_controller")),
		Log:            ctrl.Log.WithName("controllers").WithName("certificate_info_controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "certificate_info_controller")
		os.Exit(1)
	}

	if err = (&secrettokeystore.SecretToKeyStoreReconciler{
		ReconcilerBase: outils.NewFromManager(mgr, mgr.GetEventRecorderFor("secret_to_keystore_contoller")),
		Log:            ctrl.Log.WithName("controllers").WithName("secret_to_keystore_contoller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "secret_to_keystore_contoller")
		os.Exit(1)
	}

	if res, err := outils.IsGVKDefined(schema.GroupVersionKind{
		Group:   "route.openshift.io",
		Version: "v1",
		Kind:    "Route",
	}, discovery.NewDiscoveryClientForConfigOrDie(mgr.GetConfig())); err == nil && res != nil {
		if err = (&route.RouteCertificateReconciler{
			ReconcilerBase: outils.NewFromManager(mgr, mgr.GetEventRecorderFor("route_certificate_controller")),
			Log:            ctrl.Log.WithName("controllers").WithName("route_certificate_controller"),
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "route_certificate_controller")
			os.Exit(1)
		}
	}

	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("health", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("check", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
