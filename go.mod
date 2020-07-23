module github.com/redhat-cop/cert-utils-operator

go 1.14

require (
	github.com/fsnotify/fsnotify v1.4.7
	github.com/grantae/certinfo v0.0.0-20170412194111-59d56a35515b
<<<<<<< HEAD
	github.com/openshift/api v3.9.0+incompatible
	github.com/operator-framework/operator-sdk v0.18.1
	github.com/pavel-v-chernykh/keystore-go v2.1.0+incompatible
	github.com/redhat-cop/operator-utils v0.3.3
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.5.1
	k8s.io/api v0.18.2
	k8s.io/apiextensions-apiserver v0.18.2
	k8s.io/apimachinery v0.18.2
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/kubectl v0.18.2
=======
	github.com/openshift/api v3.9.1-0.20190924102528-32369d4db2ad+incompatible
	github.com/operator-framework/operator-sdk v0.18.1
	github.com/pavel-v-chernykh/keystore-go v2.1.0+incompatible
	github.com/redhat-cop/operator-utils v0.3.1
	github.com/spf13/pflag v1.0.5
	k8s.io/api v0.18.5
	k8s.io/apiextensions-apiserver v0.18.2
	k8s.io/apimachinery v0.18.5
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/kube-aggregator v0.18.5
>>>>>>> b6b914e... work in progress
	sigs.k8s.io/controller-runtime v0.6.0
)

// Pinned to kubernetes-1.16.2
replace (
	github.com/Azure/go-autorest => github.com/Azure/go-autorest v13.3.2+incompatible // Required by OLM
	k8s.io/client-go => k8s.io/client-go v0.18.2 // Required by prometheus-operator
)
