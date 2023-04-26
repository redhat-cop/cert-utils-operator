module github.com/redhat-cop/cert-utils-operator

go 1.16

require (
	github.com/go-logr/logr v0.4.0
	github.com/grantae/certinfo v0.0.0-20170412194111-59d56a35515b
	github.com/openshift/api v3.9.0+incompatible
	github.com/pavel-v-chernykh/keystore-go v2.1.0+incompatible
	github.com/pavel-v-chernykh/keystore-go/v4 v4.2.0
	github.com/pavlo-v-chernykh/keystore-go/v4 v4.4.1 // indirect
	github.com/prometheus/client_golang v1.7.1
	github.com/redhat-cop/operator-utils v1.1.4
	github.com/scylladb/go-set v1.0.2
	github.com/stretchr/testify v1.6.1
	k8s.io/api v0.20.2
	k8s.io/apiextensions-apiserver v0.20.1
	k8s.io/apimachinery v0.20.2
	k8s.io/client-go v0.20.2
	k8s.io/kube-aggregator v0.20.1
	k8s.io/kubectl v0.20.2
	sigs.k8s.io/controller-runtime v0.8.3
)
