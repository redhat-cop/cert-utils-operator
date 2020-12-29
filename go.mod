module github.com/redhat-cop/cert-utils-operator

go 1.15

require (
	github.com/go-logr/logr v0.3.0
	github.com/grantae/certinfo v0.0.0-20170412194111-59d56a35515b
	github.com/openshift/api v3.9.0+incompatible
	github.com/pavel-v-chernykh/keystore-go v2.1.0+incompatible
	github.com/redhat-cop/operator-utils v1.1.0
	github.com/stretchr/testify v1.6.1
	k8s.io/api v0.20.1
	k8s.io/apiextensions-apiserver v0.19.2
	k8s.io/apimachinery v0.20.1
	k8s.io/client-go v0.20.1
	k8s.io/kube-aggregator v0.20.1
	k8s.io/kubectl v0.20.0
	sigs.k8s.io/controller-runtime v0.7.0
)

replace github.com/redhat-cop/operator-utils => /home/rspazzol/go/src/github.com/redhat-cop/operator-utils
