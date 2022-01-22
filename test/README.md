# Manual Tests

Deploy cert-manager:

```shell
oc create namespace cert-manager
oc apply -f https://github.com/jetstack/cert-manager/releases/download/v1.6.1/cert-manager.yaml
oc apply -f ./test/cert-manager/setup.yaml
```

Initialize the CA and certificate needed during the tests

```shell
oc new-project test-cert-utils
oc apply -f ./test/sample-cert.yaml -n test-cert-utils
```

Test Routes

```shell
oc apply -f ./test/routes.yaml -n test-cert-utils
```

Test ca-injection

```shell
oc apply -f ./test/validatingwebhookconfiguration.yaml
oc apply -f ./test/mutatingwebhookconfiguration.yaml
oc apply -f ./test/crd.yaml
oc apply -f ./test/ca_injection_in_secret_configmap.yaml -n test-cert-utils
oc apply -f ./test/apiservice.yaml
```

Test truststore/keystore

```shell
oc annotate secret test1 cert-utils-operator.redhat-cop.io/generate-java-keystores=true --overwrite -n test-cert-utils
```
