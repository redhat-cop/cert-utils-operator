# Manual Tests

Deploy cert-manager:

```shell
oc create namespace cert-manager
oc label namespace cert-manager certmanager.k8s.io/disable-validation=true
oc apply --validate=false -f https://github.com/jetstack/cert-manager/releases/download/v0.8.0/cert-manager-openshift.yaml
```

Initialize the CA and certificate needed during the tests

```shell
oc new-project test-cert-utils
oc apply -f ./test/cert-manager/setup.yaml
oc apply -f ./testsample-cert.yaml
```

Test Routes

```shell
oc apply -f ./testroutes.yaml
```

Test ca-injection

```shell
oc apply -f ./test/webhookconfiguration.yaml
```
