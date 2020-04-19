# Manual Tests

Deploy cert-manager:

```shell
oc create namespace cert-manager
oc apply --validate=false -f https://github.com/jetstack/cert-manager/releases/download/v0.14.1/cert-manager.yaml
oc apply -f ./test/cert-manager/setup.yaml
```

Initialize the CA and certificate needed during the tests

```shell
oc new-project test-cert-utils
oc apply -f ./test/sample-cert.yaml
```

Test Routes

```shell
oc apply -f ./test/routes.yaml
```

Test ca-injection

```shell
oc apply -f ./test/webhookconfiguration.yaml
oc apply -f ./test/ca_injection_in_secret_configmap.yaml
```
