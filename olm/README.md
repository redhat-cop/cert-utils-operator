# instructions on how to manually test the olm integration

To run the test type the following

to build the catalog image

```shell
oc new-project cert-utils-operator-olm-test
oc new-build --name=olm-test --binary=true --strategy=docker
oc start-build olm-test --from-dir ./olm
```

to deploy the image:

```shell
oc apply -f ./olm/catalog-source.yaml
```

get the quay token

```shell
AUTH_TOKEN=$(curl -sH "Content-Type: application/json" -XPOST https://quay.io/cnr/api/v1/users/login -d '
{
    "user": {
        "username": "'"${QUAY_USERNAME}"'",
        "password": "'"${QUAY_PASSWORD}"'"
    }
}' | jq -r '.token')
```

validate the olm CSV

```shell
operator-courier verify olm/olm-catalog/
operator-courier verify olm/olm-catalog/ --ui_validate_io
```

go to this [site](https://operatorhub.io/preview) to visually validate the result

push the catalog to the quay application registry

```shell
operator-courier push olm/olm-catalog/ raffaelespazzoli cert-utils-operator 0.0.1 "${AUTH_TOKEN}"
```

deploy the operator source

```shell
oc apply -f ./olm/operator-source.yaml
```