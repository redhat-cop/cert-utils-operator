# Operator Hub Release steps

set some environment variables used during the process

```shell
export new_version=<new-version>
export old_version=<old-version>
export quay_test_repo=<quay-test-repo>
export community_fork=<a-fork-of-community-operator>
```

## Create new CSV

I wasn't able to automate this set of steps, unfortunately.

update the [`deploy/operator.yaml`](./deploy/operator.yaml) with the image tag of the version you are about to release. Also update anything else that might have change in this release in the manifests.

If you creating the csv for the first time run the following:

```shell
operator-sdk olm-catalog gen-csv --csv-version $new_version --csv-channel alpha --default-channel
```

If you are updating run the following:

```shell
operator-sdk generate csv --csv-version $new_version --from-version $old_version --make-manifests=false
```

verify the created csv:

```shell
operator-courier --verbose verify deploy/olm-catalog/cert-utils-operator
operator-courier --verbose verify --ui_validate_io deploy/olm-catalog/cert-utils-operator
```

## Test new CSV

One new way to test is the following:

```shell
oc new-project cert-utils-operator
operator-sdk run --olm --olm-namespace openshift-operator-lifecycle-manager --operator-namespace cert-utils-operator --install-mode=OwnNamespace=cert-utils-operator --operator-version $new_version
```

Test what the operator would look like in OperatorHub, by going to this [site](https://operatorhub.io/preview) and paste the csv/

Test the operator deployment process from OperatorHub

```shell
AUTH_TOKEN=$(curl -sH "Content-Type: application/json" -XPOST https://quay.io/cnr/api/v1/users/login -d '
{
    "user": {
        "username": "'"${QUAY_USERNAME}"'",
        "password": "'"${QUAY_PASSWORD}"'"
    }
}' | jq -r '.token')
```

Push the catalog to the quay application registry (this is different than a container registry).

```shell
operator-courier push deploy/olm-catalog/cert-utils-operator $quay_test_repo cert-utils-operator-package $new_version "${AUTH_TOKEN}"
```

Deploy the operator source

```shell
envsubst < deploy/olm-catalog/operator-source.yaml | oc apply -f -
```

Now you should see the operator in the operator catalog, follow the normal installation process from here.

## Pushing the new CSV to OperatorHub

```shell
git -C /tmp clone https://github.com/operator-framework/community-operators
git -C /tmp/community-operators remote add tmp https://github.com/${community_fork}/community-operators
git -C /tmp/community-operators checkout -b cert-utils-operator-${new_version}
rm -rf /tmp/community-operators/community-operators/cert-utils-operator/*
mkdir -p /tmp/community-operators/community-operators/cert-utils-operator
cp -R deploy/olm-catalog/cert-utils-operator/* /tmp/community-operators/community-operators/cert-utils-operator
git -C /tmp/community-operators add .
git -C /tmp/community-operators commit -m "cert-utils-operator release ${new_version}" -s
# TODO push in a way that overwrites whatever exist
git -C /tmp/community-operators push tmp
# TODO create the PR only it does not exist already
# TODO automate which first time/update
# if first time
hub -C /tmp/community-operators pull-request -F ./deploy/olm-catalog/pr-message-initial-commit.md
# else
hub -C /tmp/community-operators pull-request -F ./deploy/olm-catalog/pr-message-new-version.md
```