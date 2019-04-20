# Cert-utils-operator

[![Build Status](https://travis-ci.org/redhat-cop/cert-utils-operator.svg?branch=master)](https://travis-ci.org/redhat-cop/cert-utils-operator) [![Docker Repository on Quay](https://quay.io/repository/redhat-cop/cert-utils-operator/status "Docker Repository on Quay")](https://quay.io/repository/redhat-cop/cert-utils-operator)

Cert utils operator is a set of functionlities around certificates packaged in a Kubernetes operator.

Certificates are assumed to be avalaible in a secret of type `kubernetes.io/tls` (other types of secrets are *ignored* by this operator).
By convention this type of secrets have three optional entries:

1. `tls.key`: the private key of the certificate
2. `tls.crt`: the actual certificate
3. `ca.crt`: the CA bundle that validates the certificate

The functionalities are the following:

1. Ability to populate route certificates
2. Ability to create java keystore and truststore from the certificates
3. Ability to show info regarding the certificates
4. Ability to alert when a certificate is about to expire

All these feature are activated via opt-in annotations.

## Populating route certificates

This feature works on secure routes with `edge` or `reencrypt` type of termination.

This feature is activated with the following annotation on a route: `raffa.systems/certs-from-secret: "<secret-name>"`.

The following fields of the route will be updated:

1. `key` with the content of `tls.key`
2. `certficiate` with the content of `tls.crt`
3. `caCertificate` with the content of `ca.crt`

Only for `reencrypt` routes, if the optional annotation: `raffa.systems/replace-dest-CA: "true"` is set, then also the following field is populated:

4. `destinationCACertificate` with the content of `ca.crt`

## Creating java keystore and truststore

This feature is activated with the following annotation on a `kubernetes.io/tls` secret: `raffa.systems/generate-java-keystores: "true"`.

When this annotation is set two more entries are added to the secret:

1. `keystore.jks`: this Java keystore contains the `tls.crt` and `tls.key` certificate.
2. `trustsstore.jks`: this Java keystore contains the `ca.crt` certificate.

The default password for these keystores is `changeme`. The password can be changedby adding the following optional annotation: `raffa.systems/java-keystore-password: <password>`

## Showing info on the certificates

This feature is activated with the following annotation on a `kubernetes.io/tls` secret: `raffa.systems/generate-cert-info: "true"`.

When this annotation is set two more entries are added to the secret:

1. `tls.crt.info`: this entries contains a textual representation of `tls.crt` the certificates in a similar notation to `openssl`
2. `ca.crt.info`: this entries contains a textual representation of `ca.crt` the certificates in a similar notation to `openssl`

## Alerting when a certificate is about to expire

This feature is activated with the following annotation on a `kubernetes.io/tls` secret: `raffa.systems/generate-cert-expiry-alert: "true"`.

When this annotation is set the secret will generate a Kubernetes `Warning` Event if the certicate is about to expire.

This feature is useful when the certificates are not renewed by an automatic system.

The timing of this alerting mechanism can be controller with the following annotations:

| Annotation  | Default  | Description  |
|:-|:-:|---|
| `raffa.systems/cert-expiry-check-frequency`  | 7 days  | with which frequency should the system check is a certificate is expiring  |
| `raffa.systems/cert-soon-to-expire-check-frequency`  | 1 hour  | with which frequency should the system check is a certificate is expired, once it's close to expiring  |
| `raffa.systems/cert-soon-to-expire-threshold`  | 90 days  | what is the interval of time below which we conside rthe certificate close to expiry  |