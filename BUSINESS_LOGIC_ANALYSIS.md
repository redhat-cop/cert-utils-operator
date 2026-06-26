# Cert-Utils-Operator Business Logic Analysis

## Executive Summary

This document provides a comprehensive analysis of the cert-utils-operator codebase, documenting all business logic flows, controller dependencies, data transformations, and test coverage gaps. This analysis supports safe dependency upgrades and identifies areas requiring additional testing.

**Analysis Date:** 2026-06-26  
**Codebase Version:** master branch (commit 0b1fe90)

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Controller Inventory](#controller-inventory)
3. [Business Logic Flows](#business-logic-flows)
4. [Shared Utilities & Dependencies](#shared-utilities--dependencies)
5. [Data Transformations](#data-transformations)
6. [Critical Business Rules & Invariants](#critical-business-rules--invariants)
7. [Error Handling Patterns](#error-handling-patterns)
8. [Test Coverage Analysis](#test-coverage-analysis)
9. [Recommendations](#recommendations)

---

## Architecture Overview

The cert-utils-operator is a Kubernetes operator that provides certificate management utilities through 9 distinct controllers:

- **3 Certificate Transformation Controllers**: Route population, Secret-to-Keystore, ConfigMap-to-Keystore
- **2 Certificate Information Controllers**: Certificate Info display, Certificate Expiry Alerting
- **4 CA Injection Controllers**: ConfigMap, Secret, MutatingWebhook, ValidatingWebhook, CRD, APIService

All controllers follow the Kubernetes controller-runtime pattern with:
- Reconciliation loops triggered by resource changes
- Annotation-based opt-in feature activation
- Event watching with custom predicates for efficiency

**Key Dependencies:**
- `github.com/redhat-cop/operator-utils v1.1.4` - Base reconciler functionality
- `sigs.k8s.io/controller-runtime v0.8.3` - Controller framework
- `github.com/pavel-v-chernykh/keystore-go/v4` - Java keystore generation
- `github.com/prometheus/client_golang v1.7.1` - Metrics collection

---

## Controller Inventory

### 1. Route Certificate Controller
**File:** `controllers/route/route_controller.go`  
**Purpose:** Populate OpenShift Route TLS certificates from Secrets  
**Watches:** Routes (with annotations), Secrets (TLS type)  
**RBAC:** routes (get/list/watch/update/patch), secrets (get/list/watch), events (get/list/watch/create/patch)

### 2. Secret-to-Keystore Controller
**File:** `controllers/secrettokeystore/secret_to_keystore_controller.go`  
**Purpose:** Generate Java keystores/truststores from TLS Secrets  
**Watches:** Secrets (type: TLS - corev1.SecretTypeTLS)  
**RBAC:** secrets (get/list/watch/update/patch), events (get/list/watch/create/patch)

### 3. ConfigMap-to-Keystore Controller
**File:** `controllers/configmaptokeystore/configmap_to_keystore_controller.go`  
**Purpose:** Generate Java truststores from ConfigMap CA bundles  
**Watches:** ConfigMaps (with annotation)  
**RBAC:** configmaps (get/list/watch/update/patch), events (get/list/watch/create/patch)

### 4. Certificate Info Controller
**File:** `controllers/certificateinfo/certificate_info_controller.go`  
**Purpose:** Display human-readable certificate information  
**Watches:** Secrets (type: TLS - corev1.SecretTypeTLS)  
**RBAC:** secrets (get/list/watch/update/patch), events (get/list/watch/create/patch)

### 5. Certificate Expiry Alert Controller
**File:** `controllers/certexpiryalert/certexpiryalert_controller.go`  
**Purpose:** Alert on certificate expiration via Events and Prometheus metrics  
**Watches:** Secrets (type: TLS - corev1.SecretTypeTLS)  
**RBAC:** secrets (get/list/watch/update/patch), events (get/list/watch/create/patch)

### 6. ConfigMap CA Injection Controller
**File:** `controllers/cainjection/configmap_controller.go`  
**Purpose:** Inject CA bundles from Secrets into ConfigMaps  
**Watches:** ConfigMaps (with annotation), Secrets (TLS type)  
**RBAC:** configmaps (get/list/watch/update/patch), secrets (get/list/watch), events (get/list/watch/create/patch)

### 7. Secret CA Injection Controller
**File:** `controllers/cainjection/secret_controller.go`  
**Purpose:** Inject CA bundles from Secrets into other Secrets  
**Watches:** Secrets (with annotation), Secrets (TLS type source)  
**RBAC:** secrets (get/list/watch/update/patch), events (get/list/watch/create/patch)

### 8. MutatingWebhookConfiguration CA Injection Controller
**File:** `controllers/cainjection/mutatingwebhookconfiguration_controller.go`  
**Purpose:** Inject CA bundles into MutatingWebhookConfigurations  
**Watches:** MutatingWebhookConfigurations (with annotation), Secrets (TLS type)  
**RBAC:** mutatingwebhookconfigurations (get/list/watch/update/patch), secrets (get/list/watch), events (get/list/watch/create/patch)

### 9. ValidatingWebhookConfiguration CA Injection Controller
**File:** `controllers/cainjection/validatingwebhookconfiguration_controller.go`  
**Purpose:** Inject CA bundles into ValidatingWebhookConfigurations  
**Watches:** ValidatingWebhookConfigurations (with annotation), Secrets (TLS type)  
**RBAC:** validatingwebhookconfigurations (get/list/watch/update/patch), secrets (get/list/watch), events (get/list/watch/create/patch)

### 10. CustomResourceDefinition CA Injection Controller
**File:** `controllers/cainjection/customresourcedefinition_controller.go`  
**Purpose:** Inject CA bundles into CRD webhook configurations  
**Watches:** CustomResourceDefinitions (with annotation), Secrets (TLS type)  
**RBAC:** customresourcedefinitions (get/list/watch/update/patch), secrets (get/list/watch), events (get/list/watch/create/patch)

### 11. APIService CA Injection Controller
**File:** `controllers/cainjection/apiservice_controller.go`  
**Purpose:** Inject CA bundles into APIService specs  
**Watches:** APIServices (with annotation), Secrets (TLS type)  
**RBAC:** apiservices (get/list/watch/update/patch), secrets (get/list/watch), events (get/list/watch/create/patch)

---

## Business Logic Flows

### Flow 1: Route Certificate Population

**Trigger Annotations:**
- `cert-utils-operator.redhat-cop.io/certs-from-secret: "<secret-name>"`
- `cert-utils-operator.redhat-cop.io/destinationCA-from-secret: "<secret-name>"`
- `cert-utils-operator.redhat-cop.io/inject-CA: "[true|false]"` (default: true)

**Reconciliation Flow:**
```
1. Route created/updated OR referenced Secret changes
   ↓
2. Predicate filters:
   - Route has annotation AND
   - Route.Spec.TLS != nil AND
   - Route.Spec.TLS.Termination in ["edge", "reencrypt"]
   ↓
3. On annotation change or TLS field changes:
   - Fetch referenced Secret(s)
   - Populate Route.Spec.TLS fields:
     • Key ← Secret.Data["tls.key"]
     • Certificate ← Secret.Data["tls.crt"]
     • CACertificate ← Secret.Data["ca.crt"] (if inject-CA != "false")
     • DestinationCACertificate ← DestCA Secret.Data["ca.crt"]
   ↓
4. Update Route if any field changed
   ↓
5. ManageSuccess/ManageError (operator-utils pattern)
```

**Edge Cases:**
- Route without annotation: clears all TLS fields
- Secret not found: ManageError, logs error, returns for retry
- Non-edge/reencrypt routes: ignored even with annotation
- Empty annotation value after being set: clears TLS fields

**Data Flow Diagram:**
```
Secret (TLS type)           Secret (optional, dest CA)
  ├─ tls.key ─────────────┐             ├─ ca.crt
  ├─ tls.crt ─────────┐   │             │
  └─ ca.crt ──────┐   │   │             │
                  │   │   │             │
                  ▼   ▼   ▼             ▼
                Route.Spec.TLS
                  ├─ Key
                  ├─ Certificate
                  ├─ CACertificate
                  └─ DestinationCACertificate
```

**Watch Mechanism:**
- Custom `enqueueRequestForReferecingRoutes` handler
- On Secret change: queries all Routes in same namespace
- Enqueues Routes that reference the changed Secret
- Efficient: only reconciles affected Routes

**Critical Invariants:**
- Routes must be secure (edge or reencrypt)
- Secret must exist in same namespace as Route
- Route updates are idempotent (only updates if values differ)

---

### Flow 2: Secret-to-Java-Keystore

**Trigger Annotation:**
- `cert-utils-operator.redhat-cop.io/generate-java-keystores: "true"`

**Optional Annotations:**
- `cert-utils-operator.redhat-cop.io/java-keystore-password: "<password>"` (default: "changeme")
- `cert-utils-operator.redhat-cop.io/java-keystores-creation-timestamp: "<RFC3339>"` (auto-generated)

**Reconciliation Flow:**
```
1. Secret created/updated with annotation="true"
   ↓
2. Predicate filters:
   - Secret.Type == corev1.SecretTypeTLS AND
   - Annotation value change OR content change (tls.crt/tls.key/ca.crt)
   ↓
3. Generate Java Keystore (keystore.jks):
   a. Extract tls.key (must be PKCS#8 PEM)
   b. Parse tls.crt PEM blocks into certificate chain
   c. Get/create creation timestamp (persisted in annotation)
   d. Create PrivateKeyEntry with:
      - alias: "alias"
      - privateKey: tls.key bytes
      - certificateChain: tls.crt parsed chain
      - creationTime: from annotation
   e. Encode to JKS format with password
   ↓
4. Generate Java Truststore (truststore.jks):
   a. Parse ca.crt PEM blocks
   b. For each certificate, create TrustedCertificateEntry:
      - alias: "alias0", "alias1", ...
      - certificate: parsed cert
      - creationTime: from annotation
   c. Encode to JKS format with password
   ↓
5. Compare with existing keystores:
   - Load existing keystore.jks/truststore.jks
   - Deep comparison: aliases, certificates, private keys
   - Only update if different (avoids unnecessary updates)
   ↓
6. Update Secret.Data:
   - keystore.jks ← new keystore bytes
   - truststore.jks ← new truststore bytes
   ↓
7. If annotation="false": delete keystore.jks and truststore.jks
```

**Edge Cases:**
- Missing tls.key or tls.crt: skips keystore generation (no error)
- Missing ca.crt: skips truststore generation (no error)
- Invalid PEM format: returns error, reconcile retries
- Invalid PKCS#8 key: error returned to user
- Password change: forces keystore regeneration
- Timestamp annotation missing: generates current time and persists

**Data Transformations:**
```
PEM (tls.key) ──────┐
                    │
PEM (tls.crt) ──────┼──► Parse PEM blocks
                    │     ├─ Extract PKCS#8 private key
                    │     └─ Extract X.509 cert chain
                    ▼
               KeyStore API
                 ├─ SetPrivateKeyEntry("alias", ...)
                 └─ Store(buffer, password)
                    │
                    ▼
               Binary JKS (keystore.jks)

PEM (ca.crt) ──────► Parse PEM blocks
                     ├─ For each cert block
                     │   └─ SetTrustedCertificateEntry("aliasN", ...)
                     └─ Store(buffer, password)
                        │
                        ▼
                   Binary JKS (truststore.jks)
```

**Performance Optimization:**
- `compareKeyStoreBinary()`: Avoids unnecessary Secret updates
- Deep comparison of keystore contents before writing
- Timestamp preservation prevents keystore recreation on every reconcile

**Critical Invariants:**
- tls.key must be in PKCS#8 format (operator does not convert)
- Password applies to both keystore and truststore
- Alias names are fixed: "alias" for keystore, "alias0", "alias1"... for truststore
- Creation timestamp must be stable across reconciliations

---

### Flow 3: ConfigMap-to-Java-Truststore

**Trigger Annotation:**
- `cert-utils-operator.redhat-cop.io/generate-java-truststore: "true"`

**Optional Annotations:**
- `cert-utils-operator.redhat-cop.io/java-keystore-password: "<password>"` (default: "changeme")
- `cert-utils-operator.redhat-cop.io/source-ca-key: "<key>"` (default: "ca-bundle.crt")

**Reconciliation Flow:**
```
1. ConfigMap created/updated with annotation="true"
   ↓
2. Predicate filters:
   - Annotation value change OR
   - Source key content change
   ↓
3. Get source key (default: "ca-bundle.crt", override via annotation)
   ↓
4. Generate Java Truststore:
   a. Parse ConfigMap.Data[sourceKey] as PEM blocks
   b. For each certificate:
      - Create TrustedCertificateEntry
      - alias: "alias0", "alias1", "alias2"...
      - certificate: parsed X.509 cert
      - creationTime: ConfigMap.CreationTimestamp
   c. Encode to JKS with password
   ↓
5. Update ConfigMap.BinaryData:
   - truststore.jks ← JKS bytes
   ↓
6. If annotation="false": delete truststore.jks
```

**Edge Cases:**
- Source key not found: returns error
- Empty source key value: returns error
- Invalid PEM: error returned
- Password change: forces regeneration
- Custom source key allows flexibility for varied ConfigMap structures

**Data Transformation:**
```
ConfigMap.Data[source-ca-key] (PEM bundle)
   │
   ├─ Parse PEM blocks
   │   ├─ cert 1 ──► TrustedCertificateEntry (alias0)
   │   ├─ cert 2 ──► TrustedCertificateEntry (alias1)
   │   └─ cert N ──► TrustedCertificateEntry (aliasN-1)
   │
   └─ KeyStore.Store(buffer, password)
      │
      ▼
ConfigMap.BinaryData["truststore.jks"] (JKS format)
```

**Test Coverage:**
- ✅ Basic truststore generation from ca-bundle.crt
- ✅ Custom source key via annotation
- ✅ Binary equality across multiple reconciles
- ❌ Missing: Password validation tests
- ❌ Missing: Invalid PEM handling tests
- ❌ Missing: Multi-certificate bundles (tested but limited)

---

### Flow 4: Certificate Information Display

**Trigger Annotation:**
- `cert-utils-operator.redhat-cop.io/generate-cert-info: "true"`

**Reconciliation Flow:**
```
1. Secret created/updated with annotation="true"
   ↓
2. Predicate filters:
   - Secret.Type == corev1.SecretTypeTLS AND
   - Annotation value change OR
   - tls.crt or ca.crt content change
   ↓
3. Generate certificate info for tls.crt:
   a. Parse PEM blocks
   b. For each block:
      - Parse as X.509 certificate
      - Generate text representation (OpenSSL-like)
      - Concatenate to result string
   c. Store in Secret.Data["tls.crt.info"]
   ↓
4. Generate certificate info for ca.crt:
   a. Same process as tls.crt
   b. Store in Secret.Data["ca.crt.info"]
   ↓
5. If annotation="false": delete tls.crt.info and ca.crt.info
```

**Edge Cases:**
- Missing tls.crt or ca.crt: skips that entry (no error)
- Invalid certificate: logs error, skips that block
- Multi-certificate bundles: concatenates all cert info

**Data Transformation:**
```
PEM Certificate ──► x509.ParseCertificate()
                    │
                    ▼
              X.509 Certificate
                    │
                    ▼
              certinfo.CertificateText()
                    │
                    ▼
              Human-readable text
              (Subject, Issuer, Validity, etc.)
```

**Use Case:**
- Debugging: Quick view of cert details in Kubernetes console
- Auditing: Certificate properties visible without decoding
- Validation: Verify certificate matches expectations

**Critical Invariants:**
- Output format similar to `openssl x509 -text`
- Multiple certificates result in concatenated output
- Invalid certs are skipped with error log

---

### Flow 5: Certificate Expiry Alerting

**Trigger Annotation:**
- `cert-utils-operator.redhat-cop.io/generate-cert-expiry-alert: "true"`

**Optional Annotations:**
- `cert-utils-operator.redhat-cop.io/cert-expiry-check-frequency: "168h"` (7 days)
- `cert-utils-operator.redhat-cop.io/cert-soon-to-expire-check-frequency: "1h"` (1 hour)
- `cert-utils-operator.redhat-cop.io/cert-soon-to-expire-threshold: "2160h"` (90 days)

**Reconciliation Flow:**
```
1. Secret created/updated with annotation="true"
   ↓
2. Predicate filters:
   - Secret.Type == corev1.SecretTypeTLS AND
   - Annotation value change OR tls.crt content change
   ↓
3. Parse tls.crt and extract:
   - Earliest NotBefore (issue time)
   - Earliest NotAfter (expiry time)
   ↓
4. Update Prometheus metrics:
   - certutils_certificate_issue_time (Unix timestamp)
   - certutils_certificate_expiry_time (Unix timestamp)
   Labels: {name, namespace}
   ↓
5. Check expiry threshold:
   - If now + threshold > expiryTime:
     a. Emit Kubernetes Warning Event
        Message: "Certificate expiring in X days"
     b. Requeue after soon-to-expire frequency
   - Else:
     a. Requeue after normal check frequency
   ↓
6. On Secret deletion: Delete Prometheus metrics
```

**Edge Cases:**
- Multiple certs in bundle: uses earliest expiry
- Missing tls.crt: returns without error
- Parse error: logs error, skips that block
- Threshold/frequency parse errors: use defaults
- Metrics survive operator restarts (Prometheus scrapes)

**Requeue Strategy:**
```
Certificate Lifecycle:
  │
  ├─ Far from expiry (> threshold)
  │  └─ Check every 7 days (expiry-check-frequency)
  │
  └─ Soon to expire (< threshold)
     └─ Check every 1 hour (soon-to-expire-check-frequency)
        └─ Emit Warning event each check
```

**Prometheus Integration:**
```
Metrics Exposed:
  certutils_certificate_issue_time{name="...", namespace="..."}
  certutils_certificate_expiry_time{name="...", namespace="..."}

Derived Metrics (via PromQL):
  cert:validity_duration:sec = expiry_time - issue_time
  cert:time_to_expiration:sec = expiry_time - time()

Alerts (configured externally):
  - CertificateExpiringSoon (85% of validity)
  - CertificateExpiringVeryoon (95% of validity)
```

**Critical Invariants:**
- Metrics labels must be stable (name, namespace)
- Expiry time is the minimum across all certs in bundle
- Requeue frequencies are configurable per-secret
- Events are regenerated on each check when soon-to-expire

**Test Coverage Gaps:**
- ❌ No unit tests for expiry alert controller
- ❌ No tests for metric generation
- ❌ No tests for requeue logic
- ❌ No tests for event emission

---

### Flow 6: CA Injection (All Resources)

**Common Pattern** (applied to 6 resource types):

**Trigger Annotation:**
- `cert-utils-operator.redhat-cop.io/injectca-from-secret: "<namespace>/<secret-name>"`

**Supported Resources:**
1. ConfigMap → `ca.crt` key
2. Secret (TLS type) → `ca.crt` data field
3. MutatingWebhookConfiguration → `webhooks[*].clientConfig.caBundle`
4. ValidatingWebhookConfiguration → `webhooks[*].clientConfig.caBundle`
5. CustomResourceDefinition → `spec.conversion.webhook.clientConfig.caBundle` (if defined)
6. APIService → `spec.caBundle`

**Reconciliation Flow:**
```
1. Resource created/updated with annotation OR source Secret changes
   ↓
2. Predicate filters:
   - Resource has annotation OR
   - Secret with type=kubernetes.io/tls changed ca.crt field
   ↓
3. Parse annotation value:
   - Format: "namespace/secret-name"
   - Validation: must contain "/" separator
   ↓
4. Fetch source Secret:
   - Namespace from annotation
   - Name from annotation
   - Extract Secret.Data["ca.crt"]
   ↓
5. Inject CA bundle into target resource:
   - ConfigMap: Data["ca.crt"] = caBundle (as string)
   - Secret: Data["ca.crt"] = caBundle (as bytes)
   - Webhooks: webhooks[i].clientConfig.caBundle = caBundle (all webhooks)
   - CRD: spec.conversion.webhook.clientConfig.caBundle = caBundle (if webhook != nil)
   - APIService: spec.caBundle = caBundle
   ↓
6. If annotation removed or empty:
   - Delete ca.crt key (ConfigMap/Secret)
   - Set caBundle to nil (Webhooks/APIService)
   ↓
7. Update resource
```

**Edge Cases:**
- Invalid annotation format (no "/"): returns error, ManageError
- Source secret not found: returns error, reconcile retries
- Source secret missing ca.crt: injects empty bundle
- CRD without conversion webhook: no-op, no error
- Cross-namespace injection: supported (annotation specifies namespace)

**Watch Mechanism (Shared Utility):**
```go
// util.NewEnqueueRequestForReferecingObject
- Maintains dynamic client for each GVK
- On Secret change:
  1. Lists all resources of type (cluster-wide or namespace)
  2. Filters by annotation matching "namespace/secret-name"
  3. Enqueues matching resources for reconciliation
- Efficient: only reconciles resources referencing changed Secret
```

**Data Flow (Example: MutatingWebhookConfiguration):**
```
Source Secret (namespace-a/webhook-cert)
  └─ ca.crt: <PEM bundle>
         │
         │ Referenced by annotation
         ▼
MutatingWebhookConfiguration
  └─ webhooks:
      ├─ webhook-1
      │   └─ clientConfig.caBundle ← injected
      ├─ webhook-2
      │   └─ clientConfig.caBundle ← injected
      └─ webhook-N
          └─ clientConfig.caBundle ← injected
```

**Shared Utility Functions (`controllers/util/util.go`):**

| Function | Purpose |
|----------|---------|
| `ValidateSecretName(name string)` | Validates "namespace/secret-name" format |
| `ValidateConfigMapName(name string)` | Validates "namespace/configmap-name" format |
| `GetSecretCA(client, secretName, namespace)` | Fetches ca.crt from Secret |
| `NewEnqueueRequestForReferecingObject(config, gvk)` | Creates watch handler for CA injection |
| `IsAnnotatedForSecretCAInjection` (predicate) | Filters resources with annotation |
| `IsCAContentChanged` (predicate) | Filters Secrets where ca.crt changed |

**Critical Invariants:**
- Annotation format must be "namespace/secret-name"
- CA bundle is raw bytes (not base64 encoded)
- All webhooks in a configuration get the same CA bundle
- Updates are idempotent (no change if CA bundle identical)
- CRD injection only occurs if conversion webhook is configured

**Test Coverage Gaps:**
- ❌ No unit tests for any CA injection controllers
- ❌ No tests for watch mechanism (enqueueRequestForReferecingObject)
- ❌ No tests for cross-namespace injection
- ❌ No tests for annotation removal
- ❌ No tests for invalid annotation formats
- ❌ No tests for missing source secrets

---

## Shared Utilities & Dependencies

### Utility Package (`controllers/util/util.go`)

**Constants:**
```go
TLSSecret = "kubernetes.io/tls"        // Standard Kubernetes TLS secret type
AnnotationBase = "cert-utils-operator.redhat-cop.io"
Cert = "tls.crt"                       // Certificate key
Key = "tls.key"                        // Private key key
CA = "ca.crt"                          // CA bundle key
CABundle = "ca-bundle.crt"             // Alternative CA bundle key (ConfigMaps)
CertAnnotationSecret = AnnotationBase + "/injectca-from-secret"
```

**Predicates (Event Filters):**

1. **IsAnnotatedForSecretCAInjection**
   - Create: Has annotation
   - Update: Annotation value changed
   - Delete/Generic: Always false

2. **IsCAContentChanged**
   - Create: Secret type is TLS
   - Update: Secret type is TLS AND ca.crt field changed (deep equal)
   - Delete/Generic: Always false

**Validation Functions:**
- Input format: "namespace/name"
- Returns error if "/" not found
- Used by all CA injection controllers

**Reconciliation Helpers:**
- `enqueueRequestForReferecingObject`: Custom watch handler
  - Dynamically queries resources by GVK
  - Matches annotation against Secret namespace/name
  - Enqueues matching resources for reconciliation

**Critical Dependencies:**
```
controllers/util/util.go
  │
  ├─ Used by ALL CA injection controllers
  │   ├─ cainjection/configmap_controller.go
  │   ├─ cainjection/secret_controller.go
  │   ├─ cainjection/mutatingwebhookconfiguration_controller.go
  │   ├─ cainjection/validatingwebhookconfiguration_controller.go
  │   ├─ cainjection/customresourcedefinition_controller.go
  │   └─ cainjection/apiservice_controller.go
  │
  ├─ Used by route controller (constants only)
  ├─ Used by keystore controllers (constants only)
  ├─ Used by cert info controller (constants only)
  └─ Used by expiry alert controller (constants only)
```

### Operator-Utils Dependency

**Package:** `github.com/redhat-cop/operator-utils v1.1.4`

**Usage:**
- `ReconcilerBase`: Base struct for all controllers
  - Provides: GetClient(), GetRecorder(), GetRestConfig()
  - Provides: ManageSuccess(), ManageError() - standardized error handling
  - Handles: Event recording, error tracking
  - Pattern: All controllers embed `outils.ReconcilerBase`

- `NewFromManager()`: Creates ReconcilerBase from manager
  - Sets up client, scheme, recorder

**Critical for:**
- Error handling consistency
- Event recording
- Kubernetes client access
- REST config for dynamic clients

### Controller-Runtime Dependency

**Package:** `sigs.k8s.io/controller-runtime v0.8.3`

**Usage:**
- Manager setup and lifecycle
- Controller builder with predicates
- Watch sources and event handlers
- Reconcile request/result pattern
- Client interface for K8s API

**Version Upgrade Risk:**
- v0.8.3 is from 2021 (old, multiple major versions behind)
- Breaking changes likely in newer versions
- Predicate API may have changed
- Watch mechanisms may differ

### Keystore Dependencies

**Package:** `github.com/pavel-v-chernykh/keystore-go/v4 v4.2.0`

**Usage:**
- JKS (Java KeyStore) format encoding/decoding
- `keystore.New()`: Creates keystore instance
- `SetPrivateKeyEntry()`: Adds private key + cert chain
- `SetTrustedCertificateEntry()`: Adds CA certificate
- `Store()`: Encodes to JKS binary format
- `Load()`: Decodes from JKS binary

**Critical Functions:**
- `compareKeyStore()`: Deep equality check
- `compareKeyStoreBinary()`: Binary JKS comparison

**Note:** Package has both v2 and v4 in go.mod (technical debt)

### Prometheus Dependency

**Package:** `github.com/prometheus/client_golang v1.7.1`

**Usage (certexpiryalert only):**
- `prometheus.NewGaugeVec()`: Creates metric collectors
- `metrics.Registry.MustRegister()`: Registers metrics
- Metrics:
  - `certutils_certificate_issue_time`
  - `certutils_certificate_expiry_time`

**Lifecycle:**
- Metrics created at package init time
- Updated on reconcile
- Deleted on Secret deletion

---

## Data Transformations

### 1. PEM to Java Keystore (JKS)

**Input:** PEM-encoded certificates and keys  
**Output:** Binary JKS keystore

**Transformation Chain:**
```
PEM Format (ASCII)
  ├─ -----BEGIN CERTIFICATE-----
  ├─ Base64-encoded DER
  └─ -----END CERTIFICATE-----

    ↓ pem.Decode()
    
DER Format (Binary)
  └─ ASN.1 encoded X.509 certificate

    ↓ No parsing (passed as bytes to keystore lib)
    
KeyStore Entry
  ├─ PrivateKeyEntry (for tls.key + tls.crt)
  │   ├─ alias: "alias"
  │   ├─ privateKey: []byte (DER-encoded PKCS#8)
  │   ├─ certificateChain: []Certificate
  │   └─ creationTime: time.Time
  │
  └─ TrustedCertificateEntry (for ca.crt)
      ├─ alias: "alias0", "alias1", ...
      ├─ certificate: Certificate
      └─ creationTime: time.Time

    ↓ keystore.Store(buffer, password)
    
JKS Binary Format
  └─ Java-compatible binary keystore
```

**Requirements:**
- Private key MUST be PKCS#8 format
- Operator does NOT convert keys (e.g., PKCS#1 to PKCS#8)
- User must provide correct format

**Password Handling:**
- Default: "changeme" (hardcoded constant)
- Override: annotation value
- Same password for keystore and truststore
- Password stored in annotation (plaintext, visible in K8s)

### 2. PEM to Certificate Info (Text)

**Input:** PEM-encoded certificate  
**Output:** Human-readable text (OpenSSL style)

**Transformation:**
```
PEM Certificate
  ↓ pem.Decode()
DER Bytes
  ↓ x509.ParseCertificate()
*x509.Certificate struct
  ├─ Subject
  ├─ Issuer
  ├─ NotBefore / NotAfter
  ├─ KeyUsage
  ├─ ExtKeyUsage
  ├─ SubjectKeyId
  └─ ... (all X.509 fields)
  ↓ certinfo.CertificateText()
Text Format:
  Certificate:
      Data:
          Version: 3 (0x2)
          Serial Number: ...
      Signature Algorithm: ...
      Issuer: ...
      Validity:
          Not Before: ...
          Not After : ...
      Subject: ...
      ...
```

**Library:** `github.com/grantae/certinfo`  
**Format:** Similar to `openssl x509 -text -noout`

### 3. PEM to Expiry Metrics

**Input:** PEM-encoded certificate  
**Output:** Prometheus gauge values

**Transformation:**
```
PEM Certificate
  ↓ pem.Decode() + x509.ParseCertificate()
*x509.Certificate
  ├─ NotBefore ──────► Unix timestamp ──► issue_time metric
  └─ NotAfter ───────► Unix timestamp ──► expiry_time metric

Multiple Certificates:
  ├─ Issue time: max(NotBefore)  (latest issue)
  └─ Expiry time: min(NotAfter)  (earliest expiry)
```

**Metric Labels:**
- name: Secret name
- namespace: Secret namespace

**Derived Metrics (PromQL):**
```promql
cert:validity_duration:sec = 
  certutils_certificate_expiry_time - certutils_certificate_issue_time

cert:time_to_expiration:sec = 
  certutils_certificate_expiry_time - time()
```

### 4. Secret CA to Target Resource

**Input:** Secret.Data["ca.crt"] ([]byte)  
**Output:** Varies by target resource type

**No Transformation (Raw Bytes):**
- Secret → Secret: Direct copy
- Webhook configs: Direct copy
- APIService: Direct copy

**Bytes to String:**
- ConfigMap: `bytes.NewBuffer(caBundle).String()`
- Stored in ConfigMap.Data (string map)

**Important:**
- NO base64 encoding (K8s API handles that)
- NO PEM validation (trusts source Secret)
- NO certificate parsing

---

## Critical Business Rules & Invariants

### Global Invariants

1. **Annotation-Based Opt-In**
   - All features require explicit annotation
   - No automatic processing of resources
   - Annotation removal reverses the operation

2. **TLS Secret Type Enforcement**
   - Only `kubernetes.io/tls` type secrets processed
   - Other secret types ignored
   - Prevents accidental processing of unrelated secrets

3. **Idempotent Updates**
   - Controllers only update if values differ
   - Prevents update loops
   - Reduces API server load

4. **Same-Namespace Constraint (Route Controller)**
   - Route must reference Secret in same namespace
   - Cross-namespace not supported for Routes
   - Security: prevents privilege escalation

5. **Cross-Namespace Allowed (CA Injection)**
   - CA injection supports "namespace/name" format
   - Allows central CA secret distribution
   - Use case: cluster-wide CA bundles

### Controller-Specific Invariants

#### Route Controller
- Routes without TLS spec are ignored
- Only edge/reencrypt termination supported
- Passthrough routes never processed
- Empty annotation clears TLS fields

#### Keystore Controllers
- Private keys must be PKCS#8 (not validated, user responsibility)
- Password applies to both keystore and truststore
- Alias names are fixed (cannot be customized)
- Keystore password visible in annotation (security concern)
- Creation timestamp must be stable (annotation-persisted)

#### Certificate Info Controller
- Invalid certificates are skipped (logged, not failed)
- Multiple certs concatenated in output
- Output format mimics OpenSSL (user expectation)

#### Expiry Alert Controller
- Expiry time is minimum across all certs in bundle
- Metrics survive operator restarts (Prometheus scrapes)
- Events regenerated on each check (not deduplicated)
- Requeue frequency changes based on proximity to expiry

#### CA Injection Controllers
- Annotation format strictly enforced ("namespace/name")
- Empty CA bundle is valid (removes CA requirement)
- All webhooks in a configuration get same CA
- CRD injection only if conversion webhook exists

### Security Invariants

1. **No Secret Creation**
   - Operator only updates existing resources
   - Never creates new Secrets/ConfigMaps
   - Prevents unauthorized data creation

2. **RBAC Boundaries**
   - Each controller has minimal RBAC
   - No cluster-admin required
   - Namespace-scoped where possible

3. **Password Storage**
   - Keystore passwords in annotations (plaintext)
   - **Risk:** Anyone with Secret read access sees password
   - **Mitigation:** Default password "changeme" documented
   - **Recommendation:** Use RBAC to restrict annotation access

4. **CA Bundle Trust**
   - Operator trusts source Secret CA without validation
   - No certificate chain validation
   - User responsible for CA correctness

### Performance Invariants

1. **Efficient Watches**
   - Predicates filter events before reconciliation
   - Only relevant changes trigger reconcile
   - Custom handlers for cross-resource watches

2. **Keystore Comparison**
   - Deep comparison before update
   - Prevents unnecessary Secret writes
   - Reduces etcd load

3. **Requeue Strategy**
   - Expiry alerts use dynamic requeue
   - Far-from-expiry: 7 days
   - Soon-to-expire: 1 hour
   - Configurable per-secret

---

## Error Handling Patterns

### Standard Pattern (All Controllers)

**ManageError vs ManageSuccess:**
```go
// Success case
return r.ManageSuccess(context, instance)
// Returns: reconcile.Result{}, nil

// Error case
return r.ManageError(context, instance, err)
// - Records Event on resource
// - Logs error
// - Returns: reconcile.Result{}, err (controller-runtime retries)
```

**Retry Behavior:**
- Errors trigger exponential backoff retry
- Default: immediate, 5s, 10s, 20s, ...
- Max backoff: 5 minutes (controller-runtime default)

### Error Categories

#### 1. Resource Not Found
```go
if errors.IsNotFound(err) {
    return reconcile.Result{}, nil  // Don't requeue
}
```
- Occurs when resource deleted during reconcile
- Safe to ignore (no retry needed)
- Used in all controllers

#### 2. Validation Errors
```go
err = util.ValidateSecretName(secretNamespacedName)
if err != nil {
    log.Error(err, "invalid ca secret name", "secret", secretNamespacedName)
    return r.ManageError(context, instance, err)
}
```
- Invalid annotation format
- Logs error with context
- Records Event on resource
- Retries (may be transient typo fix)

#### 3. External Resource Not Found
```go
secret := &corev1.Secret{}
err = r.GetClient().Get(context, types.NamespacedName{...}, secret)
if err != nil {
    log.Error(err, "unable to find referenced secret", "secret", secretName)
    return r.ManageError(context, instance, err)
}
```
- Referenced Secret doesn't exist
- Logs error
- Retries (Secret may be created soon)
- **Risk:** Infinite retry if Secret never created

#### 4. Data Processing Errors
```go
keyStore, err := r.getKeyStoreFromSecret(instance)
if err != nil {
    log.Error(err, "unable to create keystore from secret", "secret", instance.Namespace+"/"+instance.Name)
    return reconcile.Result{}, err  // Retry
}
```
- PEM parsing failures
- Invalid certificate format
- Missing required fields
- Retries (likely won't succeed, but safe)

#### 5. Update Errors
```go
err = r.GetClient().Update(context, instance)
if err != nil {
    log.Error(err, "unable to update route", "route", instance)
    return r.ManageError(context, instance, err)
}
```
- Conflict errors (resource modified)
- API server errors
- Retries (conflict likely resolved on retry)

### Missing Error Handling

**Gaps:**
1. **No validation of PKCS#8 format** (keystore controllers)
   - Invalid key format causes error, but not user-friendly
   - Should validate and return clear message

2. **No timeout on retries**
   - Missing Secret → infinite retry
   - Should have max retry count or timeout

3. **No circuit breaker**
   - Continuous errors (e.g., bad PEM) cause continuous retries
   - Should back off permanently after N failures

4. **No error metrics**
   - No Prometheus counter for errors by type
   - Hard to monitor controller health

5. **Silent skips in some cases**
   - Certificate info: invalid certs skipped (logged but not alerted)
   - Should emit Event for user visibility

### Edge Case Handling

#### Concurrent Updates
**Scenario:** Secret updated while controller processing  
**Handling:** 
- Update conflict error
- Controller-runtime retries with fresh resource
- Eventually consistent

#### Resource Deletion During Reconcile
**Scenario:** Resource deleted after reconcile triggered  
**Handling:**
- Get returns IsNotFound error
- Controller returns without error
- No retry

#### Annotation Removal
**Scenario:** User removes annotation  
**Handling:**
- Route: Clears TLS fields
- Keystore: Deletes JKS files
- Cert info: Deletes info fields
- CA injection: Deletes CA bundles
- Expiry alert: Stops reconciling (predicate filters out)

#### Partial Data
**Scenario:** Secret has tls.crt but no tls.key  
**Handling:**
- Keystore: Skips keystore, generates truststore only
- Route: Populates certificate field only
- No error (partial operation acceptable)

#### Invalid PEM
**Scenario:** Malformed PEM block  
**Handling:**
- Parse error returned
- Logged with error
- Retry (won't succeed)
- **Missing:** User-facing Event

---

## Test Coverage Analysis

### Existing Tests

#### ConfigMap-to-Keystore Controller ✅
**File:** `controllers/configmaptokeystore/configmap_to_keystore_controller_test.go`

**Tests:**
1. `TestConfigmapControllerCreateFromConfigMap`
   - Creates truststore from ca-bundle.crt
   - Validates JKS format
   - Verifies certificate content matches

2. `TestConfigmapCustomKeyControllerCreateFromConfigMap`
   - Tests custom source key via annotation
   - Validates annotation parsing

3. `TestConfigmapControllerCreateFromConfigMapBinaryEquals`
   - Multiple reconciles produce identical binary
   - Tests idempotency

**Coverage:**
- ✅ Basic functionality
- ✅ Custom source key
- ✅ Binary stability
- ✅ JKS validation

**Gaps:**
- ❌ Password validation
- ❌ Invalid PEM handling
- ❌ Missing source key
- ❌ Annotation removal
- ❌ Multi-certificate bundles (many certs)

### Missing Tests (Critical Gaps)

#### 1. Route Controller ❌
**No tests exist**

**Needed:**
- Route certificate population from Secret
- Destination CA injection
- inject-CA annotation (true/false)
- Route without TLS spec (should ignore)
- Non-edge/reencrypt routes (should ignore)
- Secret not found error
- Annotation removal (should clear fields)
- Secret watch triggers reconcile
- Multiple Routes referencing same Secret

#### 2. Secret-to-Keystore Controller ❌
**No tests exist**

**Needed:**
- Keystore generation from tls.key + tls.crt
- Truststore generation from ca.crt
- Password annotation
- Creation timestamp persistence
- Keystore comparison (avoid unnecessary updates)
- Missing tls.key (should skip keystore)
- Missing ca.crt (should skip truststore)
- Invalid PKCS#8 key error
- Multi-cert chain in tls.crt
- Annotation removal (should delete JKS files)

#### 3. Certificate Info Controller ❌
**No tests exist**

**Needed:**
- Generate tls.crt.info
- Generate ca.crt.info
- Invalid certificate (should skip)
- Multi-cert bundle
- Annotation removal

#### 4. Certificate Expiry Alert Controller ❌
**No tests exist**

**Needed:**
- Prometheus metric generation
- Metric updates on cert change
- Metric deletion on Secret deletion
- Event emission (soon to expire)
- Requeue logic (normal vs soon-to-expire)
- Threshold/frequency annotation parsing
- Multi-cert bundle (earliest expiry)

#### 5. CA Injection Controllers (All 6) ❌
**No tests exist**

**Needed for each:**
- CA injection from Secret
- Annotation format validation
- Source Secret not found
- Cross-namespace injection
- Annotation removal
- Secret watch triggers reconcile
- Empty CA bundle

**Resource-Specific:**
- ConfigMap: String conversion
- Secret: Bytes handling
- MutatingWebhook: All webhooks updated
- ValidatingWebhook: All webhooks updated
- CRD: Only if conversion webhook exists
- APIService: Spec.CABundle field

#### 6. Utility Functions ❌
**No tests exist**

**Needed:**
- ValidateSecretName (valid/invalid formats)
- ValidateConfigMapName (valid/invalid formats)
- GetSecretCA (found/not found/missing ca.crt)
- IsAnnotatedForSecretCAInjection predicate
- IsCAContentChanged predicate
- enqueueRequestForReferecingObject handler

### Test Infrastructure Gaps

**Missing:**
1. **Integration Tests**
   - No end-to-end tests
   - No multi-controller interaction tests
   - No real Kubernetes cluster tests

2. **Test Fixtures**
   - No shared test certificates
   - No reusable Secret/ConfigMap factories
   - Each test would recreate fixtures

3. **Mocking Strategy**
   - Uses fake client (good)
   - No mock for external dependencies
   - No time mocking (for expiry tests)

4. **Test Coverage Metrics**
   - No coverage tracking in CI
   - Unknown actual coverage percentage
   - No coverage regression detection

### Recommended Test Strategy

#### Phase 1: Unit Tests (Critical Path)
**Priority:** HIGH  
**Effort:** Medium

Focus on business logic, no K8s cluster required:

1. **Keystore Transformations**
   - PEM → JKS conversion
   - Password handling
   - Multi-cert handling
   - Error cases (invalid PEM, wrong key format)

2. **CA Injection Logic**
   - Annotation parsing
   - CA extraction
   - Resource updates

3. **Certificate Parsing**
   - PEM parsing
   - Expiry calculation
   - Info generation

**Framework:** Standard Go testing + testify/assert  
**Fixtures:** `test/fixtures/` directory with sample certs

#### Phase 2: Controller Tests (Reconciliation)
**Priority:** HIGH  
**Effort:** Medium-High

Focus on reconcile logic using fake client:

1. **Each Controller**
   - Happy path (resource with annotation)
   - Missing resources
   - Invalid data
   - Annotation removal
   - Update idempotency

**Framework:** controller-runtime fake client  
**Pattern:** Follow `configmap_to_keystore_controller_test.go`

#### Phase 3: Integration Tests
**Priority:** MEDIUM  
**Effort:** High

Focus on multi-controller interactions:

1. **End-to-End Scenarios**
   - Secret created → Route populated
   - Secret updated → Route updated
   - Secret deleted → Route cleared

2. **Watch Mechanism**
   - Secret change triggers reconcile
   - Multiple resources reconciled

**Framework:** envtest (controller-runtime)  
**Requires:** Real API server simulation

#### Phase 4: E2E Tests
**Priority:** LOW  
**Effort:** Very High

Focus on real cluster behavior:

1. **Operator Deployment**
   - Install operator
   - Create test resources
   - Verify expected state

**Framework:** Ginkgo/Gomega or custom  
**Requires:** Real or kind cluster

### Test Data Requirements

**Needed Fixtures:**

1. **Valid Certificates**
   - Self-signed CA
   - Server certificate (signed by CA)
   - Client certificate (signed by CA)
   - Multi-cert chain
   - Expired certificate
   - Soon-to-expire certificate

2. **Invalid Data**
   - Malformed PEM
   - Non-PKCS#8 key
   - Mismatched key/cert
   - Empty data

3. **Secrets**
   - Valid TLS secret
   - Secret with only tls.crt
   - Secret with only ca.crt
   - Non-TLS secret

4. **Routes**
   - Edge termination
   - Reencrypt termination
   - Passthrough termination (should ignore)
   - No TLS (should ignore)

**Generation Script:**
```bash
# test/fixtures/generate-certs.sh
openssl genrsa -out ca.key 2048
openssl req -new -x509 -key ca.key -out ca.crt -days 3650 -subj "/CN=Test CA"
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=test.example.com"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -out server.crt -days 365
openssl pkcs8 -topk8 -inform PEM -outform PEM -in server.key -out server-pkcs8.key -nocrypt
```

---

## Recommendations

### Immediate Actions (Pre-Upgrade)

#### 1. Implement Critical Unit Tests
**Priority:** CRITICAL  
**Before:** Any dependency upgrades

**Minimum Test Suite:**
- Secret-to-Keystore: Keystore generation, password handling
- ConfigMap-to-Keystore: Multi-cert bundles, error cases
- Route Controller: Basic population, annotation removal
- CA Injection: At least one controller (ConfigMap as template)

**Rationale:**
- Provides safety net for upgrades
- Documents expected behavior
- Catches regressions early

**Effort:** 2-3 days  
**Files to Create:**
- `controllers/route/route_controller_test.go`
- `controllers/secrettokeystore/secret_to_keystore_controller_test.go`
- `controllers/cainjection/configmap_controller_test.go`
- `test/fixtures/` (certificates and test data)

#### 2. Add Integration Test Framework
**Priority:** HIGH  
**Before:** controller-runtime upgrade

**Setup envtest:**
```go
// controllers/suite_test.go
var _ = BeforeSuite(func() {
    testEnv = &envtest.Environment{
        CRDDirectoryPaths: []string{filepath.Join("..", "config", "crd", "bases")},
    }
    cfg, err := testEnv.Start()
    // ...
})
```

**Rationale:**
- Tests controller-runtime integration
- Validates watch mechanisms
- Catches API changes

**Effort:** 3-4 days

#### 3. Document PKCS#8 Requirement
**Priority:** MEDIUM  
**Before:** User-facing issues

**Add to README.md:**
```markdown
## Important: Private Key Format

The Secret-to-Keystore feature requires private keys in PKCS#8 format.
If your key is in PKCS#1 format (begins with "BEGIN RSA PRIVATE KEY"), convert it:

openssl pkcs8 -topk8 -inform PEM -outform PEM -in key.pem -out key-pkcs8.pem -nocrypt
```

**Rationale:**
- Current error messages unclear
- Users may provide wrong format
- Prevents support issues

**Effort:** 1 hour

#### 4. Add Error Metrics
**Priority:** MEDIUM  
**For:** Operational visibility

**Add Prometheus counters:**
```go
var (
    reconcileErrors = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Subsystem: "certutils",
            Name:      "reconcile_errors_total",
            Help:      "Total number of reconciliation errors",
        },
        []string{"controller", "error_type"},
    )
)
```

**Rationale:**
- Monitor controller health
- Alert on error spikes
- Debug production issues

**Effort:** 2-3 days (all controllers)

### Dependency Upgrade Strategy

#### Phase 1: Patch Upgrades (Low Risk)
**Target:** Same minor version, latest patch

1. `github.com/prometheus/client_golang v1.7.1 → v1.7.x` (latest patch)
2. `github.com/redhat-cop/operator-utils v1.1.4 → v1.1.x`

**Process:**
1. Update go.mod
2. Run existing tests (configmap-to-keystore)
3. Manual smoke test
4. Deploy to dev cluster

**Risk:** Very Low  
**Effort:** 1 day

#### Phase 2: Minor Upgrades (Medium Risk)
**Target:** Same major version, newer minor

1. `github.com/prometheus/client_golang v1.7.x → v1.19.x` (latest v1)
2. Check for deprecations in release notes
3. Update code if needed

**Process:**
1. Review release notes for breaking changes
2. Update go.mod
3. Run ALL tests (after Phase 1 tests added)
4. Check for deprecation warnings
5. Integration test in dev cluster
6. Staging deployment

**Risk:** Medium  
**Effort:** 3-5 days

#### Phase 3: Controller-Runtime Upgrade (High Risk)
**Target:** `v0.8.3 → v0.18.x` (latest stable)

**Known Breaking Changes:**
- Predicate API may differ
- Watch API may differ
- Client interface changes
- Scheme registration changes

**Process:**
1. **DON'T** do this until Phase 1 (tests) complete
2. Create feature branch
3. Update go.mod
4. Fix compilation errors
5. Review controller-runtime migration guide
6. Update all controllers
7. Run full test suite
8. Integration test
9. Staging deployment (extensive testing)
10. Gradual production rollout

**Risk:** HIGH  
**Effort:** 2-3 weeks

**Fallback Plan:**
- Keep old version in separate branch
- Ability to rollback
- Feature flag for new version

#### Phase 4: Keystore Library (Medium Risk)
**Current:** Mixed v2 and v4 (technical debt)  
**Target:** Consolidate on v4

**Process:**
1. Remove v2 dependency from go.mod
2. Verify all imports use v4
3. Test keystore generation
4. Test keystore comparison
5. Verify binary compatibility with existing keystores

**Risk:** Medium (data format compatibility)  
**Effort:** 2-3 days

**Testing:**
- Generate keystore with old code
- Read with new code
- Verify identical
- Vice versa

### Code Quality Improvements

#### 1. Refactor Shared Logic
**Current:** Duplicate code across CA injection controllers

**Recommendation:**
Create shared reconciler in `controllers/cainjection/shared.go`:
```go
func InjectCABundle(ctx context.Context, client client.Client, 
                    resource metav1.Object, 
                    setter func([]byte)) error {
    // Common logic:
    // - Parse annotation
    // - Validate format
    // - Fetch secret
    // - Call setter with CA bundle
}
```

**Benefits:**
- Reduce code duplication
- Single place for fixes
- Easier testing

**Effort:** 2-3 days

#### 2. Add Validation Helpers
**Current:** Inline validation, inconsistent error messages

**Recommendation:**
Create `controllers/util/validation.go`:
```go
func ValidatePKCS8Key(key []byte) error
func ValidatePEMCertificate(cert []byte) error
func ValidateAnnotationFormat(annotation string) error
```

**Benefits:**
- Consistent error messages
- Testable validation
- Reusable across controllers

**Effort:** 1-2 days

#### 3. Improve Error Messages
**Current:** Generic errors, hard to debug

**Recommendation:**
Add context to all errors:
```go
return fmt.Errorf("failed to parse certificate in secret %s/%s: %w", 
                  secret.Namespace, secret.Name, err)
```

**Benefits:**
- Faster debugging
- Better user experience
- Easier support

**Effort:** 1 day (across all controllers)

#### 4. Add Keystore Password Validation
**Current:** Any password accepted, including empty

**Recommendation:**
```go
func validatePassword(password string) error {
    if len(password) < 6 {
        return fmt.Errorf("password must be at least 6 characters")
    }
    return nil
}
```

**Benefits:**
- Prevent weak passwords
- Clear error message
- Security improvement

**Effort:** 0.5 days

### Security Enhancements

#### 1. Keystore Password Security
**Current Issue:** Passwords stored in annotations (plaintext, visible to anyone with Secret read access)

**Options:**

**Option A:** Reference separate Secret for password
```yaml
annotations:
  cert-utils-operator.redhat-cop.io/java-keystore-password-secret: "keystore-password"
```
- Fetch password from referenced Secret
- Allows proper RBAC on password
- **Breaking change**

**Option B:** Document security implications
```markdown
## Security Note
Keystore passwords are stored in Secret annotations and are visible to anyone
with Secret read access. Recommended approaches:
1. Use RBAC to restrict Secret access
2. Use default password "changeme" for non-sensitive environments
3. Rotate passwords regularly
```
- No code change
- Educates users
- Not a real fix

**Recommendation:** Option B short-term, Option A long-term (v2.0)

#### 2. CA Bundle Validation
**Current:** No validation of CA bundle contents

**Recommendation:**
```go
func validateCABundle(caBundle []byte) error {
    // Parse as PEM
    // Verify it's a certificate
    // Check it's a CA (BasicConstraints)
    return nil
}
```

**Benefits:**
- Catch invalid CA bundles early
- Prevent injection of non-CA certs
- Better error messages

**Risk:** May break existing users with non-standard CAs  
**Effort:** 1-2 days

#### 3. RBAC Least Privilege
**Current:** Some controllers have broader permissions than needed

**Audit Needed:**
- Review each controller's actual API usage
- Reduce RBAC where possible
- Document why each permission needed

**Effort:** 1-2 days

### Operational Improvements

#### 1. Add Health Checks
**Current:** Basic liveness/readiness (just Ping)

**Recommendation:**
Add controller-specific health:
```go
func (r *SecretToKeyStoreReconciler) Health() error {
    // Check if reconciliation loop running
    // Check error rate
    // Check API connectivity
}
```

**Effort:** 2-3 days

#### 2. Add Detailed Metrics
**Current:** Only expiry metrics

**Recommendation:**
Add for all controllers:
- Reconcile duration histogram
- Reconcile count by controller
- Error count by controller and error type
- Queue depth gauge

**Effort:** 3-4 days

#### 3. Structured Logging
**Current:** Inconsistent log messages

**Recommendation:**
Standardize with structured fields:
```go
log.Info("reconciling route",
    "route", req.NamespacedName,
    "secret", secretName,
    "termination", route.Spec.TLS.Termination)
```

**Benefits:**
- Easier log parsing
- Better observability
- Consistent format

**Effort:** 2 days

### Documentation Improvements

#### 1. Architecture Diagram
**Add to README.md:**
```
┌─────────────────┐
│   TLS Secret    │
│  (kubernetes.io │
│       /tls)     │
└────────┬────────┘
         │
         ├─────────► Route Controller ────────► OpenShift Route
         │
         ├─────────► Keystore Controller ─────► Secret (+ JKS files)
         │
         ├─────────► Cert Info Controller ────► Secret (+ info fields)
         │
         ├─────────► Expiry Alert Controller ──► Events + Metrics
         │
         └─────────► CA Injection Controllers ─► Various K8s Resources
```

#### 2. Troubleshooting Guide
**Add new doc:** `docs/TROUBLESHOOTING.md`

**Include:**
- Common error messages and fixes
- How to check controller logs
- How to verify reconciliation
- How to check metrics
- Known limitations

#### 3. Migration Guide
**For future breaking changes:**
- Version-to-version migration steps
- Annotation changes
- RBAC changes
- API version upgrades

### Long-Term Enhancements

#### 1. Webhook for Validation
**Current:** Only reconcile, no admission control

**Recommendation:**
Add ValidatingWebhook for:
- Annotation format validation
- Referenced resource existence
- PKCS#8 key format validation

**Benefits:**
- Fail fast on invalid configuration
- Better UX (immediate feedback)
- Reduce reconcile errors

**Effort:** 1-2 weeks

#### 2. Status Conditions
**Current:** No status on managed resources

**Recommendation:**
Add Status subresource to track:
- Last reconcile time
- Reconcile success/failure
- Error message (if failed)
- Generated artifact checksums

**Benefits:**
- Visibility into operator state
- Easier debugging
- GitOps-friendly

**Effort:** 2-3 weeks

#### 3. Multi-Tenancy Improvements
**Current:** Namespace-scoped, but no tenant isolation

**Recommendation:**
- Add namespace selector (watch only certain namespaces)
- Add resource quota limits
- Add per-namespace configuration

**Effort:** 2-3 weeks

---

## Appendix: Controller Reconciliation Summary

| Controller | Trigger | Input Resources | Output Resources | Key Transformations |
|------------|---------|-----------------|------------------|---------------------|
| Route Certificate | Route annotation or Secret change | Secret (TLS) | Route (TLS fields) | PEM → Route fields |
| Secret-to-Keystore | Secret annotation or content change | Secret (TLS) | Secret (+ JKS data) | PEM → JKS binary |
| ConfigMap-to-Keystore | ConfigMap annotation or content change | ConfigMap (CA data) | ConfigMap (+ JKS binary) | PEM → JKS binary |
| Certificate Info | Secret annotation or content change | Secret (TLS) | Secret (+ info fields) | PEM → Text (OpenSSL format) |
| Cert Expiry Alert | Secret annotation or content change | Secret (TLS) | Events + Metrics | PEM → Timestamps |
| ConfigMap CA Inject | ConfigMap annotation or Secret change | Secret (TLS CA) | ConfigMap (ca.crt) | Bytes → String |
| Secret CA Inject | Secret annotation or Secret change | Secret (TLS CA) | Secret (ca.crt) | Bytes → Bytes |
| MutatingWebhook CA Inject | MWC annotation or Secret change | Secret (TLS CA) | MutatingWebhookConfig | Bytes → caBundle |
| ValidatingWebhook CA Inject | VWC annotation or Secret change | Secret (TLS CA) | ValidatingWebhookConfig | Bytes → caBundle |
| CRD CA Inject | CRD annotation or Secret change | Secret (TLS CA) | CustomResourceDefinition | Bytes → caBundle |
| APIService CA Inject | APIService annotation or Secret change | Secret (TLS CA) | APIService | Bytes → caBundle |

---

## Appendix: Annotation Reference

| Annotation | Controllers | Values | Default | Description |
|------------|-------------|--------|---------|-------------|
| `cert-utils-operator.redhat-cop.io/certs-from-secret` | Route | Secret name | - | Source secret for route certs |
| `cert-utils-operator.redhat-cop.io/destinationCA-from-secret` | Route | Secret name | - | Source secret for destination CA |
| `cert-utils-operator.redhat-cop.io/inject-CA` | Route | "true"\|"false" | "true" | Inject CA into route |
| `cert-utils-operator.redhat-cop.io/generate-java-keystores` | Secret-to-Keystore | "true"\|"false" | - | Generate JKS files |
| `cert-utils-operator.redhat-cop.io/java-keystore-password` | Secret/ConfigMap-to-Keystore | String | "changeme" | JKS password |
| `cert-utils-operator.redhat-cop.io/java-keystores-creation-timestamp` | Secret-to-Keystore | RFC3339 timestamp | Auto-generated | JKS creation time |
| `cert-utils-operator.redhat-cop.io/generate-java-truststore` | ConfigMap-to-Keystore | "true"\|"false" | - | Generate truststore |
| `cert-utils-operator.redhat-cop.io/source-ca-key` | ConfigMap-to-Keystore | Key name | "ca-bundle.crt" | Source data key |
| `cert-utils-operator.redhat-cop.io/generate-cert-info` | Certificate Info | "true"\|"false" | - | Generate cert info |
| `cert-utils-operator.redhat-cop.io/generate-cert-expiry-alert` | Cert Expiry Alert | "true"\|"false" | - | Enable expiry alerts |
| `cert-utils-operator.redhat-cop.io/cert-expiry-check-frequency` | Cert Expiry Alert | Duration | "168h" | Normal check frequency |
| `cert-utils-operator.redhat-cop.io/cert-soon-to-expire-check-frequency` | Cert Expiry Alert | Duration | "1h" | Soon-to-expire frequency |
| `cert-utils-operator.redhat-cop.io/cert-soon-to-expire-threshold` | Cert Expiry Alert | Duration | "2160h" | Expiry threshold |
| `cert-utils-operator.redhat-cop.io/injectca-from-secret` | All CA Injection | "namespace/name" | - | Source secret for CA |

---

## Appendix: File Dependency Graph

```
main.go
  ├─ controllers/route/route_controller.go
  │   └─ controllers/util/util.go (constants)
  │
  ├─ controllers/secrettokeystore/secret_to_keystore_controller.go
  │   ├─ controllers/util/util.go (constants)
  │   └─ github.com/pavel-v-chernykh/keystore-go/v4
  │
  ├─ controllers/configmaptokeystore/configmap_to_keystore_controller.go
  │   ├─ controllers/util/util.go (constants)
  │   └─ github.com/pavlo-v-chernykh/keystore-go/v4
  │
  ├─ controllers/certificateinfo/certificate_info_controller.go
  │   ├─ controllers/util/util.go (constants)
  │   └─ github.com/grantae/certinfo
  │
  ├─ controllers/certexpiryalert/certexpiryalert_controller.go
  │   ├─ controllers/util/util.go (constants)
  │   └─ github.com/prometheus/client_golang
  │
  └─ controllers/cainjection/*.go (6 controllers)
      └─ controllers/util/util.go (all functions)

controllers/util/util.go
  ├─ Validation functions
  ├─ Predicates
  ├─ Watch handlers
  └─ Helper functions

All controllers depend on:
  ├─ github.com/redhat-cop/operator-utils (ReconcilerBase)
  ├─ sigs.k8s.io/controller-runtime (framework)
  └─ k8s.io/* (API types)
```

---

## Conclusion

This analysis documents the complete business logic of the cert-utils-operator, providing a foundation for:

1. **Safe Dependency Upgrades:** Understanding critical paths and dependencies
2. **Test Development:** Identifying coverage gaps and priorities
3. **Onboarding:** Comprehensive reference for new developers
4. **Maintenance:** Clear documentation of invariants and edge cases

**Next Steps:**
1. Implement critical unit tests (Phase 1)
2. Add integration test framework
3. Begin dependency upgrades (patch → minor → major)
4. Implement security and operational improvements

**Maintenance:**
- Update this document when controllers are added/modified
- Include in code review process
- Reference in PR descriptions for complex changes
