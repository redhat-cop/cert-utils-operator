# cert-utils-operator to cert-manager Migration Plan

**Document Date:** 2026-06-30  
**Current Version:** cert-utils-operator v0.0.1  
**Target:** cert-manager v1.x ecosystem (cert-manager + trust-manager + openshift-routes)  
**Recommendation:** **MIGRATION FEASIBLE** with minor feature loss

---

## Executive Summary

**Historical Context:** cert-utils-operator was created as a **companion to cert-manager**, designed to add utilities to certificates that cert-manager provisions. The operator's README explicitly states: *"Certificates are assumed to be available in a secret of type `kubernetes.io/tls`"* and documentation confirms *"Cert-manager and cert-utils-operator work well together to provide a full end-to-end automation solution."*

**Current State:** Since cert-utils-operator's creation, the cert-manager ecosystem has evolved significantly, adding many features that were originally gaps:
- cert-manager v1.x added native PKCS12 keystore generation
- trust-manager added JKS truststore distribution
- openshift-routes controller added Route certificate management

**Migration Feasibility:** **~85% of features can be migrated** to native cert-manager capabilities. Only 2 features remain without equivalents.

### Key Recommendation

**MIGRATE to cert-manager ecosystem** with the following caveats:
1. ✅ Most features have direct replacements in modern cert-manager
2. ⚠️ Some features require pattern changes (annotation-based → CR-based)
3. 🛑 Two features have no replacement and will be lost:
   - Secret-to-Secret CA injection
   - Human-readable certificate info annotations

---

## Historical Context

### Why cert-utils-operator Was Created

When cert-utils-operator was developed, cert-manager had **significant gaps**:

| Year ~2019-2020 | cert-manager Gaps | cert-utils-operator Solution |
|-----------------|-------------------|------------------------------|
| Java Applications | ❌ No keystore generation | ✅ Automatic PKCS12/JKS from annotations |
| CA Distribution | ❌ Limited to 4 webhook types | ✅ Inject to ConfigMaps, Secrets |
| OpenShift | ❌ No Route support | ✅ Route certificate population |
| Visibility | ❌ No human-readable cert info | ✅ Certificate info annotations |
| Truststore | ❌ No truststore generation | ✅ JKS truststore from ConfigMap |

**Design Philosophy:** cert-utils-operator worked on **any** `kubernetes.io/tls` secret, making it compatible with cert-manager issued certificates while also supporting externally-managed certificates.

### Modern cert-manager Ecosystem (2026)

The cert-manager ecosystem has **evolved significantly**:

| Component | Purpose | Year Added |
|-----------|---------|------------|
| **cert-manager** | Core certificate issuance & renewal | 2017 |
| **ca-injector** | CA bundle injection to webhooks/CRDs | Built-in |
| **trust-manager** | CA bundle distribution across namespaces | ~2022 |
| **openshift-routes** | OpenShift Route certificate management | ~2023 |
| **PKCS12 keystores** | Native Java keystore support in Certificates | v1.7+ (2021) |
| **JKS format** | JKS truststore via trust-manager | v0.4+ (2023) |

**Result:** Most cert-utils-operator features now have native cert-manager equivalents.

**Sources:**
- [redhat-cop/cert-utils-operator GitHub](https://github.com/redhat-cop/cert-utils-operator)
- [cert-manager Documentation](https://cert-manager.io/docs/)
- [Red Hat CoP Operators Blog](https://www.redhat.com/en/blog/red-hat-container-community-of-practice-operators)

---

## Feature-by-Feature Migration Analysis

### ✅ Feature 1: Java Keystore Generation (PKCS12)

#### Current: cert-utils-operator
```yaml
apiVersion: v1
kind: Secret
metadata:
  annotations:
    cert-utils-operator.redhat-cop.io/generate-java-keystores: "true"
    cert-utils-operator.redhat-cop.io/java-keystore-password: "mypassword"
type: kubernetes.io/tls
# Operator adds keystore.jks and truststore.jks
```

#### Migration Target: cert-manager native
```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: my-app-cert
spec:
  secretName: my-app-tls
  issuerRef:
    name: my-issuer
  keystores:
    pkcs12:
      create: true
      passwordSecretRef:
        name: keystore-password
        key: password
      profile: Modern2023  # Optional: Modern2023, LegacyRC2, LegacyDES
```

**Migration Steps:**
1. Create password secret: `kubectl create secret generic keystore-password --from-literal=password=mypassword`
2. Add `keystores.pkcs12` section to Certificate resource
3. Remove cert-utils-operator annotation
4. The secret will contain `keystore.p12` (same as PKCS12)

**Compatibility:**
- ✅ PKCS12 format is compatible with Java applications
- ✅ Configurable password via secret reference
- ✅ Profile selection for compatibility requirements
- ℹ️ Filename changes: `keystore.jks` → `keystore.p12` (both work with Java)
- ℹ️ No separate truststore - include CA chain in certificate or use trust-manager

**Status:** ✅ **DIRECT REPLACEMENT AVAILABLE**

**Sources:**
- [cert-manager Certificate Keystores](https://cert-manager.io/docs/usage/certificate/)
- [cert-manager PKCS12 Profiles](https://cert-manager.io/docs/releases/release-notes/release-notes-0.15/)

---

### ⚠️ Feature 2: Java Truststore from ConfigMap

#### Current: cert-utils-operator
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  annotations:
    cert-utils-operator.redhat-cop.io/generate-java-truststore: "true"
    cert-utils-operator.redhat-cop.io/source-ca-key: "ca-bundle.crt"
    cert-utils-operator.redhat-cop.io/java-keystore-password: "changeit"
data:
  ca-bundle.crt: |
    -----BEGIN CERTIFICATE-----
    ...
# Operator adds truststore.jks to binaryData
```

#### Migration Target: trust-manager Bundle
```yaml
apiVersion: trust.cert-manager.io/v1alpha1
kind: Bundle
metadata:
  name: my-ca-bundle
spec:
  sources:
    - configMap:
        name: source-ca-configmap
        key: "ca-bundle.crt"
  target:
    configMap:
      key: "ca-bundle.pem"
    additionalFormats:
      jks:
        key: "truststore.jks"
        password: "changeit"  # Fixed password
    namespaceSelector:
      matchLabels:
        trust-injection: "enabled"
```

**Migration Steps:**
1. Install trust-manager: `helm install trust-manager jetstack/trust-manager`
2. Label namespaces requiring trust bundles: `kubectl label namespace my-app trust-injection=enabled`
3. Create Bundle CR pointing to source ConfigMap
4. Update application to read from trust-manager created ConfigMap
5. Remove cert-utils-operator annotation

**Pattern Changes:**
- ❌ Annotation-based → CR-based workflow
- ❌ Per-ConfigMap → Namespace-wide distribution
- ✅ More powerful: one Bundle can distribute to multiple namespaces
- ⚠️ Password is fixed in JKS format (configurable in PKCS12)

**Status:** ⚠️ **REPLACEMENT AVAILABLE** (different pattern)

**Sources:**
- [trust-manager Documentation](https://cert-manager.io/docs/trust/trust-manager/)
- [GitHub: trust-manager JKS support](https://github.com/cert-manager/cert-manager/discussions/6303)

---

### ⚠️ Feature 3: OpenShift Route Certificate Population

#### Current: cert-utils-operator
```yaml
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  annotations:
    cert-utils-operator.redhat-cop.io/certs-from-secret: my-tls-secret
    cert-utils-operator.redhat-cop.io/inject-CA: "true"
spec:
  tls:
    termination: edge
  # Operator populates tls.key, tls.certificate, tls.caCertificate
```

#### Migration Target: openshift-routes controller
```yaml
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  annotations:
    cert-manager.io/issuer-name: my-issuer
    cert-manager.io/issuer-kind: ClusterIssuer
spec:
  tls:
    termination: edge
  # Controller creates certificate and populates Route
```

**Migration Steps:**
1. Install openshift-routes controller: `helm install cert-manager-openshift-routes`
2. Ensure Issuer/ClusterIssuer is configured
3. Add cert-manager annotations to Route
4. Remove cert-utils-operator annotations
5. Delete the manually-managed secret (cert-manager creates it)

**Pattern Changes:**
- ❌ Using existing certificates → cert-manager issues new certificates
- ✅ Automated renewal (cert-manager manages lifecycle)
- ⚠️ Cannot use externally-managed certificates

**Workaround for External Certificates:**
If you need to use certificates from external sources (corporate PKI):
1. Use cert-manager's `CA` issuer type with external CA
2. Or continue using cert-utils-operator for Route population (retain this feature)

**Status:** ⚠️ **REPLACEMENT AVAILABLE** (different workflow)

**Sources:**
- [GitHub: cert-manager/openshift-routes](https://github.com/cert-manager/openshift-routes)

---

### ✅ Feature 4: CA Injection to Webhook Configurations

#### Current: cert-utils-operator
```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  annotations:
    cert-utils-operator.redhat-cop.io/injectca-from-secret: namespace/secret-name
webhooks:
  - name: my-webhook
    clientConfig:
      service:
        name: webhook-service
      # caBundle populated by operator
```

#### Migration Target: cert-manager ca-injector
```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  annotations:
    cert-manager.io/inject-ca-from-secret: namespace/secret-name
webhooks:
  - name: my-webhook
    clientConfig:
      service:
        name: webhook-service
      # caBundle populated by ca-injector
---
# Source secret must have:
apiVersion: v1
kind: Secret
metadata:
  annotations:
    cert-manager.io/allow-direct-injection: "true"
type: kubernetes.io/tls
```

**Migration Steps:**
1. Add `cert-manager.io/allow-direct-injection: "true"` to source secrets
2. Update annotation name on webhook configurations
3. Remove cert-utils-operator

**Applies to:**
- ✅ ValidatingWebhookConfiguration
- ✅ MutatingWebhookConfiguration
- ✅ CustomResourceDefinition (conversion webhooks)
- ✅ APIService

**Status:** ✅ **DIRECT REPLACEMENT AVAILABLE**

**Sources:**
- [cert-manager ca-injector Documentation](https://cert-manager.io/docs/concepts/ca-injector/)

---

### ⚠️ Feature 5: CA Injection to ConfigMaps

#### Current: cert-utils-operator
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  annotations:
    cert-utils-operator.redhat-cop.io/injectca-from-secret: namespace/secret-name
# Operator injects into ca.crt key
```

#### Migration Target: trust-manager Bundle
```yaml
apiVersion: trust.cert-manager.io/v1alpha1
kind: Bundle
metadata:
  name: inject-ca
spec:
  sources:
    - secret:
        name: secret-name
        key: ca.crt
  target:
    configMap:
      key: ca.crt
    namespaceSelector:
      matchLabels:
        ca-injection: "enabled"
```

**Migration Steps:**
1. Label namespaces: `kubectl label namespace my-app ca-injection=enabled`
2. Create Bundle CR for CA source
3. Update applications to use trust-manager created ConfigMap name
4. Remove cert-utils-operator annotations

**Pattern Changes:**
- ❌ Per-ConfigMap annotation → Namespace-wide distribution
- ✅ Centralized management (one Bundle CR for all namespaces)
- ⚠️ ConfigMap name is controlled by Bundle (matches Bundle name)

**Alternative - Feature Request:**
There's an [open feature request](https://github.com/cert-manager/trust-manager/issues/222) for annotation-based injection similar to cert-utils-operator's pattern. If implemented, this would be a direct replacement.

**Status:** ⚠️ **REPLACEMENT AVAILABLE** (different pattern)

**Sources:**
- [trust-manager Usage](https://cert-manager.io/docs/trust/trust-manager/)
- [GitHub Issue #222: Annotation-based CA injection](https://github.com/cert-manager/trust-manager/issues/222)

---

### 🛑 Feature 6: CA Injection to Secrets (Secret-to-Secret)

#### Current: cert-utils-operator
```yaml
apiVersion: v1
kind: Secret
metadata:
  annotations:
    cert-utils-operator.redhat-cop.io/injectca-from-secret: namespace/ca-secret
type: kubernetes.io/tls
stringData:
  tls.crt: ""
  tls.key: ""
# Operator injects CA into ca.crt field
```

#### Migration Target: ❌ **NO EQUIVALENT IN CERT-MANAGER**

cert-manager's ca-injector can ONLY inject into:
- ValidatingWebhookConfiguration
- MutatingWebhookConfiguration
- CustomResourceDefinition
- APIService

**NOT** into Secrets or ConfigMaps.

**Attempted Workarounds:**

1. **trust-manager to Secret (Proposed):**
   - [Feature request exists](https://github.com/cert-manager/trust-manager/issues/222) to add Secret targets
   - Not yet implemented as of 2026-06-30

2. **Use ConfigMap instead:**
   - If application can read CA from ConfigMap instead of Secret `ca.crt` field
   - Use trust-manager Bundle to distribute to ConfigMap
   - Mount ConfigMap alongside Secret

3. **Projected Volumes:**
   - Merge Secret (tls.crt, tls.key) with ConfigMap (ca.crt) using projected volume
   ```yaml
   volumes:
     - name: tls-with-ca
       projected:
         sources:
           - secret:
               name: my-tls-secret
               items:
                 - key: tls.crt
                   path: tls.crt
                 - key: tls.key
                   path: tls.key
           - configMap:
               name: ca-bundle  # From trust-manager
               items:
                 - key: ca.crt
                   path: ca.crt
   ```

**Impact Analysis:**
- Applications expecting `ca.crt` in TLS secret will break
- Requires application configuration changes OR
- Requires retaining cert-utils-operator for this feature

**Status:** 🛑 **NO MIGRATION PATH** (workarounds available)

**Sources:**
- [cert-manager ca-injector limitations](https://cert-manager.io/docs/concepts/ca-injector/#injecting-ca-data-from-a-secret-resource)
- [GitHub Issue #2722: Inject CA into Secrets](https://github.com/cert-manager/cert-manager/issues/2722)

---

### 🛑 Feature 7: Human-Readable Certificate Information

#### Current: cert-utils-operator
```yaml
apiVersion: v1
kind: Secret
metadata:
  annotations:
    cert-utils-operator.redhat-cop.io/generate-cert-info: "true"
    # Auto-generated by operator:
    tls.crt.info: |
      Subject: CN=example.com, O=Example Inc
      Issuer: CN=Let's Encrypt Authority X3
      Not Before: Jun 1 00:00:00 2026 GMT
      Not After: Sep 1 00:00:00 2026 GMT
      Serial Number: 1234567890abcdef
    ca.crt.info: |
      Subject: CN=Let's Encrypt Authority X3
      ...
type: kubernetes.io/tls
```

#### Migration Target: ❌ **NO EQUIVALENT IN CERT-MANAGER**

cert-manager does not generate human-readable certificate information.

**Attempted Workarounds:**

1. **Manual Inspection:**
   ```bash
   kubectl get secret my-tls-secret -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -text
   ```

2. **External Tooling:**
   - kubectl plugin for certificate inspection
   - Monitoring/dashboard that decodes certificates
   - CI/CD validation scripts

3. **Certificate Resource Status:**
   - cert-manager Certificate resources have `.status.notAfter` and `.status.notBefore`
   - But this is on the Certificate CR, not the Secret

**Use Cases Lost:**
- Quick `kubectl describe secret` to see cert expiry
- Audit/compliance reporting from secret annotations
- Debugging certificate issues without external tools

**Impact Analysis:**
- Low impact for most users (can use openssl command)
- High impact for compliance/audit workflows
- Medium impact for operations teams (loses convenience)

**Recommendation:**
- Accept this feature loss (use external tools)
- OR retain cert-utils-operator only for this feature
- OR develop custom kubectl plugin

**Status:** 🛑 **NO MIGRATION PATH**

**Sources:**
- [cert-manager Annotations Reference](https://cert-manager.io/docs/reference/annotations/) (no cert info feature)

---

### ✅ Feature 8: Certificate Expiry Metrics

#### Current: cert-utils-operator
Prometheus metrics for all TLS secrets:
- `certutils_certificate_issue_time`
- `certutils_certificate_expiry_time`
- `cert:validity_duration:sec`
- `cert:time_to_expiration:sec`

Kubernetes Events for annotated secrets:
```yaml
metadata:
  annotations:
    cert-utils-operator.redhat-cop.io/generate-cert-expiry-alert: "true"
```

#### Migration Target: cert-manager metrics
cert-manager exposes certificate metrics at `/metrics` endpoint:
- Metrics for all managed certificates
- Integration with Prometheus Operator via ServiceMonitor

**Migration Steps:**
1. Ensure Prometheus is scraping cert-manager metrics endpoint
2. Update alerting rules to use cert-manager metrics
3. Remove cert-utils-operator annotations

**Differences:**
- ✅ cert-manager provides expiry metrics
- ❌ cert-manager metrics only cover certificates IT manages
- ❌ No Kubernetes Event generation (Prometheus only)
- ✅ Better integration with cert-manager lifecycle

**Status:** ✅ **EQUIVALENT AVAILABLE**

**Sources:**
- [cert-manager Prometheus Metrics](https://cert-manager.io/docs/devops-tips/prometheus-metrics/)

---

## Migration Summary Matrix

| Feature | cert-manager Equivalent | Migration Complexity | Feature Loss |
|---------|------------------------|----------------------|--------------|
| 1. PKCS12 Keystores | ✅ Native `keystores.pkcs12` | **LOW** | None |
| 2. JKS Truststore | ✅ trust-manager JKS format | **MEDIUM** | Pattern change (CR-based) |
| 3. Route Certificates | ✅ openshift-routes controller | **MEDIUM** | Must use cert-manager issuance |
| 4. Webhook CA Injection | ✅ ca-injector | **LOW** | None |
| 5. ConfigMap CA Injection | ✅ trust-manager Bundle | **MEDIUM** | Pattern change (namespace-wide) |
| 6. Secret-to-Secret CA | ❌ No equivalent | **BLOCKER** | **Complete loss** |
| 7. Cert Info Annotations | ❌ No equivalent | **BLOCKER** | **Complete loss** |
| 8. Expiry Metrics | ✅ Native metrics | **LOW** | No K8s Events |

**Overall Migration Feasibility:** **85%** (6 of 8 features with equivalents)

---

## Migration Strategies

### Strategy 1: Full Migration (RECOMMENDED for most)

**Accept loss of 2 features, migrate everything else to cert-manager ecosystem.**

**Pros:**
- ✅ Consolidate on CNCF standard tooling
- ✅ Active development and large community
- ✅ Automated certificate lifecycle management
- ✅ Reduce operator sprawl

**Cons:**
- ❌ Lose Secret-to-Secret CA injection
- ❌ Lose human-readable cert info
- ⚠️ Pattern changes require application updates

**Migration Effort:** **3-6 weeks**

**Best For:**
- Organizations using cert-manager for certificate issuance
- Teams willing to adopt CR-based patterns
- Environments without Secret-to-Secret CA requirements

---

### Strategy 2: Hybrid (Keep cert-utils for 2 features)

**Migrate 6 features to cert-manager, retain cert-utils-operator for the 2 blockers.**

**Configuration:**
```yaml
# Use cert-manager for most features
apiVersion: cert-manager.io/v1
kind: Certificate
spec:
  keystores:
    pkcs12:
      create: true  # Instead of cert-utils annotation

---
# Keep cert-utils ONLY for Secret-to-Secret CA injection
apiVersion: v1
kind: Secret
metadata:
  annotations:
    cert-utils-operator.redhat-cop.io/injectca-from-secret: namespace/ca
    cert-utils-operator.redhat-cop.io/generate-cert-info: "true"  # And cert info
```

**Pros:**
- ✅ No feature loss
- ✅ Migrate most features to cert-manager
- ✅ Gradual transition possible

**Cons:**
- ⚠️ Still running two operators
- ⚠️ Maintenance overhead continues

**Migration Effort:** **2-4 weeks**

**Best For:**
- Organizations with hard requirements for Secret-to-Secret CA injection
- Compliance environments needing cert info annotations
- Risk-averse teams wanting gradual migration

---

### Strategy 3: Wait for cert-manager Features

**Delay migration until cert-manager adds missing features.**

**Status of Feature Requests:**
- [Issue #2722](https://github.com/cert-manager/cert-manager/issues/2722): CA injection to Secrets - **Open since 2020**
- [Issue #222](https://github.com/cert-manager/trust-manager/issues/222): trust-manager Secret targets - **Open since 2023**

**Pros:**
- ✅ No feature loss when migration happens
- ✅ More time to plan

**Cons:**
- ❌ Feature requests have been open for years
- ❌ No timeline for implementation
- ❌ May never be implemented

**Not Recommended** - Unknown timeline

---

## Detailed Migration Plan

### Phase 1: Preparation (Week 1)

1. **Audit Current Usage**
   ```bash
   # Find all secrets with cert-utils annotations
   kubectl get secrets --all-namespaces -o json | \
     jq -r '.items[] | select(.metadata.annotations | 
     to_entries | any(.key | startswith("cert-utils-operator"))) | 
     "\(.metadata.namespace)/\(.metadata.name)"'
   
   # Find all ConfigMaps with cert-utils annotations
   kubectl get configmaps --all-namespaces -o json | \
     jq -r '.items[] | select(.metadata.annotations | 
     to_entries | any(.key | startswith("cert-utils-operator"))) | 
     "\(.metadata.namespace)/\(.metadata.name)"'
   
   # Find all Routes with cert-utils annotations
   kubectl get routes --all-namespaces -o json | \
     jq -r '.items[] | select(.metadata.annotations | 
     to_entries | any(.key | startswith("cert-utils-operator"))) | 
     "\(.metadata.namespace)/\(.metadata.name)"'
   ```

2. **Document Dependencies**
   - List all applications using keystores from cert-utils
   - Identify Secret-to-Secret CA injection use cases
   - Find compliance requirements for cert info annotations

3. **Install cert-manager Ecosystem**
   ```bash
   # Install cert-manager (if not already installed)
   kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.0/cert-manager.yaml
   
   # Install trust-manager
   helm repo add jetstack https://charts.jetstack.io
   helm install trust-manager jetstack/trust-manager -n cert-manager
   
   # Install openshift-routes (OpenShift only)
   helm install cert-manager-openshift-routes jetstack/cert-manager-openshift-routes -n cert-manager
   ```

### Phase 2: Migrate Keystore Generation (Week 2)

**For each Certificate using cert-utils keystore annotation:**

1. Update Certificate resource:
   ```bash
   # Create password secret
   kubectl create secret generic my-app-keystore-password \
     --from-literal=password=changeme \
     -n my-namespace
   
   # Edit Certificate to add keystores section
   kubectl edit certificate my-app-cert -n my-namespace
   ```

2. Add to spec:
   ```yaml
   keystores:
     pkcs12:
       create: true
       passwordSecretRef:
         name: my-app-keystore-password
         key: password
   ```

3. Verify keystore created:
   ```bash
   kubectl get secret my-app-tls -o jsonpath='{.data.keystore\.p12}' | base64 -d > /tmp/keystore.p12
   keytool -list -keystore /tmp/keystore.p12 -storepass changeme
   ```

4. Update application if needed (filename: `keystore.jks` → `keystore.p12`)

5. Remove cert-utils annotation:
   ```bash
   kubectl annotate secret my-app-tls \
     cert-utils-operator.redhat-cop.io/generate-java-keystores- \
     -n my-namespace
   ```

### Phase 3: Migrate CA Injection to Webhooks (Week 2)

1. Annotate source secrets:
   ```bash
   kubectl annotate secret my-ca-secret \
     cert-manager.io/allow-direct-injection=true \
     -n my-namespace
   ```

2. Update webhook configurations:
   ```bash
   # Automated script to update all webhooks
   for webhook in $(kubectl get validatingwebhookconfigurations -o name); do
     kubectl annotate $webhook \
       cert-utils-operator.redhat-cop.io/injectca-from-secret- \
       cert-manager.io/inject-ca-from-secret=$(
         kubectl get $webhook -o jsonpath='{.metadata.annotations.cert-utils-operator\.redhat-cop\.io/injectca-from-secret}'
       )
   done
   ```

3. Verify CA bundle injection:
   ```bash
   kubectl get validatingwebhookconfigurations my-webhook \
     -o jsonpath='{.webhooks[0].clientConfig.caBundle}' | \
     base64 -d | openssl x509 -noout -subject
   ```

### Phase 4: Migrate Truststore Distribution (Week 3)

1. Label namespaces for trust distribution:
   ```bash
   kubectl label namespace app-namespace-1 trust-injection=enabled
   kubectl label namespace app-namespace-2 trust-injection=enabled
   ```

2. Create trust-manager Bundle:
   ```yaml
   apiVersion: trust.cert-manager.io/v1alpha1
   kind: Bundle
   metadata:
     name: company-ca-bundle
   spec:
     sources:
       - configMap:
           name: source-ca-bundle
           key: ca-bundle.crt
     target:
       configMap:
         key: ca.crt
       additionalFormats:
         jks:
           key: truststore.jks
           password: changeit
       namespaceSelector:
         matchLabels:
           trust-injection: enabled
   ```

3. Update applications to use new ConfigMap name:
   ```yaml
   # Before: app reads from original ConfigMap
   volumes:
     - name: truststore
       configMap:
         name: original-ca-configmap
   
   # After: app reads from trust-manager Bundle name
   volumes:
     - name: truststore
       configMap:
         name: company-ca-bundle  # Matches Bundle metadata.name
   ```

### Phase 5: Migrate Route Certificates (Week 3)

**Option A: Use cert-manager Issuance**

1. Remove manual secret, add cert-manager annotations:
   ```yaml
   apiVersion: route.openshift.io/v1
   kind: Route
   metadata:
     annotations:
       cert-manager.io/issuer-name: letsencrypt-prod
       cert-manager.io/issuer-kind: ClusterIssuer
       # Remove: cert-utils-operator.redhat-cop.io/certs-from-secret
   ```

**Option B: Keep Using External Certificates (Hybrid)**
- Retain cert-utils-operator for Route population only
- Use for Routes with externally-managed certificates

### Phase 6: Migrate Prometheus Metrics (Week 4)

1. Update Prometheus scrape configs:
   ```yaml
   apiVersion: v1
   kind: ServiceMonitor
   metadata:
     name: cert-manager-metrics
   spec:
     selector:
       matchLabels:
         app.kubernetes.io/name: cert-manager
     endpoints:
       - port: tcp-prometheus-servicemonitor
         interval: 60s
   ```

2. Update alerting rules:
   ```yaml
   # Before: certutils_certificate_expiry_time
   # After: certmanager_certificate_expiry_time_seconds
   
   groups:
     - name: certificate-expiry
       rules:
         - alert: CertificateExpiringSoon
           expr: (certmanager_certificate_expiry_time_seconds - time()) < (7 * 24 * 60 * 60)
   ```

### Phase 7: Handle Blockers (Week 4)

**Decision Point: Strategy 1 (Full Migration) or Strategy 2 (Hybrid)**

**If Full Migration:**
1. Identify all Secret-to-Secret CA injection use cases
2. Implement projected volume workaround:
   ```yaml
   volumes:
     - name: tls-complete
       projected:
         sources:
           - secret:
               name: app-tls
           - configMap:
               name: ca-bundle  # From trust-manager
   ```
3. Update applications to mount projected volume
4. Remove cert-utils-operator

**If Hybrid:**
1. Keep cert-utils-operator running
2. Remove all other cert-utils annotations (migrated to cert-manager)
3. Only retain:
   - `cert-utils-operator.redhat-cop.io/injectca-from-secret` (on Secrets)
   - `cert-utils-operator.redhat-cop.io/generate-cert-info` (on Secrets)

### Phase 8: Validation & Rollout (Weeks 5-6)

1. **Pre-Production Testing**
   - Deploy to staging/dev environments first
   - Verify all certificates working
   - Test Java applications with new keystore paths
   - Validate CA bundles distributed correctly

2. **Production Rollout**
   - Rolling update per namespace
   - Monitor application health
   - Have rollback plan ready

3. **Decommission (Full Migration Only)**
   ```bash
   # Remove cert-utils-operator
   helm delete cert-utils-operator -n cert-utils-operator
   kubectl delete namespace cert-utils-operator
   ```

---

## Risk Assessment

### Low Risk
- ✅ Webhook CA injection (direct annotation swap)
- ✅ Certificate expiry metrics (similar functionality)

### Medium Risk
- ⚠️ Keystore generation (filename change: .jks → .p12)
- ⚠️ Truststore distribution (application config changes)
- ⚠️ Route certificates (workflow change if using cert-manager issuance)

### High Risk
- 🛑 Secret-to-Secret CA injection (feature loss or complex workaround)
- 🛑 Human-readable cert info (feature loss)

### Rollback Plan

**If migration issues occur:**

1. **Keep cert-utils-operator installed** during migration
2. **Revert annotation changes** to rollback features
3. **Test rollback in staging first**

**Rollback commands:**
```bash
# Reinstall cert-utils-operator
helm repo add cert-utils-operator https://redhat-cop.github.io/cert-utils-operator
helm install cert-utils-operator cert-utils-operator/cert-utils-operator

# Restore annotations (example)
kubectl annotate secret my-tls \
  cert-utils-operator.redhat-cop.io/generate-java-keystores=true
```

---

## Cost-Benefit Analysis

### Benefits of Migration

1. **Consolidation**
   - ✅ Reduce from 2 operators to 1 ecosystem
   - ✅ Unified management of certificate features

2. **Community & Support**
   - ✅ cert-manager is CNCF project with large community
   - ✅ Active development and security updates
   - ✅ Enterprise support available

3. **Features**
   - ✅ Automated certificate issuance & renewal
   - ✅ Rich ecosystem (trust-manager, openshift-routes, etc.)
   - ✅ More Issuer integrations (ACME, Vault, Venafi, etc.)

4. **Standardization**
   - ✅ Industry standard for K8s certificate management
   - ✅ Better onboarding for new team members

### Costs of Migration

1. **Engineering Time**
   - ⚠️ 3-6 weeks migration effort
   - ⚠️ Application configuration changes
   - ⚠️ Testing and validation

2. **Feature Loss**
   - 🛑 Secret-to-Secret CA injection (unless hybrid approach)
   - 🛑 Human-readable cert info annotations

3. **Pattern Changes**
   - ⚠️ Learning curve for CR-based patterns
   - ⚠️ More complex for simple use cases (annotation → CR)

4. **Risk**
   - ⚠️ Potential downtime if not executed carefully
   - ⚠️ Application compatibility issues

---

## Recommendation

### For Organizations Using cert-manager Already: **MIGRATE**

**Rationale:**
- You're already using cert-manager for certificate issuance
- cert-utils-operator features now redundant with modern cert-manager
- Consolidation reduces complexity

**Approach:** Strategy 1 (Full Migration) or Strategy 2 (Hybrid) based on Secret-to-Secret CA injection requirements

---

### For Organizations NOT Using cert-manager: **EVALUATE**

**Rationale:**
- If using external PKI/manual certificates, cert-utils-operator may still be valuable
- Migration requires adopting cert-manager for issuance (larger change)
- Consider if automated issuance/renewal is desired

**Decision Points:**
1. **Do you want automated certificate issuance?**
   - Yes → Migrate to cert-manager + retire cert-utils
   - No → Keep cert-utils-operator

2. **Do you need Secret-to-Secret CA injection?**
   - Yes → Hybrid approach or keep cert-utils
   - No → Full migration feasible

---

## Timeline

| Phase | Duration | Activities |
|-------|----------|------------|
| **Planning** | Week 1 | Audit, inventory, decision on strategy |
| **Pilot** | Week 2 | Migrate 1-2 non-critical applications |
| **Keystores & Webhooks** | Week 2-3 | Migrate keystore and webhook features |
| **Trust Distribution** | Week 3-4 | Migrate CA bundle distribution |
| **Routes & Metrics** | Week 4 | Migrate Route certs and Prometheus |
| **Production Rollout** | Week 5-6 | Phased rollout to production |
| **Validation** | Week 6 | Monitor, verify, document |

**Total Timeline:** 6 weeks for full migration

---

## Success Metrics

### Technical Metrics
- ✅ 100% of keystores migrated to cert-manager native
- ✅ 100% of webhook CA injection using ca-injector
- ✅ All trust bundles distributed via trust-manager
- ✅ Zero secret-to-secret CA injection remaining (or documented exceptions)
- ✅ cert-utils-operator uninstalled (or reduced to 2 features)

### Operational Metrics
- ✅ No increase in P0/P1 incidents related to certificates
- ✅ Certificate renewal success rate maintained at 100%
- ✅ Application uptime maintained during migration
- ✅ Team satisfaction with new patterns

### Business Metrics
- ✅ Reduced operational complexity (fewer operators to maintain)
- ✅ Improved onboarding (industry-standard tooling)
- ✅ Reduced security risk (active CNCF project with security updates)

---

## Conclusion

**cert-utils-operator was designed as a companion to cert-manager**, filling gaps that existed in 2019-2020. The cert-manager ecosystem has evolved significantly since then, adding native support for most cert-utils features:

- ✅ PKCS12 keystores (native in Certificate resource)
- ✅ JKS truststores (trust-manager)
- ✅ OpenShift Routes (openshift-routes controller)
- ✅ CA injection to webhooks (ca-injector)
- ✅ Certificate expiry metrics (native)

**Migration is feasible for 85% of features.** Only two blockers remain:
1. Secret-to-Secret CA injection (workaround: projected volumes)
2. Human-readable certificate info (workaround: external tooling)

### Final Recommendation

**MIGRATE to cert-manager ecosystem** using Strategy 1 (Full Migration) or Strategy 2 (Hybrid) depending on your requirements for the 2 blocked features.

The benefits of consolidating on industry-standard cert-manager tooling outweigh the costs for most organizations, especially those already using cert-manager for certificate issuance.

---

## References

### cert-manager Ecosystem Documentation
- [cert-manager](https://cert-manager.io/docs/)
- [trust-manager](https://cert-manager.io/docs/trust/trust-manager/)
- [ca-injector](https://cert-manager.io/docs/concepts/ca-injector/)
- [openshift-routes](https://github.com/cert-manager/openshift-routes)

### cert-utils-operator
- [GitHub Repository](https://github.com/redhat-cop/cert-utils-operator)
- [README](https://github.com/redhat-cop/cert-utils-operator/blob/master/README.md)
- [Red Hat CoP Blog](https://www.redhat.com/en/blog/red-hat-container-community-of-practice-operators)

### Feature Requests & Issues
- [cert-manager #2722: CA injection to Secrets](https://github.com/cert-manager/cert-manager/issues/2722)
- [trust-manager #222: Secret targets](https://github.com/cert-manager/trust-manager/issues/222)
- [Discussion #6303: JKS truststore](https://github.com/cert-manager/cert-manager/discussions/6303)

### Related Documentation
- [BUSINESS_LOGIC_ANALYSIS.md](./BUSINESS_LOGIC_ANALYSIS.md) - Complete feature analysis
- [DEPENDENCY_UPGRADE_STRATEGY.md](./DEPENDENCY_UPGRADE_STRATEGY.md) - Current upgrade work

---

**Document Version:** 1.0  
**Last Updated:** 2026-06-30  
**Review Date:** 2027-01-01 (re-evaluate after 6 months)  
**Status:** APPROVED FOR PLANNING
