# Integration Tests

This directory contains integration tests for the cert-utils-operator using [envtest](https://book.kubebuilder.io/reference/envtest.html).

## Overview

Integration tests run controllers against a real Kubernetes API server (provided by envtest) to verify end-to-end behavior including:
- Controller reconciliation loops
- Resource watches and event handling  
- Cross-resource interactions (e.g., Secret → ConfigMap CA injection)
- Annotation-based conditional logic
- Resource updates propagating correctly

## Running Integration Tests

### Prerequisites

1. Install envtest binaries:
   ```bash
   make envtest
   ```

2. Download Kubernetes 1.21 test assets:
   ```bash
   bin/setup-envtest use 1.21
   ```

### Run All Integration Tests

```bash
make integration
```

Or directly with go test:
```bash
KUBEBUILDER_ASSETS="$(bin/setup-envtest use 1.21 -p path)" go test ./test/integration/... -v
```

### Run Specific Test

```bash
KUBEBUILDER_ASSETS="$(bin/setup-envtest use 1.21 -p path)" go test ./test/integration/... -v -run TestCAInjection_ConfigMap
```

## Test Structure

### `suite_test.go`
- Sets up envtest environment
- Initializes Kubernetes scheme with all required types
- Starts controller manager with all controllers
- Provides helper functions for tests

### `cainjection_test.go`
- Tests CA injection into ConfigMaps and Secrets
- Tests annotation removal (CA cleanup)
- Tests source secret updates propagating to targets
- Verifies watch/event mechanisms work correctly

### `secrettokeystore_test.go`
- Tests Java keystore/truststore generation
- Tests keystore removal when annotation is removed
- Tests certificate info generation
- Verifies data transformations

## CI Integration

The integration tests are designed to work with the shared Red Hat COP GitHub Actions workflow:

```yaml
RUN_INTEGRATION_TESTS: true
```

When enabled in `.github/workflows/pr.yaml`, CI will automatically run `make integration`.

## Key Differences from Unit Tests

| Aspect | Unit Tests | Integration Tests |
|--------|-----------|-------------------|
| **Kubernetes API** | Fake client (in-memory) | Real API server (envtest) |
| **Controllers** | Not running | Actually running in manager |
| **Event Watches** | Mocked predicates | Real Kubernetes watches |
| **Reconcile Loops** | Directly invoked | Triggered by resource changes |
| **Speed** | Very fast (<1s) | Slower (~10s setup + tests) |
| **Coverage** | Business logic | End-to-end behavior |

## Writing New Integration Tests

1. Create test file in `test/integration/`
2. Use `k8sClient` to create/update resources
3. Use `waitForCondition()` helper to wait for reconciliation
4. Verify final state with `k8sClient.Get()`

Example:
```go
func TestMyFeature(t *testing.T) {
    ctx := context.Background()
    
    // Create resource
    resource := &corev1.ConfigMap{ /* ... */ }
    if err := k8sClient.Create(ctx, resource); err != nil {
        t.Fatalf("Failed to create: %v", err)
    }
    defer k8sClient.Delete(ctx, resource)
    
    // Wait for controller to reconcile
    waitForCondition(t, func() bool {
        updated := &corev1.ConfigMap{}
        err := k8sClient.Get(ctx, types.NamespacedName{...}, updated)
        return err == nil && updated.Data["expected-key"] == "expected-value"
    }, 10*time.Second, "resource to be reconciled")
    
    // Verify final state
    // ...
}
```

## Troubleshooting

### "no such file or directory: /usr/local/kubebuilder/bin/etcd"

Run `make envtest` and `bin/setup-envtest use 1.21` to download the required binaries.

### Tests timeout waiting for reconciliation

- Increase timeout in `waitForCondition()` calls
- Check controller logs for errors
- Verify resource has required annotations
- Ensure controller is registered in `suite_test.go`

### "scheme not registered" errors

Add the required type to the scheme in `suite_test.go`:
```go
if err := myapiv1.AddToScheme(scheme); err != nil {
    panic(err)
}
```
