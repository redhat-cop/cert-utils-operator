# Dependency Upgrade Strategy

**Document Version:** 1.0  
**Date:** 2026-06-26  
**Current Status:** Ready for upgrades with comprehensive test coverage

---

## Executive Summary

This document outlines the strategy for safely upgrading dependencies in cert-utils-operator to address security vulnerabilities and enable modern tooling. **We now have comprehensive test coverage (54% average, all controllers tested) that will validate upgrades work correctly.**

### Current State

- **Go Version:** 1.16 (EOL - needs upgrade to 1.21+)
- **Kubernetes Libraries:** v0.20.2 (from Jan 2021 - 5+ years old)
- **controller-runtime:** v0.8.3 (from Mar 2021 - 5+ years old)
- **OpenShift API:** v3.9.0 (very old, incompatible version tag)
- **Test Coverage:** 54% average, all 11 controllers have unit tests ✅

### Goals

1. ✅ **Security:** Address known vulnerabilities in dependencies
2. ✅ **Compatibility:** Support modern Kubernetes versions (1.28+)
3. ✅ **Tooling:** Enable integration tests with modern envtest
4. ✅ **Maintainability:** Use supported, actively maintained versions
5. ✅ **Safety:** Validate with comprehensive test suite

---

## Test Coverage Status

### ✅ What We Have

**Unit Tests (All Controllers):**
- 9 test files created
- 5,716 lines of test code
- All Reconcile loops tested
- 54% average code coverage

| Controller | Coverage | Tests |
|------------|----------|-------|
| CA Injection (6 controllers) | 70.3% | ✅ |
| Secret-to-Keystore | 63.1% | ✅ |
| Utility Functions | 53.3% | ✅ |
| Certificate Expiry Alert | 53.6% | ✅ |
| ConfigMap-to-Keystore | 50.8% | ✅ |
| Certificate Info | 43.9% | ✅ |
| Route | 41.3% | ✅ |

**Integration Tests (Framework Ready):**
- 4 test files created (912 lines)
- 7 integration tests written
- `make integration` target configured
- Won't run until controller-runtime upgraded ⚠️

### ✅ What Tests Validate

- ✅ Business logic in all Reconcile loops
- ✅ Annotation-based conditional logic
- ✅ Resource creation, updates, and removal
- ✅ Data transformations (keystores, cert info, CA injection)
- ✅ Error handling paths
- ✅ Predicate filters for event handling

---

## Dependency Upgrade Plan

### Phase 1: Go Version Upgrade (Critical)

**Current:** Go 1.16 (EOL since Feb 2022)  
**Target:** Go 1.21+ (recommended: 1.21 or 1.22 for stability)

**Why:**
- Security patches no longer available for 1.16
- Required for modern dependency versions
- CI already using incompatible versions

**Changes Required:**
```diff
# go.mod
-go 1.16
+go 1.21
```

**Validation:**
```bash
go mod tidy
go build ./...
go test ./...  # Run all 5,716 lines of unit tests
```

**Risk:** Low - Go has strong backward compatibility

---

### Phase 2: Kubernetes Libraries Upgrade (High Priority)

**Current Versions:**
```
k8s.io/api                       v0.20.2  (Jan 2021)
k8s.io/apimachinery              v0.20.2
k8s.io/client-go                 v0.20.2
k8s.io/apiextensions-apiserver   v0.20.1
k8s.io/kube-aggregator           v0.20.1
```

**Target Versions:** v0.28.x (September 2023 - still supported)

**Why v0.28 instead of latest (v0.31+)?**
- v0.28 is the last version with strong Go 1.21 support
- controller-runtime v0.16.x supports v0.28
- Proven stability (released Sep 2023, well-tested)
- Avoids bleeding edge (v0.31+ may have unknown issues)

**Changes Required:**
```diff
# go.mod
require (
-    k8s.io/api v0.20.2
-    k8s.io/apimachinery v0.20.2
-    k8s.io/client-go v0.20.2
-    k8s.io/apiextensions-apiserver v0.20.1
-    k8s.io/kube-aggregator v0.20.1
+    k8s.io/api v0.28.4
+    k8s.io/apimachinery v0.28.4
+    k8s.io/client-go v0.28.4
+    k8s.io/apiextensions-apiserver v0.28.4
+    k8s.io/kube-aggregator v0.28.4
)
```

**API Changes to Watch:**
- Admission webhooks: `admissionregistration.k8s.io/v1` (already using this ✅)
- CRDs: `apiextensions.k8s.io/v1` (already using this ✅)
- RBAC: `rbac.authorization.k8s.io/v1` (already using this ✅)

**Validation:**
```bash
go mod tidy
go test ./controllers/...  # All controller unit tests
go build ./...
```

**Risk:** Medium - API-compatible but internal changes possible

---

### Phase 3: controller-runtime Upgrade (Critical for Integration Tests)

**Current:** v0.8.3 (March 2021)  
**Target:** v0.16.3 (for K8s v0.28 compatibility)

**Why This Version:**
- Compatible with Kubernetes v0.28.x
- Supports modern envtest (our integration tests need this!)
- Well-tested and stable
- Used by many production operators

**Changes Required:**
```diff
# go.mod
-sigs.k8s.io/controller-runtime v0.8.3
+sigs.k8s.io/controller-runtime v0.16.3
```

**Breaking Changes to Address:**

1. **Manager Options Changes:**
   ```go
   // Before (v0.8)
   mgr, err := ctrl.NewManager(cfg, ctrl.Options{
       Scheme: scheme,
   })
   
   // After (v0.16) - mostly compatible, but check for new fields
   mgr, err := ctrl.NewManager(cfg, ctrl.Options{
       Scheme: scheme,
       // New optional fields available
   })
   ```

2. **Predicate Interface:**
   - Mostly compatible
   - Our predicates use `predicate.Funcs` which is stable ✅

3. **ReconcilerBase from operator-utils:**
   - May need operator-utils upgrade (see Phase 4)

**Validation:**
```bash
go mod tidy
go test ./controllers/...           # Unit tests
make integration                    # Integration tests (will work now!)
```

**Risk:** Medium-High - Internal controller-runtime changes

---

### Phase 4: operator-utils Upgrade

**Current:** v1.1.4  
**Target:** v1.4.x+ (check compatibility with controller-runtime v0.16)

**Why:**
- `ReconcilerBase` compatibility with controller-runtime v0.16
- Bug fixes and improvements
- Better error handling

**Investigation Needed:**
```bash
# Check operator-utils releases
curl -s https://api.github.com/repos/redhat-cop/operator-utils/releases | jq -r '.[].tag_name' | head -10
```

**Changes Required:**
```diff
# go.mod
-github.com/redhat-cop/operator-utils v1.1.4
+github.com/redhat-cop/operator-utils v1.4.x
```

**Validation:**
```bash
go test ./controllers/...  # All controllers use ReconcilerBase
```

**Risk:** Low-Medium - Well-abstracted interface

---

### Phase 5: OpenShift API Upgrade

**Current:** v3.9.0+incompatible (very old)  
**Target:** v0.0.0-20231109182013-... (check latest route/v1 tag)

**Why:**
- Fix incompatible version tag
- Get route API updates and fixes
- Align with modern OpenShift versions

**Changes Required:**
```diff
# go.mod
-github.com/openshift/api v3.9.0+incompatible
+github.com/openshift/api v0.0.0-20231109182013-... // Use specific commit/tag
```

**API Changes to Check:**
- `route/v1.Route` structure (we use this extensively)
- TLS termination types
- Ingress controller annotations

**Validation:**
```bash
go test ./controllers/route/...  # Route controller tests
```

**Risk:** Low - Route API is stable

---

### Phase 6: Other Dependencies

**Keystore Library:**
```diff
# Clean up duplicate entries
-github.com/pavel-v-chernykh/keystore-go v2.1.0+incompatible
-github.com/pavel-v-chernykh/keystore-go/v4 v4.2.0
-github.com/pavlo-v-chernykh/keystore-go/v4 v4.4.1
+github.com/pavel-v-chernykh/keystore-go/v4 v4.5.0  // Latest stable
```

**Prometheus Client:**
```diff
-github.com/prometheus/client_golang v1.7.1
+github.com/prometheus/client_golang v1.17.0  // Modern version
```

**Risk:** Low - Well-tested libraries

---

## Upgrade Execution Strategy

### Recommended Approach: Incremental with Testing

```bash
# 1. Create upgrade branch
git checkout -b feature/dependency-upgrades

# 2. Phase 1: Go version
# Edit go.mod: go 1.21
go mod tidy
go test ./...
git add go.mod go.sum && git commit -m "Upgrade Go to 1.21"

# 3. Phase 2: Kubernetes libraries  
# Edit go.mod: k8s.io/* to v0.28.4
go mod tidy
go test ./controllers/...
git add go.mod go.sum && git commit -m "Upgrade Kubernetes libraries to v0.28.4"

# 4. Phase 3: controller-runtime
# Edit go.mod: controller-runtime to v0.16.3
go mod tidy
go test ./controllers/...
make integration  # Should work now!
git add go.mod go.sum && git commit -m "Upgrade controller-runtime to v0.16.3"

# 5. Phase 4: operator-utils
# Edit go.mod: operator-utils to v1.4.x
go mod tidy
go test ./...
git add go.mod go.sum && git commit -m "Upgrade operator-utils to v1.4.x"

# 6. Phase 5 & 6: Other dependencies
# Upgrade OpenShift API, keystore, prometheus
go mod tidy
go test ./...
git add go.mod go.sum && git commit -m "Upgrade remaining dependencies"

# 7. Final validation
make test           # All unit tests
make integration    # Integration tests
make build          # Ensure it builds
```

### Alternative Approach: All-at-Once (Riskier)

If incremental is too complex, upgrade all at once but be prepared for more debugging:

```bash
# Edit go.mod with all new versions
go mod tidy
# Fix any breaking changes
go test ./...
make integration
```

---

## Testing Strategy

### After Each Phase

```bash
# 1. Unit tests (fast - ~2s)
go test ./controllers/... -v

# 2. Integration tests (slower - ~30s after controller-runtime upgrade)
make integration

# 3. Build validation
go build ./...
make docker-build

# 4. Manual smoke test (optional)
# Deploy to kind cluster and test key scenarios
```

### Test Coverage Validation

```bash
# Ensure coverage doesn't drop
go test ./... -coverprofile=cover.out
go tool cover -func=cover.out | grep total
# Should still be ~54% or better
```

### Critical Test Scenarios

After upgrades, verify:
1. ✅ CA injection (ConfigMap & Secret) - `TestCAInjection_*`
2. ✅ Keystore generation - `TestSecretToKeyStore_*`
3. ✅ Route population - `TestReconcile_Route*`
4. ✅ Certificate expiry alerts - `TestReconcile_CertExpiry*`
5. ✅ Certificate info - `TestCertificateInfo_*`

---

## Known Issues & Resolutions

### Issue 1: Integration Tests Won't Run (Current)

**Problem:** envtest fails with K8s 1.28+ on controller-runtime v0.8.3

**Resolution:** Upgrade to controller-runtime v0.16+ (Phase 3)

### Issue 2: Go Version Mismatch

**Problem:** CI uses Go ~1.19, project uses 1.16

**Resolution:** 
1. Upgrade project to Go 1.21 (Phase 1)
2. Update CI workflow (Task #12)

### Issue 3: +incompatible Version Tags

**Problem:** Several deps have +incompatible tags

**Resolution:** Use proper semantic versions in upgrades

### Issue 4: controller-gen Panic

**Problem:** `make generate` crashes on Go 1.24

**Resolution:** Upgrade controller-tools after controller-runtime upgrade

---

## Rollback Strategy

If upgrades cause issues:

```bash
# Quick rollback
git checkout master
git branch -D feature/dependency-upgrades

# Partial rollback (revert specific commit)
git revert <commit-hash>

# Emergency: revert all upgrades
git reset --hard <commit-before-upgrades>
```

**Safe because:**
- All changes in feature branch
- Master branch unchanged
- Comprehensive tests catch issues early

---

## CI/CD Integration

### Update GitHub Actions

After upgrades, update `.github/workflows/pr.yaml`:

```diff
-GO_VERSION: ~1.19
+GO_VERSION: ~1.21

-RUN_INTEGRATION_TESTS: false
+RUN_INTEGRATION_TESTS: true  # Now works!
```

### Check Shared Workflow Compatibility

Task #12 will investigate:
- Latest version of `redhat-cop/github-workflows-operators`
- Any new features or requirements
- Integration test expectations

---

## Success Criteria

Upgrades are successful when:

1. ✅ All unit tests pass (5,716 lines)
2. ✅ All integration tests pass (912 lines)
3. ✅ `make build` succeeds
4. ✅ `make docker-build` succeeds
5. ✅ Code coverage maintained (~54%)
6. ✅ No new linter warnings
7. ✅ CI pipeline passes
8. ✅ Integration tests enabled in CI

---

## Timeline Estimate

| Phase | Time Estimate | Complexity |
|-------|---------------|------------|
| Phase 1: Go version | 30 min | Low |
| Phase 2: K8s libraries | 1-2 hours | Medium |
| Phase 3: controller-runtime | 2-4 hours | High |
| Phase 4: operator-utils | 1 hour | Medium |
| Phase 5: OpenShift API | 1 hour | Low |
| Phase 6: Other deps | 30 min | Low |
| **Total** | **6-9 hours** | **Medium-High** |

**Note:** Most time is testing and validation, not code changes.

---

## References

- [controller-runtime v0.16 Release Notes](https://github.com/kubernetes-sigs/controller-runtime/releases/tag/v0.16.0)
- [Kubernetes v0.28 Release Notes](https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.28.md)
- [operator-utils Releases](https://github.com/redhat-cop/operator-utils/releases)
- [Go Release Policy](https://go.dev/doc/devel/release)

---

## Next Steps

1. ✅ Review this document
2. Create `feature/dependency-upgrades` branch
3. Execute Phase 1 (Go upgrade)
4. Execute Phase 2 (K8s libraries)
5. Execute Phase 3 (controller-runtime) - Integration tests will work!
6. Execute Phases 4-6 (remaining dependencies)
7. Update CI configuration (Task #12)
8. Create PR for team review

**You are ready to start upgrades safely with 54% test coverage!**
