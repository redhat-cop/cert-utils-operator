FROM registry.access.redhat.com/ubi8/ubi-minimal@sha256:ecc9eba659d04c56b12da3efb83483349d57aa08734ad3e64e9bd6128806c7cc
WORKDIR /
COPY bin/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
