FROM registry.access.redhat.com/ubi8/ubi-minimal@sha256:7c5f7ae1bcad8d2ebbc364bb8f62c76f50e5666062a65a5cc969d9d1e54ce0d8
WORKDIR /
COPY bin/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
