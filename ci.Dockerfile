FROM registry.access.redhat.com/ubi8/ubi-minimal@sha256:8de6d48ae7b421bca02fc402543eb69b2acb3dcadf18c0287d509eeea08f6fb2
WORKDIR /
COPY bin/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
