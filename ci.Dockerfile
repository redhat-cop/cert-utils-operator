FROM registry.access.redhat.com/ubi8/ubi-minimal@sha256:99ae5911c373b1c9e15067646309e2212b6fe97b18cd39feb55f2f0b9be0f075
WORKDIR /
COPY bin/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
