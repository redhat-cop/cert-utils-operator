FROM registry.access.redhat.com/ubi8/ubi-minimal@sha256:4e4bb2f1d53efe9a198adc197037aa2d63f113f90911d7d074bf43bb732ed8f0
WORKDIR /
COPY bin/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
