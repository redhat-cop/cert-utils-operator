FROM registry.access.redhat.com/ubi8/ubi-minimal@sha256:b3314c5f8d009ee6df04ead732bca6d3eaf011750185e348f55fce2678fb30d0
WORKDIR /
COPY bin/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
