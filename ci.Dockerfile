FROM registry.access.redhat.com/ubi8/ubi-minimal@sha256:d9beb74f4b32ef937d3a206430b6d9200a0b0d32ecc548325a738d0e4f7f0f1b
WORKDIR /
COPY bin/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
