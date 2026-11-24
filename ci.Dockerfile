FROM registry.access.redhat.com/ubi8/ubi-minimal@sha256:1068268a5dc71d7b392ab17c07de3ebf64e18d7f34e9b63d213b0a9008993ec1
WORKDIR /
COPY bin/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
