FROM registry.access.redhat.com/ubi8/ubi-minimal@sha256:0990c03b74757479e30f381206efa1387ea2d5df037ede48c494f1acb041cf69
WORKDIR /
COPY bin/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
