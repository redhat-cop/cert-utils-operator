FROM registry.access.redhat.com/ubi8/ubi-minimal@sha256:2bd312096a71bf37dbc449f380d8b74cbdf385db2f48e07accc3d43c5e7be747
WORKDIR /
COPY bin/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
