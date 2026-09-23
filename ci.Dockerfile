FROM registry.access.redhat.com/ubi8/ubi-minimal@sha256:93288f46bf2dfb7ed83078d5d9f32d4dd8c0524bfb3afe8b5719aa636a5ecbd8
WORKDIR /
COPY bin/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
