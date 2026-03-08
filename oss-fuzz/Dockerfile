# OSS-Fuzz Dockerfile for openhitls-rs
# See: https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang/
FROM gcr.io/oss-fuzz-base/base-builder-rust

RUN git clone --depth 1 https://github.com/dong-qiu/openhitls-rs.git

WORKDIR openhitls-rs
COPY build.sh $SRC/
