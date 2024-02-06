FROM rust:latest as build

COPY ./ ./

RUN cargo build --release

RUN mkdir -p /build-out

RUN cp target/release/contact-api /build-out/

# Ubuntu 18.04
FROM ubuntu:22.04

COPY --from=build /build-out/contact-api /

CMD /contact-api