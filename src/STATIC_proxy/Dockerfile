# syntax=docker/dockerfile:1

# Comments are provided throughout this file to help you get started.
# If you need more help, visit the Dockerfile reference guide at
# https://docs.docker.com/go/dockerfile-reference/

# Want to help us make this template better? Share your feedback here: https://forms.gle/ybq9Krt8jtBL3iCk7

ARG RUST_VERSION=1.92.0
ARG APP_NAME=static_proxy

################################################################################
# Create a stage for building the application.

FROM rust:${RUST_VERSION}-alpine AS build
ARG APP_NAME
WORKDIR /app/${APP_NAME}

# Install host build dependencies for the Rust toolchain and C crates.
RUN apk add --no-cache build-base clang lld musl-dev git

# Copy the STATIC proxy crate (Dockerfile now lives beside it) and build it.
# This keeps the build context small and focused on the proxy only.
COPY Cargo.toml ./Cargo.toml
COPY src ./src
COPY assets ./assets

# Profiles and config are bundled so the binary can locate defaults via relative paths.
COPY config ./config
COPY profiles ./profiles

RUN cargo build --release --bin ${APP_NAME}

################################################################################
# Create a new stage for running the application that contains the minimal
# runtime dependencies for the application. This often uses a different base
# image from the build stage where the necessary files are copied from the build
# stage.
#
# The example below uses the alpine image as the foundation for running the app.
# By specifying the "3.18" tag, it will use version 3.18 of alpine. If
# reproducibility is important, consider using a digest
# (e.g., alpine@sha256:664888ac9cfd28068e062c991ebcff4b4c7307dc8dd4df9e728bedde5c449d91).
FROM alpine:3.18 AS final
ARG APP_NAME=static_proxy

# Create a non-privileged user that the app will run under.
# See https://docs.docker.com/go/dockerfile-user-best-practices/
ARG UID=10001
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    appuser
RUN apk add --no-cache ca-certificates

WORKDIR /app/${APP_NAME}

# Copy the executable from the "build" stage.
COPY --from=build /app/${APP_NAME}/target/release/${APP_NAME} /usr/local/bin/${APP_NAME}

# Ship default config and profiles; these can be overridden at runtime via volume mounts.
COPY config ./config
COPY profiles ./profiles

# Ensure certificate cache directory exists and is writable by the non-privileged user.
RUN mkdir -p certs/cache && \
    chown -R appuser:appuser /app/${APP_NAME}

USER appuser

# Expose the port that the application listens on.
EXPOSE 4040

# What the container should run when it is started.
CMD ["/usr/local/bin/static_proxy", "--config", "config/static.example.toml"]
