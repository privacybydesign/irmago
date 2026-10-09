# Multipaz's reference org-iso-mdoc verifier, built from source at a pinned commit.
#
# Why this exists rather than an `image:` line: the Multipaz project publishes no
# container image anywhere (its only release workflow ships Kotlin libraries to
# Maven Central), and its own Dockerfile packages JARs that Gradle has already
# staged on the host. This builds those JARs itself, so `docker compose` needs
# nothing but a checkout of irmago.
#
# Why the Android SDK is installed to build a JVM server: the verifier server
# depends on :multipaz and :multipaz-longfellow, which apply the Kotlin
# Multiplatform and androidLibrary plugins. Gradle cannot CONFIGURE that
# dependency chain without an SDK present, even though nothing Android is built.
#
# The first build is slow (a Kotlin Multiplatform project from scratch) and the
# image is large. That cost is paid once and cached; it is the price of not
# depending on a binary nobody publishes.

# ---------- build ----------
FROM eclipse-temurin:17-jdk-jammy AS build

# A commit, not a branch: an interop oracle that silently changes is not an
# oracle, and `main` would rebuild into a different verifier every time the cache
# is cold. Bump deliberately, then regenerate the captured request fixture
# (REGENERATE_MULTIPAZ_FIXTURE=1, see eudi/isomdoc/interop_live_test.go) and read
# the diff — that diff is upstream changing a request we parse.
#
# b741acd is openwallet-foundation/multipaz main as of 2026-10-06; the live
# round trip and the four fixture tests pass against it.
ARG MULTIPAZ_REF=b741acd1f2a77ffbe2818b71822841781dd7ad9f
ARG MULTIPAZ_REPO=https://github.com/openwallet-foundation/multipaz.git

RUN apt-get update && apt-get install -y --no-install-recommends \
      git curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV ANDROID_HOME=/opt/android-sdk
ENV PATH="${PATH}:${ANDROID_HOME}/cmdline-tools/latest/bin"
RUN mkdir -p "${ANDROID_HOME}/cmdline-tools" \
    && curl -sSL -o /tmp/tools.zip \
       https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip \
    && unzip -q /tmp/tools.zip -d "${ANDROID_HOME}/cmdline-tools" \
    && mv "${ANDROID_HOME}/cmdline-tools/cmdline-tools" "${ANDROID_HOME}/cmdline-tools/latest" \
    && rm /tmp/tools.zip \
    && yes | sdkmanager --licenses > /dev/null

WORKDIR /src
RUN git clone --filter=blob:none "${MULTIPAZ_REPO}" . \
    && git checkout "${MULTIPAZ_REF}" \
    && git rev-parse HEAD > /multipaz-commit.txt

# collectDependencies stages the thin server JARs and their deduplicated runtime
# classpath, which is exactly what upstream's own image consumes. Web targets are
# off: nothing here serves the Kotlin/JS frontend, and they are a large share of
# the build.
RUN ./gradlew --no-daemon --no-build-cache -Pdisable.web.targets=true \
      :multipaz-server-deployment:collectDependencies

# ---------- runtime ----------
FROM eclipse-temurin:17-jre-jammy

RUN apt-get update && apt-get install -y --no-install-recommends \
      sqlite3 libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r multipaz && useradd -r -g multipaz multipaz

WORKDIR /app
COPY --from=build /src/multipaz-server-deployment/build/docker-staging/jars/ /app/jars/
COPY --from=build /src/multipaz-server-deployment/build/docker-staging/libs/ /app/libs/
COPY --from=build /multipaz-commit.txt /app/multipaz-commit.txt

RUN mkdir -p /app/data /app/logs && chown -R multipaz:multipaz /app
USER multipaz

EXPOSE 8006

# The classpath and parameters mirror upstream's start-servers.sh for the
# `verifier` service, minus the nginx proxy and the five servers this does not
# run. base_url matters: the verifier builds its own session state against it.
ENTRYPOINT ["sh", "-c", "exec java -cp '/app/jars/verifier-server.jar:/app/jars/verifier.jar:/app/libs/*' org.multipaz.verifier.server.Main -param server_port=8006 -param base_url=http://localhost:8006 -param database_connection='jdbc:sqlite:/app/data/verifier.db'"]
