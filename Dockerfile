# syntax=docker/dockerfile:1.6

# Build stage compiles the Spring Boot jar with Maven and a JDK image. Layer-cache
# dependency resolution separately from source copy so iterative builds reuse the
# heavy dependency layer.
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml .
RUN mvn dependency:go-offline -B
COPY src ./src
RUN mvn package -DskipTests -B

# Runtime stage runs only the jar on a slim JRE. Non-root user, no Maven, no JDK.
FROM eclipse-temurin:21-jre-alpine AS runtime
# The commit sha tags the image but is not readable from inside it, so it has to be baked
# in. Sentry groups regressions by release, which is what makes "started after the last
# deploy" a reading rather than a guess.
ARG SENTRY_RELEASE=""
ENV SENTRY_RELEASE=${SENTRY_RELEASE}
RUN addgroup -S app && adduser -S -G app app
WORKDIR /app
COPY --from=build --chown=app:app /build/target/*.jar app.jar
USER app
EXPOSE 8000
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
