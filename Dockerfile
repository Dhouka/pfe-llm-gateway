# Multi-stage build for the gateway (Java/Spring). Builds with Maven against the
# project's own pom.xml (including the Spring Milestones repo it depends on for
# Spring AI 1.0.0-M5 — see AUDIT_AND_REFACTOR_PLAN.md issue #11 on that milestone-
# dependency risk), then runs the packaged jar on a slim JRE.
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /build
COPY pom.xml .
COPY src ./src
RUN mvn -B -q clean package -DskipTests

FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=build /build/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
