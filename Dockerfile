FROM maven:3.9.9-eclipse-temurin-17 AS build

WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn -B clean package

FROM eclipse-temurin:17-jre

WORKDIR /app
COPY --from=build /app/target/java-email-authentication-1.0.0.jar app.jar
COPY --from=build /app/target/lib ./lib

ENV PORT=10000
EXPOSE 10000

CMD ["java", "-jar", "app.jar"]
