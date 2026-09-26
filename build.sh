#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

# Set JVM arguments to allow reflection access for Java 17+
# export MAVEN_OPTS="--add-opens=java.base/java.lang=ALL-UNNAMED --add-opens=java.base/java.lang.reflect=ALL-UNNAMED --add-opens=java.base/java.io=ALL-UNNAMED --add-opens=java.base/java.util=ALL-UNNAMED --add-opens=java.base/java.lang.invoke=ALL-UNNAMED --add-opens=java.base/java.util.concurrent=ALL-UNNAMED"

echo "Cleaning and compiling..."
mvn clean compile

echo "Packaging the project..."
mvn clean package -DskipTests

echo "Copying dependencies to target/deps..."
mvn dependency:copy-dependencies -DoutputDirectory=target/deps


