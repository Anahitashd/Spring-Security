#!/bin/bash
# Check for help flag

DOCKER_REPO="nexus1.amnafzar.ir:1081"
DOCKER_IMAGE="pam"

# Function to handle errors
error_exit() {
  echo "$1" 1>&2
  exit 1
}

# Build core project
cd ./core || error_exit "Failed to navigate to core directory!"
mvn clean install || error_exit "Maven install failed for core project."

# Build PAM project
cd .. || error_exit "Failed to navigate to PAM directory!"
mvn clean install || error_exit "Maven install failed for PAM project."
#Login to repository
docker login --username="$nexusUser" --password="$nexusPass" $DOCKER_REPO
# Build Docker image
docker build -t "$DOCKER_REPO/$DOCKER_IMAGE:$TAG" . || error_exit "Docker build failed."

# Push Docker image
docker push "$DOCKER_REPO/$DOCKER_IMAGE:$TAG" || error_exit "Docker push failed."

echo "Build and push completed successfully!"
echo "To use it run docker pull nexus1.amnafzar.ir:1081/pam:TAG"
