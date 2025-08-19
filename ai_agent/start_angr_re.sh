CONTAINER_NAME="angr-re"
IMAGE_NAME="angr-ctf:latest"

# Stop the container if it is already running
docker stop $CONTAINER_NAME 2>/dev/null || true
# Remove the container if it exists
docker rm $CONTAINER_NAME 2>/dev/null || true

# Start the container with the specified parameters
#docker run -d --rm --name $CONTAINER_NAME -i --platform=linux/amd64 -v ~/VSCode/angr/angr_ctf:/workspace --workdir /workspace $IMAGE_NAME
docker run -d --name $CONTAINER_NAME -i --platform=linux/amd64 -v ~/VSCode/angr/angr_ctf:/workspace --workdir /workspace $IMAGE_NAME
