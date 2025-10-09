CONTAINER_NAME="angr-re"
IMAGE_NAME="angr-ctf:latest"

# Stop the container if it is already running
echo "Stopping any existing container named $CONTAINER_NAME ..."
docker stop $CONTAINER_NAME 2>/dev/null || true
echo "Stopped"
# Remove the container if it exists
echo "Removing any existing container named $CONTAINER_NAME ..."
docker rm $CONTAINER_NAME 2>/dev/null || true
echo "Removed"

echo "Wait for 3 seconds before starting a new container ..."
sleep 3

# Start the container with the specified parameters
docker run -d --rm --name $CONTAINER_NAME -i --platform=linux/amd64 -v ~/VSCode/angr/angr_ctf:/workspace --workdir /workspace $IMAGE_NAME
#docker run -d --name $CONTAINER_NAME -i --platform=linux/amd64 -v ~/VSCode/angr/angr_ctf:/workspace --workdir /workspace $IMAGE_NAME

# Check 5 times (every 3 seconds) if the container is still running
echo "Checking if the container is running ..."
sleep 3
for i in {1..5}; do
    if docker ps -a | grep -q "$CONTAINER_NAME"; then
        echo "Container $CONTAINER_NAME is still running."
        sleep 3
    else
        echo "Container $CONTAINER_NAME is not running!"
        exit 1
    fi
done

# Now it seems the container is reliably running
echo "Container $CONTAINER_NAME is running successfully."
