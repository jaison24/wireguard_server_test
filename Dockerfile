# Use the official Go image from the Docker Hub
FROM golang:latest

# Set the working directory inside the container
WORKDIR /app

# Copy the Go application files into the container
COPY . .

# Download dependencies and build the application
RUN go mod tidy && go build -o myapp

# Expose the port the application listens on (update this if needed)
EXPOSE 8000

# Run the built application
CMD ["./myapp"]
