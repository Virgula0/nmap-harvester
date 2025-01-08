# Base image
FROM ubuntu:22.04

# Set environment variables to prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install required tools and dependencies
RUN apt-get update && \
    apt-get install -y \
        curl \
        nmap \
        python3 \
        python3-pip \
        iputils-ping \
        net-tools && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create a working directory
WORKDIR /tmp/temp

# Copy any required files (if needed)
COPY . /tmp/temp

# Default command
CMD ["/bin/bash"]