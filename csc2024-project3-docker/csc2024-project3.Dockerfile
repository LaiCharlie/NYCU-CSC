# Use an official base image
FROM ubuntu:22.04

# Install required tools, libraries, and OpenSSH Server
RUN apt-get update && \
    apt-get install -y \
    openssh-server \
    build-essential \
    python3 \
    python3-pip \
    vim-common \
    unzip \
    zip \
    imagemagick \ 
    && pip3 install netifaces \
    && pip3 install paramiko \
    && rm -rf /var/lib/apt/lists/* 

# Add user for SSH access (change 'csc2024' to your desired password)
RUN useradd -ms /bin/bash csc2024
RUN echo 'csc2024:csc2024' | chpasswd
RUN echo 'csc2024 ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Create SSH directory
RUN mkdir /var/run/sshd

# Open port 22 for SSH access
EXPOSE 22

# Copy the entire project directory
COPY . /app

# Set the working directory
WORKDIR /app

# Set Permission to 777
RUN chmod -R 777 /app


