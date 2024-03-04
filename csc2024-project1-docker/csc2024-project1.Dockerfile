# Use an official base image
FROM ubuntu:22.04

# Install required tools, libraries, and OpenSSH Server
RUN apt-get update -y && \
    apt-get install -y software-properties-common lsb-release net-tools iproute2 iputils-ping vim tmux tcpdump git curl openssh-server && \
    apt-key adv --fetch-keys https://apt.kitware.com/keys/kitware-archive-latest.asc && \
    apt-add-repository "deb https://apt.kitware.com/ubuntu/ $(lsb_release -cs) main" && \
    add-apt-repository ppa:ubuntu-toolchain-r/test && \
    apt-get update && \
    apt-get install -y cmake g++-10 && \
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-10 60 --slave /usr/bin/g++ g++ /usr/bin/g++-10

# Add user for SSH access (change 'csc2024' to your desired password)
RUN useradd -m csc2024 && \
    echo "csc2024:csc2024" | chpasswd && \
    echo "root:csc2024" | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Create SSH directory
RUN mkdir /var/run/sshd

# Open port 22 for SSH access
EXPOSE 22

# Copy the entire project directory
COPY csc2024-project1 /home/csc2024/csc2024-project1

# Set the working directory
WORKDIR /home/csc2024/csc2024-project1

# Give execution permission to scripts, converting files with (CRLF) to (LF)
RUN chmod +x scripts/config.sh && \
    sed -i 's/\r$//' scripts/config.sh

# Build the project
RUN cmake -S all -B build -D CMAKE_CXX_COMPILER=/usr/bin/g++-10 && \
    cmake --build build --config Release --target client && \
    cmake --build build --config Release --target server
