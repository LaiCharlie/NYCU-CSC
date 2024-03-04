# CSC Project1 - IPSec Hijacking

## Install

### Build the project1 image

You need to install the docker at first,

and build the project1 image with
```bash
sudo docker build -t csc2024-project1 -f csc2024-project1.Dockerfile .
```

### Run the project1 containers

Run the server and client with
(If there is already a docker network of 172.18.0.0/16 in your environment, delete it at first)
Otherwise, you will encounter the error below:
 ✘ Network csc2024-project1-docker_IPSec  Error                                                                    0.0s
failed to create network csc2024-project1-docker_IPSec: Error response from daemon: Pool overlaps with other one on this address space
```bash
sudo docker compose -f csc2024-project1-docker-compose.yml up -d
```


## Usage

### Run the server

In the server container,

run the server with
```bash
docker exec -it server bash
./server 1111
```

### Run the client

In the client container,

run the client with
```bash
docker exec -it client bash
./client 172.18.100.254 1111 2222
```

### Run the hijacking tool

In the client container,

create the hijacking tool,

and run the hijacking tool with
```bash
docker exec -it client bash
make
./hijack eth0
```

### Stop and remove the containers

Remove the docker network (csc-project1-docker_IPSec) 

and the client/server containers with 
```bash
sudo docker compose -f csc2024-project1-docker-compose.yml down
```

### Remove the image

Remove the docker image (csc2024-project1) with
```bash
docker rmi csc2024-project1
```

### Restart the container 

If the container exited after rebooting,
restart the container with
```bash
docker restart $container_name
```

## Environment

### IP address

In the default setting of the docker-compose, 
- ip of server is 172.18.100.254:1111
- ip of client is 172.18.1.1:2222
- external port to access SSH in the server is 3333
- external port to access SSH in the client is 4444 

### Configuration
The script "csc2024-project1/scripts/config.sh" will depend on the setting of the docker-compose
