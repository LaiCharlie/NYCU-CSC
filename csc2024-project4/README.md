# CSC Project4 - Capture The Flag (CTF)

> server ip : 140.113.24.241
> server port:
            ⚫Task I-1: Flag Shop       (20%) port : 30170  
            ⚫Task I-2: Magic           (20%) port : 30171  
            ⚫Task I-3: Ret2libc        (20%) port : 30173  
            ⚫Task I-4: Matryoshka Doll (20%) locally solve  
            ⚫Task II-1: FMT            (10%) port : 30172  
            ⚫Task II-2: Hello System   (10%) port : 30174  

### The docker commands  

> The `Dockerfile` is come from INP, replace all **clai** into your username, replace **sence** into your password  
> **The docker environment is not same as the server**
```bash
docker network prune
sudo docker-compose up -d --build
sudo ssh -p 22222 clai@localhost
```


Task I-1:
    int total_price = price * amount;
    sol : make the tot_price overflow

Task I-2:
    write a C++ file and use same seed with server

Task I-3:
    unsolve
    
Task I-4:
    Magic number of JPG: ffd8 ffe0
    Magic number of PNG: 8950 4e47 0d0a 1a0a
    split the PNG file out of Matryoshka dolls.jpg -> get flag

Task II-1:
    printf epolit
    type input as b'%xx$p' (xx is a number) each has 8 bytes
    And run a loop on xx to print out the data in stack
    In this prob, the flag array is at (%10$p ~ %14$p)

Task II-2:
    unsolve
