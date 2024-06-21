# CSC Project4 - Capture The Flag (CTF)

> practice server ip : 140.113.24.241   
> demo server ip : 140.113.207.231    
> server port:

|   Task   | Prob name       | score | server port  |  
|----------|-----------------|-------|--------------|   
| Task I-1   | Flag Shop       | (20%) | port : 30170 |    
| Task I-2   | Magic           | (20%) | port : 30171 |   
| Task I-3   | Ret2libc        | (20%) | port : 30173 |   
| Task I-4   | Matryoshka Doll | (20%) | locally solve |   
| Task II-1  | FMT             | (10%) | port : 30172 |  
| Task II-2  | Hello System    | (10%) | port : 30174 |   

### The docker commands  

> The `Dockerfile` is come from INP, replace all **clai** into your username, replace **sense** into your password  
> **The docker environment is not same as the server**
```bash
docker network prune
sudo docker-compose up -d --build
sudo ssh -p 22222 clai@localhost
```

### 解題思路
 
- Task I-1:       
> `int total_price = price * amount;`   
> sol : make the tot_price overflow    

- Task I-2:      
> write a C++ program and use **same random seed** with server     

- Task I-3:     
> **Learn from TwinkleStar03**     
> 1. stack pivot to setvbuf 下面, 再跳回 hackMe       
> 2. 將 ROP chain 寫入 step 1 動過的 stack, 再將 stack pivot to setvbuf     
> 3. 修改 setvbuf.GOT  為 puts@plt      
> 4. 修改 FILE * stdin 為 read@got （FILE * stdin 是 setvbuf 的第一個參數）     
> 5. call setvbuf (puts) in main -> leak libc base address of read        
> 6. 因為 stack 的 RBP, RSP chain 壞了，所以要 Make execve('/bin/sh', 0, 0) (system() 會檢查 stack)    
    
- Task I-4:    
> Magic number of JPG: `ffd8 ffe0`    
> Magic number of PNG: `8950 4e47 0d0a 1a0a`    
> split the PNG file out of Matryoshka dolls.jpg -> get flag    

- Task II-1:    
> printf epolit    
> type input as b'%xx$p' (xx is a number) each has 8 bytes    
> And run a loop on xx to print out the data in stack    
> In this prob, the flag array is at (%10$p ~ %14$p)     
 
- Task II-2:    
> 1. use gdb attach on the pwn program    
> 2. buffer overflow leak canary (use `canary -a` in gdb)     
> 3. buffer overflow leak libc address    
> 4. use gadget in libc to construct ROP chain   
