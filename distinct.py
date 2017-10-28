#!/usr/bin/env python
"""
Distinct

Find potential Indicators of Compromise among similar Linux servers.
"""

import os
import argparse
from paramiko import client
from collections import OrderedDict
from collections import defaultdict
from functools import reduce


def find_file_cmd(path, startDate, endDate):
    cmd = "find " + path + " -xdev -type f"

    if startDate:
        cmd += " -newerct "+startDate

    if endDate:
        cmd += " ! -newerct "+endDate

    cmd += " -exec ls -l {} \;"
    return cmd

def find_listening_cmd():
    cmd = "netstat -tulpn"
    return cmd

def find_proc_cmd():
    cmd = "ps aux"
    return cmd

def find_critical_bin_cmd():
    commands_to_check = [ "ifconfig", "find", "ps", "netstat", "vim" ]

    cmd = "md5_cmd=`which md5sum`; "
    for bin in commands_to_check: 
        cmd += bin+"_cmd=`which " + bin + "`; "
    
    cmd += "$md5_cmd "
    for bin in commands_to_check:
        cmd += "$" + bin + "_cmd " 

    return cmd
    

def execute(conn, cmd, output, sudo):
    output = open(output, "a") 

    if sudo:
        cmd = "sudo " + cmd

    print("Executing {}".format(cmd))
    stdin, stdout, stderr = conn.exec_command(cmd)

    content = '\n'.join(map(lambda l: server + "\t" + l, stdout.read().splitlines()))
    output.write(content)
    output.write("\n")

    output.close()


def filter_uniq(numServers, concatfile, result, splitfn=None, whitelist=None):
    counter = OrderedDict()
    posdc = defaultdict(list)
    machine_count = 0
    copy = lambda v: v
    splitfn = copy if splitfn is None else splitfn
    whitelist = list() if whitelist is None else whitelist
    
    with open(concatfile) as fs:
        lines = list(map(lambda line: line.strip(), fs.readlines()))
        lines = filter(lambda line: line.strip(), lines)
        columns = list(map(lambda l: splitfn(l.split("\t")[-1]), lines))
        icolumns = sorted(enumerate(columns), key=lambda t: t[-1])

    for i, cmd in icolumns:
        counter[cmd] = counter.get(cmd, 0) + 1
        posdc[cmd].append(i)

    result_file = open(result, "w")
    for line_num in reduce(lambda a, b: a+b, [posdc[cmd] for cmd, count in counter.items() if count < numServers], []):
        line = lines[line_num] 
        if not any(map(lambda v: v in line, whitelist)):
            print(line)
            result_file.write(line+'\n')
    
    result_file.close()
    return result


def get_arguments():
    parser = argparse.ArgumentParser(prog='distinct')
 
    parser.add_argument('-f', type=str, help='F is path of the file with the list of servers to be analyzed;', required=True, nargs=1)
    parser.add_argument('-k', type=str, help='K is the path of the private key for the SSH public key authentication;', required=False, nargs=1)
    parser.add_argument('-u', type=str, help='U is the username to be used on the SSH connection;', required=True, nargs=1)
    parser.add_argument('-o', type=str, help="Optional output path. The default is 'output';", default="output")

    parser.add_argument('--files', action='store_true', help='Switch to enable file list comparison. It supports these option additional arguments')
    parser.add_argument('--path', type=str,default="/", help='Specify the find path (i.e: /var/www);')
    parser.add_argument('--startDate', type=str, help='Initial date of the time range filter based on the file time criation/modification time;')
    parser.add_argument('--endDate', type=str, help='Final date of the time range filter based on the file time criation/modification time;')

    parser.add_argument('--listening', action='store_true', help='Switch to enable listening services comparison;')
    parser.add_argument('--proc', action='store_true', help='Switch to enable proc list comparison;')
    parser.add_argument('--criticalbin', action='store_true', help='Switch to enable critical binaries (find, ps and netstat) MD5 hash comparison;')
    parser.add_argument('--whitelist', type=str, help='a file with a wordlist (one per line) to be excluded from the comparisons;')
    parser.add_argument('--sudo', action='store_true', help="Use 'sudo' while executing commands on remote servers")

    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = get_arguments()

    key = args.k[0]
    serverlist = args.f[0]
    username=args.u[0]
    whitelist=args.whitelist
    k = client.RSAKey.from_private_key_file(key)
    conn = client.SSHClient()
    conn.set_missing_host_key_policy(client.AutoAddPolicy())
    outputdir = args.o
    sudo = False
    sudo = args.sudo

    try:
        os.stat(outputdir)
    except:
        os.makedirs(outputdir)

    with open(serverlist) as f:
        content = f.readlines()

    if whitelist:
        with open(whitelist) as w:
            whitelist = list(map(lambda l: l.strip(), w.readlines()))
    
    servers = [x.strip() for x in content]    

    outputFindFile = outputdir + "/findFile.txt"
    open(outputFindFile, "w").close()
    outputFindListening = outputdir + "/findListening.txt"
    open(outputFindListening, "w").close()
    outputFindProc = outputdir + "/findProc.txt"
    open(outputFindProc, "w").close()
    outputCriticalBin = outputdir + "/criticalBin.txt"
    open(outputCriticalBin, "w").close()

    result_find_file = outputdir + "/uncommon_files.txt"
    result_find_listening = outputdir + "/uncommon_listening.txt"
    result_find_proc = outputdir + "/uncommon_proc.txt"
    result_find_critical_bin = outputdir + "/uncommon_bin_hashes.txt"

    for server in servers:
        print("connecting to ", server)
        conn.connect( hostname = server, username = username, pkey = k )
        print("connected")

        if (args.criticalbin):
            execute(conn, find_critical_bin_cmd(), outputCriticalBin, sudo)
        
        if (args.files):
            execute(conn, find_file_cmd(args.path, args.startDate, args.endDate), outputFindFile, sudo)

        if (args.listening):
            execute(conn, find_listening_cmd(), outputFindListening, sudo)
        
        if (args.proc):
            execute(conn, find_proc_cmd(), outputFindProc, sudo)

        conn.close()

    print("\n")
    if (args.criticalbin):
        print("CRITICAL BINARIES COMPARISION:\n")
        filter_uniq(len(servers), outputCriticalBin, result_find_critical_bin, lambda v: v.split(" ")[0], whitelist=whitelist)
        print("\n")

    if (args.files):
        print("UNCOMMON FILES:\n")
        filter_uniq(len(servers), outputFindFile, result_find_file, lambda v: v.split(" ")[-1], whitelist=whitelist)
        print("\n")
    
    if (args.listening):
        print("UNCOMMON LISTENING PROCESSES:\n")
        filter_uniq(len(servers), outputFindListening, result_find_listening, lambda v: v.split("/")[-1], whitelist=whitelist)
        print("\n")
    
    if (args.proc):
        print("UNCOMMON PROCESSES:\n")
        filter_uniq(len(servers), outputFindProc, result_find_proc, lambda v: v.split()[10], whitelist=whitelist)
        print("\n")
