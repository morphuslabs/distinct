"""
Mass Analyzer

Easely look up IOCs through machines.
"""

import os
import argparse
from paramiko import client
from collections import OrderedDict
from collections import defaultdict
from functools import reduce


def find_file_cmd(path, startDate, endDate):
    cmd = "sudo find " + path + " -xdev -type f"

    if startDate:
        cmd += " -newerct "+startDate

    if endDate:
        cmd += " ! -newerct "+endDate

    cmd += " -exec ls -l {} \;"
    return cmd


def find_listening_cmd():
    cmd = "sudo netstat -tulpn"
    return cmd


def find_proc_cmd():
    cmd = "sudo ps aux"
    return cmd


def find_critical_bin_cmd():
    commands_to_check = ["ifconfig", "find", "ps", "netstat", "vim"]
    cmd = "md5_cmd=`which md5sum`; "

    for bin in commands_to_check:
        cmd += bin + "_cmd=`which " + bin + "`; "

    cmd += "$md5_cmd "

    for bin in commands_to_check:
        cmd += "$" + bin + "_cmd "

    return cmd


def execute(server, conn, cmd, output):
    """
    :param server: server name
    :param conn: connection
    :param cmd: command to be executed
    :param output: filepath to write output to
    """
    output = open(output, "a")

    print("Executing {}".format(cmd))
    stdin, stdout, stderr = conn.exec_command(cmd)

    columns = stdout.read().splitlines()
    content = '\n'.join(map(lambda l: server + "\t" + l, columns))
    output.write(content)
    output.write("\n")
    output.close()


def filter_uniq(numServers, concatfile, result, splitfn=None, whitelist=None):
    counter = OrderedDict()
    posdc = defaultdict(list)
    copy = lambda v: v  # noqa: E731
    splitfn = copy if splitfn is None else splitfn
    whitelist = list() if whitelist is None else whitelist

    with open(concatfile) as fs:
        lines = list(map(lambda line: line.strip(), fs.readlines()))
        lines = filter(lambda line: line.strip(), lines)
        columns = list(map(lambda l: splitfn(l.split("\t")[-1]), lines))
        icolumns = sorted(enumerate(columns), key=lambda t: t[-1])

    for i, cmd in icolumns:
        print("cmd = " + cmd)
        counter[cmd] = counter.get(cmd, 0) + 1
        posdc[cmd].append(i)

    result_file = open(result, "w")

    unusual = (
        posdc[cmd]
        for cmd, count in counter.items()
        if count < numServers)

    for line_num in reduce(lambda a, b: a+b, unusual, []):
        line = lines[line_num]

        if not any(map(lambda v: v in line, whitelist)):
            print(line)
            result_file.write(line+'\n')

    result_file.close()
    return result


def get_arguments():
    parser = argparse.ArgumentParser(prog='mass-analyzer')

    parser.add_argument(
        '-f',
        type=str,
        help="File with servers addresses",
        required=True,
        nargs=1)
    parser.add_argument(
        '-k',
        type=str,
        help="SSH 'pem' file",
        required=False,
        nargs=1)
    parser.add_argument(
        '-u',
        type=str,
        help="SSH username",
        required=True,
        nargs=1)
    parser.add_argument(
        '-o',
        type=str,
        help="Output dir",
        default="output")

    parser.add_argument(
        '--files',
        action='store_true',
        help='Search for uncommon files amongst servers')
    parser.add_argument(
        '--path',
        type=str, default="/")
    parser.add_argument(
        '--startDate',
        type=str, help='startDate help')
    parser.add_argument(
        '--endDate',
        type=str, help='endDate help')

    parser.add_argument(
        '--listening',
        action='store_true',
        help='Search for uncommon listening services amongst servers')
    parser.add_argument(
        '--proc',
        action='store_true',
        help='Search for uncommon processes')
    parser.add_argument(
        '--criticalbin',
        action='store_true',
        help='Compare critical binaries (ifconfig, find, ps, netstat) amongst servers')  # noqa
    parser.add_argument(
        '--whitelist', type=str, help='Exclude those itens from the list')

    args = parser.parse_args()
    return args


def validate_args(args, arg1, arg2):
    """
    Given arg2 was provided, verify that arg1 is also provided.

    :returns: None if validation does not make sense. True if
    validation passes; False, otherwise.
    """
    if arg1 in args:
        return arg2 in args


def main():
    args = get_arguments()

    key = args.k[0]
    serverlist = args.f[0]
    username = args.u[0]
    whitelist = args.whitelist
    k = client.RSAKey.from_private_key_file(key)
    conn = client.SSHClient()
    conn.set_missing_host_key_policy(client.AutoAddPolicy())
    outputdir = args.o

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

    outputFindFile = os.path.join(outputdir, "findFile.txt")
    outputFindListening = os.path.join(outputdir, "findListening.txt")
    outputFindProc = os.path.join(outputdir, "findProc.txt")
    outputCriticalBin = os.path.join(outputdir, "criticalBin.txt")

    result_find_file = os.path.join(outputdir, "uncommon_files.txt")
    result_find_listening = os.path.join(outputdir, "uncommon_listening.txt")
    result_find_proc = os.path.join(outputdir, "uncommon_proc.txt")
    result_find_critical_bin = os.path.join(outputdir, "uncommon_bin_hashes.txt")  # noqa: E501

    for server in servers:
        print("connecting to", server)
        conn.connect(hostname=server, username=username, pkey=k)
        print("connected")

        if (args.criticalbin):
            execute(
                server,
                conn,
                find_critical_bin_cmd(),
                outputCriticalBin)

        if (args.files):
            execute(
                server,
                conn,
                find_file_cmd(args.path, args.startDate, args.endDate),
                outputFindFile)

        if (args.listening):
            execute(
                server,
                conn,
                find_listening_cmd(),
                outputFindListening)

        if (args.proc):
            execute(
                server,
                conn,
                find_proc_cmd(),
                outputFindProc)

        conn.close()

    print("\n")
    if (args.criticalbin):
        print("CRITICAL BINARIES COMPARISION:\n")
        filter_uniq(
            len(servers),
            outputCriticalBin,
            result_find_critical_bin,
            lambda v: v.split(" ")[0],
            whitelist=whitelist)
        print("\n")

    if (args.files):
        print("UNCOMMON FILES:\n")
        filter_uniq(
            len(servers),
            outputFindFile,
            result_find_file,
            lambda v: v.split(" ")[-1],
            whitelist=whitelist)
        print("\n")

    if (args.listening):
        print("UNCOMMON LISTENING PROCESSES:\n")
        filter_uniq(
            len(servers),
            outputFindListening,
            result_find_listening,
            lambda v: v.split("/")[-1],
            whitelist=whitelist)
        print("\n")

    if (args.proc):
        print("UNCOMMON PROCESSES:\n")
        filter_uniq(
            len(servers),
            outputFindProc,
            result_find_proc,
            lambda v: v.split(" ")[-1],
            whitelist=whitelist)
        print("\n")


if __name__ == "__main__":
    main()