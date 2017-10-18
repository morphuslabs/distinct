# Distinct
A simple script to look for potential Indicators of Compromise among similar Linux servers.

Distinct's approach consists in comparing some characteristics of a group of similar servers do detect the outliers, that is, those that do not follow "the pattern" and may have been compromised. The compared characteristics for this first version are: list of files, list of listening services and list of processes. It may be useful as a primary source of suspicious indicators to be analyzed while responding to an incident, especially when there isn’t file integrity monitor or other HIDS features in place.

It is important mentioning that having no indication of anomalous files or processes detected by Distinct, does not mean that there is no breached server. An attacker may delete its track and/or use kernel level rootkits to hide processes from tools like “ps” and “netstat”– even the legitimate ones. 

I hope the tool may be useful for other people within similar hunting scenarios or even for system administrators willing to find configuration errors on a bunch of servers. Feel free to extend the tool to support other comparisons, like system users and, who knows, to support analyzing Windows Servers.

## Hot it works

First, the tool receives a list of servers as input and performs the following information gathering tasks through remote SSH command execution:

-	With “find”, it lists file paths to be compared. It supports a time range filter based on creation and modification file time;
-	With “ps”, it lists all running applications and its parameters;
-	With “netstat”, it lists all listening network ports on the server;
-	As “find”, “ps” and “netstat” commands may have been modified by an attacker, there is another option to compare the tools hashes among servers – following the same approach;
-	Additionally, the user may give a whitelist  parameter with a list of words that should be excluded from comparison. It is useful to avoid file names naturally different among servers (i.e.: access.log.2017100301.gz into the /var/log path).

Then, it basically compares the results by sorting the lists and counting the items (file paths, listening services and running applications) repetitions. The items with a repetition count smaller them the number of compared servers, indicates that a given item is anomalous and, thus, must be investigated. For example, a file like /var/www/a.php present in one of, let’s say, 100 servers will have a count of 1 and, therefore, will appear on the output. The same will occur for uncommon listening services and processes. 

## Install

```
git https://github.com/morphuslabs/distinct.git
pip install paramiko
```

## Example

Looking for uncommon files on a given path, created or modified on a given period, on a group of servers:

```
python distinct.py -f serverlist.txt -f serverlist.txt -u ssh-user -k sshkey.pem --files --path=/var --startDate=2017-10-01 --endDate=2017-10-19 --whitelist=whitelist.txt
```

## Credits
Original idea and script from Morphus Labs (morphuslabs.com)

Team: @renato_marinho, @italomaia



