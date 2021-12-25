# nSpector
This tool was created so that NMAP scan results can be analyzed queried in a way similar to tools like Zenmap and Metasploit. Zenmap is no longer supported (python2), and Metasploit is a bit bulky just for this task.

## Requirements
- Python3
- NMAP scan results in XML format

## Usage
#### Without sub-commands
Running the tool without sub-commands will print basic information. Include the '-i' option to also print open ports.

```
nSpector.py [-h] [-i] [-d nSpection.db] {query,q,parse,p} ...

A tool to parse XML-formatted Nmap scan results, and store the results in a queryable database.

optional arguments:
  -h, --help            show this help message and exit
  -i, --info            Get quick info from the database, and include open ports.
  -d nSpection.db, --database nSpection.db
                        The SQLite database file to use if not the default. Can alternately be set in the 'NDB' environment variable.

Sub-commands:
  {query,q,parse,p}
    query (q)           Query the database.
    parse (p)           Parse an nmap file into the database.
```

#### parse sub-command
Supply an XML-formatted NMAP scan result to add it to the database.
```
nSpector.py parse [-h] [-c] -f nmap.xml [--force]

optional arguments:
  -h, --help            show this help message and exit
  -c, --create          Create the database if it does not exist. Will also overwrite an existing database.
  -f nmap.xml, --file nmap.xml
                        The name of the nmap file in XML format.
  --force               Overwrite existing database.
```

#### query sub-command
Query the database for different for different criteria.
```
nSpector.py query [-h] [-i IP] [-p PORT] [-s SERVICE] [--sort {ip,service,port,protocal}] [--simple] [--extended]

optional arguments:
  -h, --help            show this help message and exit
  -i IP, --ip IP, --host IP
                        Comma-seperated IP(s) to search for. Use '%' to use a wildcard.
  -p PORT, --port PORT  Comma-seperated port(s) to search for. Also supports ranges.
  -s SERVICE, --service SERVICE
                        Comma-seperated service(s) to search for. This is a wildcard search.
  --sort {ip,service,port,protocal}
                        Field to sort by. Default is port.
  --simple              Print just the host info and its ports.
  --extended, -e        Print script info.
```
## Installation Recommendation
```
cp ./nSpector.py ~/.local/bin/
chmod +x ~/.local/bin/
```

## TODO
[] Extend the results to show what scan found each host, "host scripts"
[] Create functionality to manually add and delete entries