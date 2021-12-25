#!/usr/bin/env python3

import argparse
import xml.etree.ElementTree as xml
import sqlite3
from os import _exit, remove, getenv # _exit to not trigger traceback
from os.path import exists
import sys
import traceback

database = getenv("NDB", default = "nSpection.db")

def create_db():
    try:
        hosts_table = """CREATE TABLE IF NOT EXISTS "hosts" (
            "ip"    TEXT NOT NULL UNIQUE,
            "hostname"      TEXT,
            "os"    TEXT,
            PRIMARY KEY("ip")
        );"""

        services_table = """CREATE TABLE IF NOT EXISTS "services" (
            "ip"    TEXT,
            "port"  INTEGER NOT NULL,
            "service"      TEXT,
            "script-results"        BLOB,
            "protocol"      TEXT DEFAULT 'tcp',
            FOREIGN KEY("ip") REFERENCES "hosts"("ip") on delete cascade,
            PRIMARY KEY("ip","port","protocol")
        );"""

        con = sqlite3.connect(database)
        cur = con.cursor()

        cur.execute(hosts_table)
        cur.execute(services_table)

        con.commit()
        con.close()

        print(f"[+] {database} created")
    except Exception as e:
        print(f"[!] Could not create {database}")
        print(e)
        exit(1)

def check_file(file, type = "file"):
    if not exists(file):
            print(f"[!] The {type} file \"{file}\" does not exist.")
            _exit(1)

def get_info(db, info = False):
    check_file(database, "database")
    con = sqlite3.connect(db)
    cur = con.cursor()
    host_count = 0

    for row in cur.execute("SELECT * from hosts order by ip").fetchall():
        host_count += 1
        ports = ""
        ip = row[0]
        host = row[1]
        os = row[2]
        count = 0
        for p in cur.execute(f"SELECT port from services where ip = '{ip}'"):
            count += 1
            ports += str(p[0]) + ", "
        print(f"\t[+] Host: {ip:16} {str(count):3} port(s)")
        if info:
            ports = ports.strip(", ")
            print(f"\t\tHostname: [{host}] \tOS: {os}")
            print(f"\t\tPort(s): {ports}")

    print(f"[ {db} ] - {str(host_count)} hosts")
    con.close()

def query_db(args):
    check_file(database, "database")

    if args.simple:
        if args.port or args.service or args.sort != "ip" or args.extended:
            print("[!] '--simple' is not compatible with other options")
            _exit(1)

    con = sqlite3.connect(database)
    cur = con.cursor()
    cur2 = con.cursor()
    cur3 = con.cursor()

    #if args.ip or args.port or args.service:
    host = port = svc = ""
    stmt = f"SELECT * from services where 1"
    sort = args.sort

    if args.ip:
        hosts = args.ip.replace("*","%").split(',')
        if len(hosts) == 1:
            host = "ip like '" + hosts[0] +"'"
        else:
            for h in hosts:
                host += "ip like '"+ h + "' or "
            host = host[:-4]
        stmt += f" and ({host})"

    if args.port:
        if not args.port.replace(",","").replace(" ","").replace("-", "").isdecimal():
            print("[!] Error in the port(s) specified! ")
            _exit(1)

        ports = [] 
        for p in args.port.split(','):
            if "-" in p.strip(): ports.extend(range(int(p.split("-")[0]), int(p.split("-")[1]) + 1))

            else:
                ports.append(str(p.strip()))

        if len(ports) == 1:
            port = "port = " + str(ports[0])

        else:
            for p in ports:
                port += "port = "+ str(p) + " or "
            port = port[:-4]
        stmt += f" and ({port})"

    if args.service:
        services = args.service.split(',')
        if len(services) == 1:
            svc = "service like '%"+ services[0] + "%'"
        else:
            for s in services:
                svc += "service like '%"+ s + "%' or "
            svc = svc[:-4]
        stmt += f" and ({svc})"

    query = cur.execute(stmt + f" order by {sort}")
    toggle = True

    try:
        rows = 0
        new_ip = old_ip = ports = ""
        for row in query:
            rows += 1
            output = ""

            ports = "\tPort: "

            if toggle:
                os = cur2.execute(f"SELECT os from hosts where ip = '{row[0]}'").fetchone()[0]
                os = "OS: [" + os + "]" if os != None else ""
                hostname = cur3.execute(f"SELECT hostname from hosts where ip = '{row[0]}'").fetchone()[0]
                hostname = "Hostname: [" + hostname + "] " if hostname != None else ""
                new_ip = row[0]

                if new_ip != old_ip:
                    output += f"[+] Host:\t{row[0]} \t {hostname} {os}" if row[0] != None else ""
                toggle = False if ((args.ip and len(args.ip.split(",")) == 1) and '%' not in args.ip) else True
            protocol = f"/{row[4]}" if row[4] != None else ""
            if not args.simple:
                output += f"\n\tPort:\t {row[1]}{protocol}" if row[1] != None else ""
                output += f"\n\tService:\t {row[2]}\n" if row[2] != None else ""
            else:
                ports += f"{str(row[1]).strip()}{protocol.strip()}" if row[1] != None else ""
            if args.extended:
                output += f"\tScript Output:\n{row[3]}\n" if row[3] != None else ""


            old_ip = new_ip if new_ip != old_ip else old_ip

            if output != "": print(output)
            if args.simple:
                print(ports)

        print("[ "+ database + " ] - " + str(rows) + " ports returned!")
    except Exception:
        traceback.print_exc()
    con.close()

def parse_nmap(args):
    if args.create:
        if exists(database):
            if not args.force:
                print("[!] Database already exists. Use the '--force' option to overwrite it.")
                _exit(1)
            else: remove(database)
        create_db()

    nmap = args.file
    check_file(database,"database")
    check_file(nmap, "nmap")

    print(f"[+] Parsing {nmap}...")

    tree = xml.parse(nmap)
    root = tree.getroot()

    for host in root.findall("host"):
        try:
            #hosts table stuff
            ip = str(host.find("address").get("addr", default = "N/A")) if host.find("address") != None else "N/A"
            hostname = str(host.find("hostnames").find("hostname").get("name", default = "N/A")) if (host.find("hostnames") != None and host.find("hostnames").find("hostname") != None) else "N/A"
            os = "Likely " + host.find("os").find("osmatch").get("name", default = "not found during scan") if (host.find("os") != None and host.find("os").find("osmatch") != None) else "Likely not found during scan"
            
            #services & ports - This is a list of Elements
            ports = host.find("ports").findall("port") if host.find("ports") != None else []

            #Write stuff to the database
            con = sqlite3.connect(database)
            cur = con.cursor()
            try:
                cur.execute("Insert into hosts(ip, hostname, os) values (?,?,?)",(ip, hostname, os))
            except sqlite3.IntegrityError:
                pass


            #parse service information
            if len(ports) > 0:
                for port in ports:
                    #service info
                    name = "[" + port.find("service").get("name", default = "")  + "]" if port.find("service") != None else "[N/A]"
                    product = " " + port.find("service").get("product", default = "") if port.find("service") != None else ""
                    extrainfo = " " + port.find("service").get("extrainfo", default = "") if port.find("service") != None else ""
                    version = " " + port.find("service").get("version", default = "") if port.find("service") != None else ""
                    service = name + product + version + extrainfo

                    #script results
                    scriptinfo = ""
                    if port.findall("script"):
                        for scripts in port.findall("script"):
                            scriptinfo += "\t\t" + scripts.get("id") + ":\n\t\t\t" + scripts.get("output").strip().replace('\n','\n\t\t') + "\n"
                    else: scriptinfo = "\t\tN/A"

                    #protocol
                    protocol = port.get("protocol")

                    try:
                        cur.execute(r"Insert into services values (?,?,?,?,?)",(ip.strip(), port.get("portid").strip(), service.strip(), scriptinfo.strip('\n'), protocol.strip()))
                    except sqlite3.IntegrityError:
                        pass

            else: 
                pass

            con.commit()
            con.close()
        except Exception:
            traceback.print_exc()

def main():
    global database

    parser = argparse.ArgumentParser(description="A tool to parse XML-formatted Nmap scan results, and store the results in a queryable database. ")
    parser.add_argument("-i", "--info", action="store_true", help="Get quick info from the database, and include open ports.")
    parser.add_argument("-d", "--database", metavar=database, help="The SQLite database file to use if not the default. Can alternately be set in the 'NDB' environment variable.", default=database)
    parser.set_defaults(func=get_info)
    
    subparsers = parser.add_subparsers(title = "Sub-commands", required = False, dest="cmdname")
    
    query_data = subparsers.add_parser("query", aliases = ['q'], help = "Query the database.")
    query_data.add_argument("-i","--ip", "--host", help = "Comma-seperated IP(s) to search for. Use '%%' to use a wildcard.")
    query_data.add_argument("-p", "--port", help = "Comma-seperated port(s) to search for. Also supports ranges.")
    query_data.add_argument("-s", "--service", help = "Comma-seperated service(s) to search for. This is a wildcard search.")
    query_data.add_argument("--sort", choices = ["ip", "service","port","protocal"], default = "ip", help = "Field to sort by. Default is port.")
    query_data.add_argument("--simple", help = "Print just the host info and its ports.", action = "store_true")
    query_data.add_argument("--extended", "-e", help = "Print script info.", action = "store_true")
    query_data.set_defaults(func = query_db)

    add_data = subparsers.add_parser("parse", aliases = ['p'], help = "Parse an nmap file into the database.")
    add_data.add_argument("-c", "--create", action="store_true", help="Create the database if it does not exist. Will also overwrite an existing database.")
    add_data.add_argument("-f", "--file", metavar="nmap.xml", help="The name of the nmap file in XML format.", required=True)
    add_data.add_argument("--force", help = "Overwrite existing database.", action = "store_true")
    add_data.set_defaults(func = parse_nmap)

    args = parser.parse_args()
 
    database = args.database

    print("[ "+ database + " ]")
    if args.info:
        get_info(database, info = True)
    
    else:
        if args.cmdname == None:
            get_info(database, info=False)
        else:
            try:
                args.func(args)
            except:
                traceback.print_exc()

main()