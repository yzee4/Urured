# Dustox by Yzee4
#
# MIT License
#
# Copyright (c) 2023 Yzee4
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Code version BAGABU

# Import libraries
import os
import re
import sys
import time
import signal
import shutil
import argparse
import threading
import subprocess

# Define colors
class Colors:
    WHITE = '\033[0;97m'
    LIGHT_RED = '\033[0;91m'
    LIGHT_GREEN = '\033[0;92m'
    LIGHT_BLUE = '\033[0;94m'
    YELLOW = '\033[0;93m'
    PINK = '\033[0;95m'
    CYAN = '\033[0;96m'
Colors()

# Check user mode
def verify_root():
    global root
    if os.geteuid() != 0:
        root = None
    else:
        root = True
verify_root()

# Check required tools
def check_tool_installed(tool_name):
    return shutil.which(tool_name) is not None

def initializing_dustox():
    tools_to_check = ['nmap', 'ip']
    not_installed_tools = [tool for tool in tools_to_check if not check_tool_installed(tool)]
    
    if not_installed_tools:
        for tool in not_installed_tools:
            print(f"{Colors.LIGHT_RED}> {Colors.YELLOW}{tool} {Colors.WHITE}not installed. To install, use {Colors.LIGHT_GREEN}'pkg install {tool}'{Colors.WHITE}")
            sys.exit(0)
initializing_dustox()

# Interface
def MainMenu():
    global interface
    interface = f"""{Colors.WHITE}Urured {Colors.WHITE}- {Colors.LIGHT_GREEN}Open {Colors.WHITE}Port {Colors.WHITE}Scanner{Colors.WHITE}
{Colors.LIGHT_RED}-| {Colors.WHITE}GitHub {Colors.LIGHT_GREEN}https://github.com/yzee4/Urured{Colors.WHITE}\n
{Colors.LIGHT_RED}            ████                            
           █████████                        
           ████████████                     
            ███████████████                 
             █████████████████              
            ████████████████████            
           ████████████████████████         
           ████████████████████████         
   ██████  █████████████████████████        
  ████████████████████████████████████      
 ██████████████████████████████████████     
 ███    █████ ███████████████████████████   
 ██            ████████████████████████████ 
               ██████████████████████████ █ 
 [ {Colors.WHITE}Urured{Colors.LIGHT_RED} ]    ███████████████████████████  
               █████████████████████████    
               ████    ████   █████████ █   
             ██         ███     ████████ █  
     ████████████  ███████        ████████  
                                   ██ █  ██ {Colors.WHITE}"""                                           
    global main_scans
    main_scans = f""" 1 {Colors.LIGHT_RED}* {Colors.WHITE}Local IP address
 2 {Colors.LIGHT_RED}* {Colors.WHITE}Specified IP address
 3 {Colors.LIGHT_RED}* {Colors.WHITE}Info
"""

MainMenu()

# Principal scanning logic
def scan_network():
    print(f"\n{Colors.LIGHT_RED}> {Colors.WHITE}Scanning...")
    # --localnet flag
    if localnet:
        result = subprocess.run("ip route | grep -oP 'src \K\S+' | head -n 1", shell=True, capture_output=True, text=True)
        local_ips = result.stdout.splitlines()
        if len(local_ips) == 0:
            print(f"{Colors.LIGHT_RED}> {Colors.WHITE}Failed to scan local network ip")
            sys.exit(0)
        local_ips_with_subnet = [ip + "/24" for ip in local_ips]
        command_list.append(*local_ips_with_subnet)
    
    if root:
        command = ['nmap', '-O', '-open','-T5', *command_list]
    else:
        command = ['nmap', '-open','-T5', *command_list]

    # -ip flag
    try:
        repeatcounter = 1
        for _ in range(repeat):
            global started_time
            startedlocaltime = time.localtime()
            started_time = (time.strftime("%H:%M:%S", startedlocaltime))

            # Nmap command
            with open('/dev/null', 'w') as null_file:
                nmap_output = subprocess.check_output(command, universal_newlines=True, stderr=null_file)
            paragraphs = re.split(r'\n(?=Nmap scan report)', nmap_output)
            ip_address = None
            num_ips_scanned = 0
            num_ports_scanned = 0

            if paragraphs:
                if repeat > 1:
                    if repeat == repeatcounter:
                        print(f"{Colors.LIGHT_GREEN}> {Colors.WHITE}Repeat counter {Colors.LIGHT_GREEN}({repeatcounter}/{repeat})")
                    else:
                        print(f"{Colors.LIGHT_GREEN}> {Colors.WHITE}Repeat counter {Colors.YELLOW}({repeatcounter}/{repeat})")
            # Extracting ip info    
            for paragraph in paragraphs:
                match_ip = re.search(r'Nmap scan report for (\S+)(?: \(([\d\.]+)\))?', paragraph)
                match_ports = re.finditer(r'(\d+/[a-zA-Z-0-9]+)\s+(open)\s+([a-zA-Z-0-9]+)', paragraph)
                match_mac = re.search(r'MAC Address: ([0-9A-F:]+) \((.*?)\)', paragraph)
                match_host = re.search(r"Note: Host seems down", paragraph)
                match_os = re.search(r'OS details: (.+)', paragraph)

                if match_host:
                    print(f"\n{Colors.LIGHT_GREEN}----| IP: {Colors.WHITE}") 
                    print(f"{Colors.LIGHT_RED}> {Colors.WHITE}No response")

                if match_ip:
                    host_name = match_ip.group(1)
                    ip_address = match_ip.group(2)
                    if ip_address:
                        print(f"\n{Colors.LIGHT_GREEN}----| IP: {Colors.WHITE}{ip_address} ({host_name})")
                    else:
                        print(f"\n{Colors.LIGHT_GREEN}----| IP: {Colors.WHITE}{host_name}")

                    for match in match_ports:
                        found_port = True

                    if match_os:
                        os = match_os.group(1)
                    else:
                        if not root:
                            os = f"{Colors.LIGHT_RED}Need root mode"
                        if root:
                            os = f"{Colors.LIGHT_RED}Not accessible"

                    if match_mac:
                        mac = match_mac.group(1)
                        name = match_mac.group(2)
                    else:
                        if not root:
                            mac = f"{Colors.LIGHT_RED}Need root mode"
                            name = f"{Colors.LIGHT_RED}Need root mode"
                        if root:
                            mac = f"{Colors.LIGHT_RED}Not accessible"
                            name = f"{Colors.LIGHT_RED}Not accessible"

                    print(f"""{Colors.LIGHT_GREEN}NAME: {Colors.WHITE}{name}\n{Colors.LIGHT_GREEN}MAC:  {Colors.WHITE}{mac}\n{Colors.LIGHT_GREEN}OS:   {Colors.WHITE}{os}""")

                    if found_port:
                        print(f"{Colors.LIGHT_GREEN}PORT     {Colors.LIGHT_GREEN}SERVICE")

                        match_ports = re.finditer(r'(\d+/[a-zA-Z-0-9]+)\s+(open)\s+([a-zA-Z-0-9]+)', paragraph)
                        for match in match_ports:
                            num_ports_scanned += 1
                            port = match.group(1).split("/")[0]
                            service = match.group(3)

                            chars_to_add = max(0, 9 - len(port))
                            port = port + f"{Colors.YELLOW} " * chars_to_add
                            print(f"{Colors.WHITE}{port}{Colors.YELLOW}{Colors.WHITE}{service}")
                            
                    # Not found open ports
                    else:
                        if num_ips_scanned > 0:
                            print(f"{Colors.LIGHT_RED}> {Colors.WHITE}No open ports")
                    num_ips_scanned += 1
                    
            # Extracting scanning time
            if "Nmap done" in paragraph:
                endlocaltime = time.localtime()
                end_time = (time.strftime("%H:%M:%S", endlocaltime))
                match_time = re.search(r'in (\d+\.\d+) seconds', paragraph)
                if match_time:
                    total_scan_time = match_time.group(1)
                    if num_ips_scanned == 0:
                        print(f"\n{Colors.LIGHT_RED}> {Colors.WHITE}No results for the search. Try again or change some options")
                        print()
                        input(f"{Colors.WHITE}Enter any key for back {Colors.LIGHT_RED}> {Colors.WHITE}")
                        main()
                    if num_ips_scanned > 1:
                        show_ip_word = "addresses"
                    else:
                         show_ip_word = "address"
                    if num_ports_scanned > 1:
                        show_port_word = "ports"
                    else:
                        show_port_word = "port"
                    print(f"""\n{Colors.LIGHT_GREEN}{num_ips_scanned} IP {show_ip_word} and {num_ports_scanned} {show_port_word} found
in {total_scan_time} seconds between {started_time}...{end_time}\n""")
            repeatcounter += 1

    except subprocess.CalledProcessError as e:
        print(f"{Colors.LIGHT_RED}> {Colors.WHITE}Unknown error: {str(e)}")
    except KeyboardInterrupt:
        print(f"\n{Colors.LIGHT_RED}> {Colors.WHITE}Scan interrupted\n")
        main()
    finally:
        signal.alarm(0)
    try:
        input(f"{Colors.WHITE}Enter any key for back {Colors.LIGHT_RED}> {Colors.WHITE}")
        main()

    except KeyboardInterrupt:
        print(f"\n\n{Colors.WHITE}Copyright (c) 2023 Yzee4")
        sys.exit()

# Check valid flags
def is_valid_ip(argsip):
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if argsip == '0.0.0.0':
        return False
    if re.match(ip_pattern, argsip):
        parts = argsip.split('.')
        for part in parts:
            if not (0 <= int(part) <= 255):
                return False
        return True

def is_valid_port(argsport):
    try:
        port = int(argsport)
        if 1 <= port <= 65535:
            return True
    except ValueError:
        return False
   
# Flags management
def main():
    subprocess.run("clear")
    print(f"{interface}")
    argsip = None
    argsport = None
    rangeip = None
    global localnet 
    localnet = None
    global repeat
    repeat = 1
    global timescan
    timescan = None
    global command_list
    command_list = []

    try:
        print(f"{main_scans}")
        userselect = input(f"Select option {Colors.LIGHT_RED}>{Colors.WHITE} ")

        # Local IP address
        if userselect == "1":
            localnet = True

            userselect = input(f"Set a specified port? [Y/n] {Colors.LIGHT_RED}>{Colors.WHITE} ")
            if userselect == "Y" or userselect == "y":
                argsport = input(f"Set port {Colors.LIGHT_RED}>{Colors.WHITE} ") 
            
            elif userselect == "N" or userselect == "n":
                pass

            else:
                print(f"{Colors.LIGHT_RED}> {Colors.WHITE}Invalid option")
                time.sleep(0.15)
                main()

        # Specified IP address
        elif userselect == "2":
            argsip = input(f"Set IP address {Colors.LIGHT_RED}>{Colors.WHITE} ") 

            userselect = input(f"Scans all ranges? [Y/n] {Colors.LIGHT_RED}>{Colors.WHITE} ")
            if userselect == "Y" or userselect == "y":
                rangeip = True
            
            elif userselect == "N" or userselect == "n":
                pass

            else:
                print(f"{Colors.LIGHT_RED}> {Colors.WHITE}Invalid option")
                time.sleep(0.15)
                main()

            userselect = input(f"Set a specified port? [Y/n] {Colors.LIGHT_RED}>{Colors.WHITE} ")
            if userselect == "Y" or userselect == "y":
                argsport = input(f"Set port {Colors.LIGHT_RED}>{Colors.WHITE} ") 
            
            elif userselect == "N" or userselect == "n":
                pass

            else:
                print(f"\n{Colors.LIGHT_RED}> {Colors.WHITE}Invalid option")
                time.sleep(0.15)
                main()

        elif userselect == "3":
            print(f"""
Coded by yzee4
Version 1.0.0 (Dustox alternative version)

{Colors.LIGHT_GREEN}Urured is a simple open port scanner, with it you can see all
Open ports of local or specified IP address. It features some filters 
that make your search easier. Its interface facilitates the 
visualization of information, as it is simple and contains 
elements that facilitate the interpretation of results
              
{Colors.WHITE}For more information visit project documentation on GitHub\n""")
        
            input(f"{Colors.WHITE}Enter any key for back {Colors.LIGHT_RED}> {Colors.WHITE}")
            main()

        else:
            print(f"\n{Colors.LIGHT_RED}> {Colors.WHITE}Invalid option")
            time.sleep(0.15)
            main()

        # Variables validation
        if argsip:
            if argsip and not is_valid_ip(argsip):
                print(f"\n{Colors.LIGHT_RED}> {Colors.WHITE}Invalid IP address format")
                time.sleep(0.5)
                main()
            if rangeip:
                command_list.append(argsip+"-255")
            else:
                command_list.append(argsip)        
        if argsport:
            if argsport and not is_valid_port(argsport):
                print(f"\n{Colors.LIGHT_RED}> {Colors.WHITE}Invalid port format")
                sys.exit()
            command_list.append(f"-p {argsport}")

        scan_network()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WHITE}Copyright (c) 2023 Yzee4")
        sys.exit()
main()
