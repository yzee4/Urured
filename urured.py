# Dustox by yzee4
#
# MIT License
#
# Copyright (c) 2023 yzee4
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

# Code version QUI18JAN012024

# Import libraries
import os
import re
import sys
import time
import signal
import shutil
import readline
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

# Principal scanning logic
def scan_network():
    # --localnet flag
    if timescan != None:
        timescanvalue = int(timescan)
        if timescanvalue != None:
            def timer_to_scan(signum, frame):
                global stop_animation
                stop_animation = True
                print(f"\n{Colors.LIGHT_RED}> {Colors.WHITE}Time is over\n""")
                input(f"{Colors.WHITE}Enter any key for back {Colors.LIGHT_RED}> {Colors.WHITE}")
                main()
            signal.signal(signal.SIGALRM, timer_to_scan)
            signal.alarm(timescanvalue)

    if localnet:
        result = subprocess.run("ip route | grep -oP 'src \K\S+' | head -n 1", shell=True, capture_output=True, text=True)
        local_ips = result.stdout.splitlines()
        if len(local_ips) == 0:
            print(f"{Colors.LIGHT_RED}> {Colors.WHITE}Failed to scan local network ip")
            sys.exit(0)
        local_ips_with_subnet = [ip + "/24" for ip in local_ips]
        command_list.append(*local_ips_with_subnet)
    
    if root:
        command = ['nmap', '-O', '-open', '-T5', *command_list]
    else:
        command = ['nmap', '-open', '-T5', *command_list]

    # -ip flag
    try:
        repeatcounter = 1
        repeatvalue = int(repeat)
        for _ in range(repeatvalue):
            print(f"\n{Colors.LIGHT_RED}> {Colors.WHITE}Scanning...")
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
                if repeatvalue > 1:
                    if repeatvalue == repeatcounter:
                        print(f"{Colors.LIGHT_RED}> {Colors.WHITE}Repeat counter {Colors.LIGHT_GREEN}[{repeatcounter}/{repeatvalue}]")
                    else:
                        print(f"{Colors.LIGHT_RED}> {Colors.WHITE}Repeat counter [{repeatcounter}/{repeatvalue}]")
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
        main()

# Interface
def MainMenu():
    global interface
    interface = f"""{Colors.WHITE}Urured {Colors.WHITE}- {Colors.LIGHT_GREEN}Open {Colors.WHITE}Port {Colors.WHITE}Scanner{Colors.WHITE}
{Colors.LIGHT_RED}-| {Colors.WHITE}GitHub {Colors.LIGHT_GREEN}https://github.com/yzee4/Urured{Colors.WHITE}

     {Colors.LIGHT_RED}       █████████              ████              
     {Colors.LIGHT_RED}█████████████████        █████████████          
     {Colors.LIGHT_RED}███████████████████      █████████████████      
  {Colors.WHITE}U  {Colors.LIGHT_RED}███████████████████     ████████████████████    
     {Colors.LIGHT_RED}██████████████████     ███████████████████████  
     {Colors.LIGHT_RED}██████████████████    █████████████████████████ 
  {Colors.WHITE}R  {Colors.LIGHT_RED}████████████████████████████████████████████████
     {Colors.LIGHT_RED}████████████████████████████████████████████████
     {Colors.LIGHT_RED}█████████████████████████████████           ███ 
  {Colors.WHITE}U  {Colors.LIGHT_RED}███████████████████████████████                 
     {Colors.LIGHT_RED}██████████████████████████████                  
     {Colors.LIGHT_RED}███████████  ████████████████                   
  {Colors.LIGHT_RED}R  {Colors.LIGHT_RED}██████████     █████████████      {Colors.WHITE}coded by yzee4{Colors.LIGHT_RED}
     {Colors.LIGHT_RED}█████████       ██████████                      
     {Colors.LIGHT_RED}████████                                        
  {Colors.LIGHT_RED}E  {Colors.LIGHT_RED}███████      {Colors.WHITE}1 {Colors.LIGHT_RED}> {Colors.WHITE}Local IP address               
     {Colors.LIGHT_RED}██████       {Colors.WHITE}2 {Colors.LIGHT_RED}> {Colors.WHITE}Specified IP address           
     {Colors.LIGHT_RED}█████                                           
  {Colors.LIGHT_RED}D  {Colors.LIGHT_RED}████         {Colors.WHITE}3 {Colors.LIGHT_RED}> {Colors.WHITE}Options                        
     {Colors.LIGHT_RED}███          {Colors.WHITE}4 {Colors.LIGHT_RED}> {Colors.WHITE}Info                           
     {Colors.LIGHT_RED}██           {Colors.WHITE}5 {Colors.LIGHT_RED}> {Colors.WHITE}Exit                           
     {Colors.LIGHT_RED}█                                               {Colors.WHITE}
"""                                           
MainMenu()

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
    
def is_valid_repeat(repeat):
    try:
        repeat = int(repeat) 
        if 1 <= repeat <= 10:
            return True
    except ValueError:
        return False
    
def is_valid_timescan(timescan):
    try:
        timescan = int(timescan) 
        if 0 <= timescan:
            return True
    except ValueError:
        return False

def options():
    global repeat
    repeat = 1
    global timescan
    timescan = None 
options()

# Flags management
def main():
    subprocess.run("clear")
    print(f"{interface}")
    global menu
    menu = 1
    global repeat
    global timescan
    argsip = None
    argsport = None
    rangeip = None
    global localnet 
    localnet = None
    global command_list
    command_list = []

    
    try:
        userselect = input(f"""{Colors.LIGHT_RED}----| {Colors.WHITE}Select option {Colors.LIGHT_RED}>{Colors.WHITE} """)
    except KeyboardInterrupt:
        print(f"\n{Colors.WHITE}Copyright (c) 2023 Yzee4")
        sys.exit(0)

    try:
        # Local IP address
        if userselect == "1":
            localnet = True

            userselect = input(f"Set a specified {Colors.LIGHT_GREEN}port{Colors.WHITE}? [Y/n/c] {Colors.LIGHT_RED}>{Colors.WHITE} ")
            if userselect == "Y" or userselect == "y":
                argsport = input(f"Set {Colors.LIGHT_GREEN}port {Colors.LIGHT_RED}>{Colors.WHITE} ") 
            
            elif userselect == "N" or userselect == "n":
                pass

            elif userselect == "C" or userselect == "c":
                main()

            else:
                print(f"{Colors.LIGHT_RED}> {Colors.WHITE}Invalid option")
                time.sleep(0.15)
                main()

        # Specified IP address
        elif userselect == "2":
            argsip = input(f"Set {Colors.LIGHT_GREEN}IP address {Colors.LIGHT_RED}>{Colors.WHITE} ") 

            userselect = input(f"Scans {Colors.LIGHT_GREEN}all {Colors.WHITE}ranges? [Y/n/c] {Colors.LIGHT_RED}>{Colors.WHITE} ")
            if userselect == "Y" or userselect == "y":
                rangeip = True
            
            elif userselect == "N" or userselect == "n":
                pass

            elif userselect == "C" or userselect == "c":
                main()

            else:
                print(f"{Colors.LIGHT_RED}> {Colors.WHITE}Invalid option")
                time.sleep(0.15)
                main()

            userselect = input(f"Set a specified {Colors.LIGHT_GREEN}port{Colors.WHITE}? [Y/n/c] {Colors.LIGHT_RED}>{Colors.WHITE} ")
            if userselect == "Y" or userselect == "y":
                argsport = input(f"Set {Colors.LIGHT_GREEN}port {Colors.LIGHT_RED}>{Colors.WHITE} ") 
            
            elif userselect == "N" or userselect == "n":
                pass

            elif userselect == "C" or userselect == "c":
                main()
                
            else:
                print(f"\n{Colors.LIGHT_RED}> {Colors.WHITE}Invalid option")
                time.sleep(0.15)
                main()

        elif userselect == "3":
            print(f"""\n1 {Colors.LIGHT_RED}>{Colors.WHITE} repeat = {Colors.LIGHT_GREEN}{repeat}{Colors.WHITE}
2 {Colors.LIGHT_RED}>{Colors.WHITE} time to scan = {Colors.LIGHT_GREEN}{timescan}{Colors.WHITE}

3 {Colors.LIGHT_RED}>{Colors.WHITE} Cancel""")
            userselect = input(f"\nSet the option you will change {Colors.LIGHT_RED}>{Colors.WHITE} ")

            if userselect == "1":
                repeat = input(f"Set {Colors.LIGHT_GREEN}repeat{Colors.WHITE} value {Colors.LIGHT_RED}>{Colors.WHITE} ")
                if not repeat == None:
                    if repeat and not is_valid_repeat(repeat):
                        print(f"\n{Colors.LIGHT_RED}> {Colors.WHITE}Invalid repeat value")
                        repeat = 1
                        time.sleep(0.5)
                        main()
                elif repeat == None:
                    repeat = 1
                print(f"Repeat set to {Colors.LIGHT_GREEN}{repeat}{Colors.WHITE}")
                time.sleep(0.50)
                main()

            elif userselect == "2":
                timescan = input(f"Set {Colors.LIGHT_GREEN}timescan{Colors.WHITE} value {Colors.LIGHT_RED}>{Colors.WHITE} ")
                if timescan == "None" or timescan == "none" or timescan == "0":
                    timescan = None
                elif not timescan == None:
                    if timescan and not is_valid_timescan(timescan):
                        print(f"\n{Colors.LIGHT_RED}> {Colors.WHITE}Invalid timescan value")
                        timescan = 1
                        time.sleep(0.5)
                        main()
                elif timescan == None:
                    timescan = None
                print(f"Timescan set to {Colors.LIGHT_GREEN}{timescan}{Colors.WHITE}")
                time.sleep(0.50)
                main()

            elif userselect == "3":
                main()
            
            else:
                print(f"\n{Colors.LIGHT_RED}> {Colors.WHITE}Invalid option")
                time.sleep(0.15)
                main()

        elif userselect == "4":
            print(f"""
Coded by yzee4
Version 1.1.0 (Urured default version)

{Colors.LIGHT_GREEN}Urured is a simple open port scanner, with it you can see all
open ports of local or specified IP address. It features some filters 
that make your search easier. Its interface facilitates the 
visualization of information, as it is simple and contains 
elements that facilitate the interpretation of results
            
{Colors.WHITE}For more information visit project documentation on GitHub\n""")
        
            input(f"{Colors.WHITE}Enter any key for back {Colors.LIGHT_RED}> {Colors.WHITE}")
            main()

        elif userselect == "5":
            print(f"{Colors.WHITE}Copyright (c) 2023 Yzee4")
            sys.exit(0)

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
        main()
main()
