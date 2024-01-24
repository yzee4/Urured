# Urured by yzee4
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

# Code version SAB20JAN0124

# Import libs necessarias para o funcionamento
import os
import re
import sys
import time
import signal
import shutil
import readline
import subprocess

# Cores usadas no programa
class Colors:
    WHITE = '\033[0;97m'
    LIGHT_RED = '\033[0;91m'
    LIGHT_GREEN = '\033[0;92m'
Colors()

# Verifica em que modo o usuario esta, root ou nao
def verify_root():
    global root
    if os.geteuid() != 0:
        root = None
    else:
        root = True
verify_root()

# Inicializa o programa e confere se as ferramentas necessarias estao instaladas
def check_tool_installed(tool_name):
    return shutil.which(tool_name) is not None

def initializing_urured():
    tools_to_check = ['nmap', 'ip']
    not_installed_tools = [tool for tool in tools_to_check if not check_tool_installed(tool)]
    
    if not_installed_tools:
        for tool in not_installed_tools:
            print(f"{Colors.LIGHT_RED}> {Colors.LIGHT_GREEN}{tool} {Colors.WHITE}not installed. To install, use {Colors.LIGHT_GREEN}'pkg install {tool}'{Colors.WHITE}")
            sys.exit(0)
initializing_urured()

# Escaneamento de IP
# Essa e a funcao principal do programa, aqui sera escaneado e extraida as informacoes de
# cada IP, sendo possivel alterar algumas vartiaveis no menu principal
def scan_network():

    # Caso 'timescan' for valida, ele comeca o processo de contagem e encerramendo definido pelo usuario 
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

    # Extracao de IP local
    # Se caso 'localnet' for True, ira extrair o IP no qual o usuario esta conectado
    if localnet:
        result = subprocess.run("ip route | grep -oP 'src \K\S+' | head -n 1", shell=True, capture_output=True, text=True)
        local_ips = result.stdout.splitlines()
        if len(local_ips) == 0:
            print(f"{Colors.LIGHT_RED}> {Colors.WHITE}Failed to scan local network ip\n")
            input(f"{Colors.WHITE}Enter any key for back {Colors.LIGHT_RED}> {Colors.WHITE}")
            main()
            sys.exit(0)

        # Agrega o escaneamento em todos os intervalos automaticamente
        local_ips_with_subnet = [ip + "/24" for ip in local_ips]
        command_list.append(*local_ips_with_subnet)
    
    # Comandos de escaneamento
    # Para cada situacao o comando de escaneamento e diferente
    # Caso usuario esteja em root    
    if root:
        # Caso 'onlyopen' for True
        if onlyopen == f"{Colors.LIGHT_GREEN}true":
            command = ['nmap', '-O', '-open', '-T5', *command_list]
        else:
            command = ['nmap', '-O', '-T5', *command_list]

    # Caso usuario nao esteja em root        
    else:
        # Caso 'onlyopen' for True
        if onlyopen == f"{Colors.LIGHT_GREEN}true":
            command = ['nmap', '-open', '-T5', *command_list]
        else:
            command = ['nmap', '-T5', *command_list]

    # Funcao principal de escameamento de escaneamento e extracao
    try:
        # Variaves de funcionamento
        global found_port
        repeatcounter = 1

        # Transforma a o numero definido em 'repeat' em inteiro
        repeatvalue = int(repeat)

        # Repete o sistema de acordo com o valor de 'repeatvalue'
        for _ in range(repeatvalue):
            print(f"{Colors.LIGHT_RED}> {Colors.WHITE}Scanning...")

            # Inicia o cronometro de escaneamento
            global started_time
            startedlocaltime = time.localtime()
            started_time = (time.strftime("%H:%M:%S", startedlocaltime))

            # Executa o comando de escaneamento
            with open('/dev/null', 'w') as null_file:
                nmap_output = subprocess.check_output(command, universal_newlines=True, stderr=null_file)
            # Extrai a saida do comando e grava em 'paragraphs'
            paragraphs = re.split(r'\n(?=Nmap scan report)', nmap_output)

            # Variaveis necessarias para o funcionamento e exibicao
            ip_address = None
            num_ips_scanned = 0
            num_ports_scanned = 0

            if paragraphs:
                if repeatvalue > 1:
                    if repeatvalue == repeatcounter:
                        print(f"{Colors.LIGHT_RED}> {Colors.WHITE}Repeat counter {Colors.LIGHT_GREEN}[{repeatcounter}/{repeatvalue}]")
                    else:
                        print(f"{Colors.LIGHT_RED}> {Colors.WHITE}Repeat counter [{repeatcounter}/{repeatvalue}]")

            # Extrai informacoes de cada IP por paragrafo    
            for paragraph in paragraphs:
                match_ip = re.search(r'Nmap scan report for (\S+)(?: \(([\d\.]+)\))?', paragraph)
                match_ports = re.finditer(r'(\d+/[a-zA-Z-0-9]+)\s+(open)\s+([a-zA-Z-0-9]+)', paragraph)
                match_mac = re.search(r'MAC Address: ([0-9A-F:]+) \((.*?)\)', paragraph)
                match_host = re.search(r"Note: Host seems down", paragraph)
                match_os = re.search(r'OS details: (.+)', paragraph)
                match_closed_ports = re.search(r'Not shown: 1000 closed ([a-zA-Z]+) ports', paragraph)

                # Se caso encontrar a mensagem 'Note: Host seems down', exibe a mensagem
                if match_host:
                    print(f"\n{Colors.LIGHT_GREEN}----| IP: {Colors.WHITE}{argsip}") 
                    print(f"{Colors.LIGHT_RED}> {Colors.WHITE}No response")
                    sys.exit(0)
                
                # Exibe as informacoes de cada IP na tela
                if match_ip:
                    host_name = match_ip.group(1)
                    ip_address = match_ip.group(2)

                    # Se caso for IP exibe uma mensagem, se caso for dominio, exibe outra
                    if ip_address:
                        print(f"\n{Colors.LIGHT_GREEN}----| IP: {Colors.WHITE}{ip_address} ({host_name})")
                    else:
                        print(f"\n{Colors.LIGHT_GREEN}----| IP: {Colors.WHITE}{host_name}")

                    # Se encontar portas em algum paragrafo, definit 'found_port' para True
                    for match in match_ports:
                        found_port = True

                    # Tratamento para OS e MAC
                    # Mesnagem diferentes para usuarios que estao em root ou nao
                    # Se o usuario estiver em root porem nao teve retorno, exibe uma mensagem diferente    
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

                    # Mostra na tela o resultados de NAME, MAC e OS
                    print(f"""{Colors.LIGHT_GREEN}NAME: {Colors.WHITE}{name}
{Colors.LIGHT_GREEN}MAC:  {Colors.WHITE}{mac}
{Colors.LIGHT_GREEN}OS:   {Colors.WHITE}{os}""")

                    # Trabalha com o tratamento de portas, mas apenas se for verdadeiro
                    if found_port:
                        # Se caso o IP nao tiver portas abertas, exibe a mensagem
                        if match_closed_ports:
                            print(f"{Colors.LIGHT_RED}> {Colors.WHITE}No open ports")

                        # Se caso nao tiver resultado para a busca do IP
                        elif match_host:
                            print(f"{Colors.LIGHT_RED}> {Colors.WHITE}No result")

                        # Se tudo estiver correto, exibe o cabecalho dos resultados das portas    
                        else:    
                            print(f"{Colors.LIGHT_GREEN}PORT     {Colors.LIGHT_GREEN}SERVICE")

                        # Extrai as portas do paragrafo do IP
                        match_ports = re.finditer(r'(\d+/[a-zA-Z-0-9]+)\s+(open)\s+([a-zA-Z-0-9]+)', paragraph)

                        # Trabalha de forma diferente para cada porta encontrada no paragrafo do IP
                        for match in match_ports:
                            num_ports_scanned += 1
                            port = match.group(1).split("/")[0]
                            service = match.group(3)
                            
                            # Formata a exibicao para cada porta
                            chars_to_add = max(0, 9 - len(port))
                            port = port + f" " * chars_to_add
                            print(f"{Colors.WHITE}{port}{Colors.WHITE}{service}")
                    
                    # Aumenta 1 em 'num_ips_scanned' a cada IP escaneado
                    num_ips_scanned += 1

            # Extrai o tempo de escaneamento que cada IP levou
            if "Nmap done" in paragraph:
                endlocaltime = time.localtime()
                end_time = (time.strftime("%H:%M:%S", endlocaltime))
                match_time = re.search(r'in (\d+\.\d+) seconds', paragraph)

                if match_time:
                    total_scan_time = match_time.group(1)

                    # Caso o numero de IP escaneados com sucesso for igual a 0, exibe a mensagem
                    if num_ips_scanned == 0:
                        print(f"\n{Colors.LIGHT_RED}> {Colors.WHITE}No results for the search. Try again or change some options\n")
                        input(f"{Colors.WHITE}Enter any key for back {Colors.LIGHT_RED}> {Colors.WHITE}")
                        main()

                    # Formata a mensagem de log para plural ou nao     
                    if num_ips_scanned > 1:
                        show_ip_word = "addresses"
                    else:
                         show_ip_word = "address"
                    if num_ports_scanned > 1:
                        show_port_word = "ports"
                    else:
                        show_port_word = "port"

                    # Mensagem de log
                    print(f"""\n{Colors.LIGHT_GREEN}{num_ips_scanned} IP {show_ip_word} and {num_ports_scanned} {show_port_word} found
in {total_scan_time} seconds between {started_time}...{end_time}\n""")
                    
            # A cada IP escaneado adiciona 1 no contador de repeticao        
            repeatcounter += 1

    # Algumas excessoes para encerrar o escaneamento
    except subprocess.CalledProcessError as e:
        print(f"{Colors.LIGHT_RED}> {Colors.WHITE}Unknown error: {str(e)}\n")
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

# Interface principal do programa
# Um urubu cabuloso
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

# Verifica as variaveis
# Aqui verifica se as variaveis estao na formatacao correta, se caso nao estiverem retornam False
# Verifica se o IP escolhido e valido
def is_valid_ip(argsip):
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if argsip == '0.0.0.0':
        return False
    if argsip == "":
        return False
    if re.match(ip_pattern, argsip):
        parts = argsip.split('.')
        for part in parts:
            if not (0 <= int(part) <= 255):
                return False
        return True

# Verifica se a porta escolhida e valida
def is_valid_port(argsport):
    try:
        port = int(argsport)
        if 1 <= port <= 65535:
            return True
    except ValueError:
        return False
    
# Verifica se o valor de repeticao escolhido e valido    
def is_valid_repeat(repeat):
    try:
        repeat = int(repeat) 
        if 1 <= repeat <= 10:
            return True
    except ValueError:
        return False

# Verifica se o valor de tempo de escaneamento escolhido e valido        
def is_valid_timescan(timescan):
    try:
        timescan = int(timescan) 
        if 0 <= timescan:
            return True
    except ValueError:
        return False

# Opcoes
# Aqui e definido as variaveis padroes, isso afeta o funcionamento principal
def options():
    global onlyopen # Mostrar todos os IPs mesmo que nao tenha portas abertas
    global repeat   # Quantidade que o escaneamento ira repetir 
    global timescan # Tempo limite de escaneamento
    onlyopen = f"{Colors.LIGHT_GREEN}true"
    repeat = 1
    timescan = None 
options()

# Menu principal 
# Aqui e definido o que o escaneamento ira fazer, contendo todas as variaveis necessarias
# para o funcionamento correto
def main():
    subprocess.run("clear")
    print(f"{interface}")

    # Variaveis temporarias
    # Essas variaveis irao ser retoranadas a None apos o fim do escaneamento
    global argsip # Variavel temporaria do IP
    global localnet # Variavel que vai dizer se o escaneamento e local ou nao
    global command_list # Lista que agrega todos os anexos do comando

    # Retorna tudo a None 
    argsip = None
    argsport = None
    rangeip = None
    localnet = None
    command_list = []

    global onlyopen # Mostrar todos os IPs mesmo que nao tenha portas abertas
    global repeat   # Quantidade que o escaneamento ira repetir 
    global timescan # Tempo limite de escaneamento

    # Aqui sao dadas as opcoes de escolha principal ao usuario
    # O 'try' e devido ao encerramento principal do programa com Cntrl+C    
    try:
        userselect = input(f"""{Colors.LIGHT_RED}----| {Colors.WHITE}Select option {Colors.LIGHT_RED}>{Colors.WHITE} """)
    except KeyboardInterrupt:
        print(f"\n{Colors.WHITE}Copyright (c) 2023 yzee4")
        sys.exit(0)

    try:
        # Opcao 1: Escaneamento local
        # Escaneamento local e basicamente escanear o IP no qual esta conectado atualmente
        # Variavel 'localnet' e definida para 'True'        
        if userselect == "1":
            localnet = True

            # Pergunta se deseja definir uma porta especifica para escanear
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

        # Opcao 2: Escaneamento de IP especifico
        # Escaneia um ip escolhido pelo usuario, pode escanear todo o intervalo tambem        
        elif userselect == "2":
            argsip = input(f"Set {Colors.LIGHT_GREEN}IP address {Colors.LIGHT_RED}>{Colors.WHITE} ")

            # Verifica se o IP escolhido e valido
            if argsip == "":
                print(f"{Colors.LIGHT_RED}> {Colors.WHITE}Invalid IP address format")
                time.sleep(0.5)
                main()
            if argsip and not is_valid_ip(argsip):
                print(f"{Colors.LIGHT_RED}> {Colors.WHITE}Invalid IP address format")
                time.sleep(0.5)
                main()

            # Pergunta se quer que escaeneie o intervalo inteiro, '192.168.1.0-255'
            userselect = input(f"Scans {Colors.LIGHT_GREEN}all {Colors.WHITE}ranges? [Y/n/c] {Colors.LIGHT_RED}>{Colors.WHITE} ")
            if userselect == "Y" or userselect == "y":
                rangeip = True
                if rangeip:
                    command_list.append(argsip+"-255")
                else:
                    command_list.append(argsip)                  
            
            elif userselect == "N" or userselect == "n":
                pass

            elif userselect == "C" or userselect == "c":
                main()

            else:
                print(f"{Colors.LIGHT_RED}> {Colors.WHITE}Invalid option")
                time.sleep(0.15)
                main()

            # Pergunta se deseja definir uma porta especifica para escanear
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

        # Opcao 3: Menu de opcoes
        # Aqui sera definido opcoes que afetam o funcionamento principal do programa
        elif userselect == "3":
            print(f"""\n1 {Colors.LIGHT_RED}>{Colors.WHITE} repeat = {Colors.LIGHT_GREEN}{repeat}{Colors.WHITE}
2 {Colors.LIGHT_RED}>{Colors.WHITE} time to scan = {Colors.LIGHT_GREEN}{timescan}{Colors.WHITE}
3 {Colors.LIGHT_RED}>{Colors.WHITE} only show ip addresses with open ports = {onlyopen}{Colors.WHITE}

4 {Colors.LIGHT_RED}>{Colors.WHITE} reset all options to {Colors.LIGHT_GREEN}deafult{Colors.WHITE}
5 {Colors.LIGHT_RED}>{Colors.WHITE} Cancel""")
            userselect = input(f"\nSet the option you will change {Colors.LIGHT_RED}>{Colors.WHITE} ")

            # Valor de 'repeat', Inteiro
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

            # Valor de 'timescan', Inteiro
            elif userselect == "2":
                timescan = input(f"Set {Colors.LIGHT_GREEN}timescan{Colors.WHITE} value {Colors.LIGHT_RED}>{Colors.WHITE} ")
                if timescan == "None" or timescan == "none" or timescan == "0":
                    timescan = None
                elif not timescan == None:
                    if timescan and not is_valid_timescan(timescan):
                        print(f"{Colors.LIGHT_RED}> {Colors.WHITE}Invalid timescan value")
                        timescan = 1
                        time.sleep(0.5)
                        main()
                elif timescan == None:
                    timescan = None
                print(f"Timescan set to {Colors.LIGHT_GREEN}{timescan}{Colors.WHITE}")
                time.sleep(0.50)
                main()

            # Valor de 'onlyopen', True/False
            elif userselect == "3":
                onlyopen = input(f"Set {Colors.LIGHT_GREEN}show only open ports IP address{Colors.WHITE} value [T/f] {Colors.LIGHT_RED}>{Colors.WHITE} ")
                if not (onlyopen.lower() == "t" or onlyopen.lower() == "f"):
                    print(f"{Colors.LIGHT_RED}> {Colors.WHITE}Invalid value")
                    time.sleep(0.5)
                    main()
                if onlyopen.lower() == "t":
                    onlyopen = f"{Colors.LIGHT_GREEN}true"

                if onlyopen.lower() == "f":
                    onlyopen = f"{Colors.LIGHT_RED}false"

                print(f"Show only open ports IP address {Colors.WHITE}set to {onlyopen}{Colors.WHITE}")
                time.sleep(0.5)
                main()

            # resetar todas as opcoes para padrao
            elif userselect == "4":
                print(f"All options reset to {Colors.LIGHT_GREEN}deafult{Colors.WHITE}")
                time.sleep(0.5)
                options()
                main()

            # Retorna ao menu
            elif userselect == "5":
                main()
            
            # Se caso escolher alguma opcao errada, exibe mensagem e retorna ao menu 
            else:
                print(f"{Colors.LIGHT_RED}> {Colors.WHITE}Invalid option")
                time.sleep(0.15)
                main()

        # Informacoes sobre o programa
        elif userselect == "4":
            print(f"""
Coded by yzee4
Version 1.1.5 (Urured default version) DOM21JAN0124

{Colors.LIGHT_GREEN}Urured is a simple open port scanner, with it you can see all
open ports of local or specified IP address. It features some filters 
that make your search easier. Its interface facilitates the 
visualization of information, as it is simple and contains 
elements that facilitate the interpretation of results
            
{Colors.WHITE}For more information visit project documentation on GitHub\n""")
        
            input(f"{Colors.WHITE}Enter any key for back {Colors.LIGHT_RED}> {Colors.WHITE}")
            main()

        # Sai do programa
        elif userselect == "5":
            print(f"{Colors.WHITE}Copyright (c) 2023 yzee4")
            sys.exit(0)

        # Se caso escolher alguma opcao errada, exibe mensagem e retorna ao menu 
        else:
            print(f"{Colors.LIGHT_RED}> {Colors.WHITE}Invalid option")
            time.sleep(0.15)
            main()

        # Se caso tiver um porta escolhida, chama a funcao de verificacao
        if argsport:
            if argsport and not is_valid_port(argsport):
                print(f"{Colors.LIGHT_RED}> {Colors.WHITE}Invalid port format")
                time.sleep(0.15)
                main()

            # Agrega a porta na lista de comandos    
            command_list.append(f"-p {argsport}")

        # Chama a funcao principal do programa, escaneamento
        print()
        scan_network()

    # Caso apertar Cntrl+C, voltar para o menu de escolhas
    except KeyboardInterrupt:
        main()
main()
