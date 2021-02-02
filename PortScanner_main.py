import socket
import struct
import argparse
import PortScanner_func as portscanner
from operator import itemgetter
import bcolors
import datetime
import time
import threading
import concurrent.futures

# 4 Sockets for 4 Threads
tcp_send_sockets = (socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) , socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP), socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP), socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP))
raw_rcv_sockets = (socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)), socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)), socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)), socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)))


# Obtain this machines IP for future use
myip = portscanner.Get_Host_IP()


# Creting Arguments and their Parser
parser = argparse.ArgumentParser(description="usage example : -t google.com -p 1-100 -s A -d 3 ")
parser.add_argument("-t", help= "Scan Target", required= True)
parser.add_argument("-p", help="Scan Range - ex: 1-100", required= True)
parser.add_argument("-s", help="Scan Type - can be: CS, A, S, F, W", required= True)
parser.add_argument("-d", help="Interval between each port in secondes (Can be float)", required= True)
parser.add_argument("-m", help="prevent Multi threding - No Argument is Required", action='store_true')
args = parser.parse_args()
#print(args)



#some Unused ports Constants
unused_ports = [(29170,29998) , (38866,39680) , (41798,42507) , (43442,44122)]


def main():
    # Handling Entered Arguments and checking for validation
    try:
        target_ip = socket.gethostbyname(args.t)
    except:
        print(bcolors.RED + bcolors.BOLD + "The Entered Target is not a valid address or its offline" + bcolors.ENDC)
        exit()

    try:
        ports = args.p.split('-')
        start_port = int(ports[0])
        finish_port = int(ports[1])
    except :
        print(bcolors.RED + bcolors.BOLD + "Entered Range is not correct! \nPlease Enter two integers in this format: start-finish" + bcolors.ENDC)
        print(bcolors.YELLOW + bcolors.BOLD + "For more Information use -h" + bcolors.ENDC)
        exit()

    scan_type = args.s
    if scan_type not in ('CS', 'A', 'S', 'F', 'W'):
        print(bcolors.RED + bcolors.BOLD + "Scan Type can only be one of: CS, A, S, F, W" + bcolors.ENDC)
        print(bcolors.YELLOW + bcolors.BOLD + "CS: Connect Scan\nA: Ack Scan\nS: Syn Scan\nF: Fin Scan\nW: Window Scan" + bcolors.ENDC)
        exit()

    try:
        delay = float(args.d)
    except:
        print(bcolors.RED + bcolors.BOLD + "The Entered Delay must be a float number!" + bcolors.ENDC)
        exit()
    
    if args.m == True: nothreading = True
    else: nothreading = False

    
    # Ping The host with ip and see if its up
    if not portscanner.ping(target_ip):
        print(bcolors.YELLOW + bcolors.BOLD + "WARNING: The Target You entered did not answer to ping\nIt might be Down." + bcolors.ENDC)
        yesorno = ''
        while yesorno not in ('y','Y','n','N'):
            yesorno = input("Do you want to continue? (y/n) : ")
        if yesorno in ('n','N'): exit()



    #print header line
    print(bcolors.HEADER + "-"*62 + bcolors.ENDC)
    print(bcolors.HEADER + "Scan Started at: {} ".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")), end='')
    if nothreading: print("without Threading Option" + bcolors.ENDC)
    else: print("with 4 Threads" + bcolors.ENDC)
    print(bcolors.HEADER + "-"*62 + bcolors.ENDC)
    

    # Final Result Lists
    final_open = []
    final_closed = []
    final_filtered = []
    final_unfiltered = []
    final_open_filtered = []



    # Port Partitioning for 4 Threads
    port_count = finish_port - start_port + 1
    port_delim = int(port_count/4)
    ports_delimed = [(start_port, start_port + port_delim - 1) , (start_port + port_delim, start_port + 2*port_delim - 1) ,
                     (start_port + 2*port_delim , start_port + 3*port_delim-1) , (start_port + 3*port_delim, finish_port)]


    start_time = time.time()
    #Connect Scan
    if scan_type == 'CS':
        if nothreading:
            con_res_open = portscanner.Connection_Scan(target_ip,start_port,finish_port,delay)
            #print(con_res_open)
            final_open = con_res_open

        else:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                thd1 = executor.submit(portscanner.Connection_Scan, target_ip, ports_delimed[0][0], ports_delimed[0][1], delay)
                thd2 = executor.submit(portscanner.Connection_Scan, target_ip, ports_delimed[1][0], ports_delimed[1][1], delay)
                thd3 = executor.submit(portscanner.Connection_Scan, target_ip, ports_delimed[2][0], ports_delimed[2][1], delay)
                thd4 = executor.submit(portscanner.Connection_Scan, target_ip, ports_delimed[3][0], ports_delimed[3][1], delay)
                con_res_open1 = thd1.result()
                con_res_open2 = thd2.result()
                con_res_open3 = thd3.result()
                con_res_open4 = thd4.result()
            final_open = con_res_open1 + con_res_open2 + con_res_open3 + con_res_open4
        
        
        for i in range(start_port,finish_port+1):
            if i not in final_open:
                final_closed.append(i)
        #print(final_open,final_closed)



    #Ack Scan
    elif scan_type == 'A':
        if nothreading:
            ack_res_filtered = portscanner.Ack_Scan(tcp_send_sockets[0], raw_rcv_sockets[0], myip,target_ip, start_port, finish_port, unused_ports[0], delay)
            #print(ack_res_filtered)
            final_filtered = ack_res_filtered
        
        else:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                thd1 = executor.submit(portscanner.Ack_Scan, tcp_send_sockets[0], raw_rcv_sockets[0], myip,target_ip, ports_delimed[0][0], ports_delimed[0][1], unused_ports[0], delay)
                thd2 = executor.submit(portscanner.Ack_Scan, tcp_send_sockets[1], raw_rcv_sockets[1], myip,target_ip, ports_delimed[1][0], ports_delimed[1][1], unused_ports[1], delay)
                thd3 = executor.submit(portscanner.Ack_Scan, tcp_send_sockets[2], raw_rcv_sockets[2], myip,target_ip, ports_delimed[2][0], ports_delimed[2][1], unused_ports[2], delay)
                thd4 = executor.submit(portscanner.Ack_Scan, tcp_send_sockets[3], raw_rcv_sockets[3], myip,target_ip, ports_delimed[3][0], ports_delimed[3][1], unused_ports[3], delay)

                ack_res_filtered1 = thd1.result()
                ack_res_filtered2 = thd2.result()
                ack_res_filtered3 = thd3.result()
                ack_res_filtered4 = thd4.result()
            final_filtered = ack_res_filtered1 + ack_res_filtered2 + ack_res_filtered3 + ack_res_filtered4
        
        
        for i in range(start_port,finish_port+1):
            if i not in final_filtered:
                final_unfiltered.append(i)


    #Syn Scan        
    elif scan_type == 'S':
        if nothreading:
            syn_res_open, syn_res_close, syn_res_filtered = portscanner.SYN_Scan(tcp_send_sockets[0], raw_rcv_sockets[0], myip, target_ip, start_port, finish_port, unused_ports[0], delay)
        #print(syn_res_open, syn_res_close, syn_res_filtered)
            final_open = syn_res_open
            final_closed = syn_res_close
            final_filtered = syn_res_filtered
        
        else:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                thd1 = executor.submit(portscanner.SYN_Scan, tcp_send_sockets[0], raw_rcv_sockets[0], myip,target_ip, ports_delimed[0][0], ports_delimed[0][1], unused_ports[0], delay)
                thd2 = executor.submit(portscanner.SYN_Scan, tcp_send_sockets[1], raw_rcv_sockets[1], myip,target_ip, ports_delimed[1][0], ports_delimed[1][1], unused_ports[1], delay)
                thd3 = executor.submit(portscanner.SYN_Scan, tcp_send_sockets[2], raw_rcv_sockets[2], myip,target_ip, ports_delimed[2][0], ports_delimed[2][1], unused_ports[2], delay)
                thd4 = executor.submit(portscanner.SYN_Scan, tcp_send_sockets[3], raw_rcv_sockets[3], myip,target_ip, ports_delimed[3][0], ports_delimed[3][1], unused_ports[3], delay)

                syn_res1 = thd1.result()
                syn_res2 = thd2.result()
                syn_res3 = thd3.result()
                syn_res4 = thd4.result()

            final_open = syn_res1[0] + syn_res2[0] + syn_res3[0] + syn_res4[0]
            final_closed = syn_res1[1] + syn_res2[1] + syn_res3[1] + syn_res4[1]
            final_filtered = syn_res1[2] + syn_res2[2] + syn_res3[2] + syn_res4[2]


    #Fin Scan
    elif scan_type == 'F':
        if nothreading:
            fin_res_open_filtered = portscanner.FIN_Scan(tcp_send_sockets[0],raw_rcv_sockets[0], myip, target_ip, start_port, finish_port, unused_ports[0], delay)
            #print(fin_res_open_filtered)
            final_open_filtered = fin_res_open_filtered


        else:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                thd1 = executor.submit(portscanner.FIN_Scan, tcp_send_sockets[0], raw_rcv_sockets[0], myip,target_ip, ports_delimed[0][0], ports_delimed[0][1], unused_ports[0], delay)
                thd2 = executor.submit(portscanner.FIN_Scan, tcp_send_sockets[1], raw_rcv_sockets[1], myip,target_ip, ports_delimed[1][0], ports_delimed[1][1], unused_ports[1], delay)
                thd3 = executor.submit(portscanner.FIN_Scan, tcp_send_sockets[2], raw_rcv_sockets[2], myip,target_ip, ports_delimed[2][0], ports_delimed[2][1], unused_ports[2], delay)
                thd4 = executor.submit(portscanner.FIN_Scan, tcp_send_sockets[3], raw_rcv_sockets[3], myip,target_ip, ports_delimed[3][0], ports_delimed[3][1], unused_ports[3], delay)

                fin_res1 = thd1.result()
                fin_res2 = thd2.result()
                fin_res3 = thd3.result()
                fin_res4 = thd4.result()

            final_open_filtered = fin_res1 + fin_res2 + fin_res3 + fin_res4


        for i in range(start_port,finish_port+1):
            if i not in final_open_filtered:
                final_closed.append(i)


    #Window Scan
    elif scan_type == 'W':
        if nothreading:
            win_res_open, win_res_close, win_res_filtered = portscanner.Window_scan(tcp_send_sockets[0], raw_rcv_sockets[0], myip, target_ip, start_port, finish_port, unused_ports[0], delay)
            #print(win_res_open, win_res_close, win_res_filtered)
            final_open = win_res_open
            final_closed = win_res_close
            final_filtered = win_res_filtered

        else:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                thd1 = executor.submit(portscanner.Window_scan, tcp_send_sockets[0], raw_rcv_sockets[0], myip,target_ip, ports_delimed[0][0], ports_delimed[0][1], unused_ports[0], delay)
                thd2 = executor.submit(portscanner.Window_scan, tcp_send_sockets[1], raw_rcv_sockets[1], myip,target_ip, ports_delimed[1][0], ports_delimed[1][1], unused_ports[1], delay)
                thd3 = executor.submit(portscanner.Window_scan, tcp_send_sockets[2], raw_rcv_sockets[2], myip,target_ip, ports_delimed[2][0], ports_delimed[2][1], unused_ports[2], delay)
                thd4 = executor.submit(portscanner.Window_scan, tcp_send_sockets[3], raw_rcv_sockets[3], myip,target_ip, ports_delimed[3][0], ports_delimed[3][1], unused_ports[3], delay)

                win_res1 = thd1.result()
                win_res2 = thd2.result()
                win_res3 = thd3.result()
                win_res4 = thd4.result()

            final_open = win_res1[0] + win_res2[0] + win_res3[0] + win_res4[0]
            final_closed = win_res1[1] + win_res2[1] + win_res3[1] + win_res4[1]
            final_filtered = win_res1[2] + win_res2[2] + win_res3[2] + win_res4[2]




    print("Scan results for {} ({}) ({})".format(args.t, socket.gethostbyaddr(target_ip)[0], target_ip))
    

    maxindex, maxlen = max(enumerate([len(final_closed), len(final_filtered), len(final_unfiltered)]), key= itemgetter(1))
    if maxindex == 0:
        print("Not Shown: {} Closed Ports".format(maxlen))
        print(bcolors.HEADER + bcolors.BOLD + "Port\t   STATE\t  SERVICE" + bcolors.ENDC)
        print(bcolors.HEADER + "-"*36 + bcolors.ENDC)
        for i in range(start_port,finish_port+1):
            try:
                portname = socket.getservbyport(i,'tcp')
            except:
                portname = "Unknown"
            if i in final_open:
                print(bcolors.GREEN + "{: <09}  {: <013}  {}".format(str(i)+"/tcp", "Open",portname) + bcolors.ENDC)
            elif i in final_filtered:
                print(bcolors.YELLOW + "{: <09}  {: <013}  {}".format(str(i)+"/tcp", "Filtered",portname) + bcolors.ENDC)
            elif i in final_open_filtered:
                print(bcolors.BLUE + "{: <09}  {: <013}  {}".format(str(i)+"/tcp", "Open|Filtered",portname) + bcolors.ENDC)
    
    elif maxindex == 1:
        print("Not Shown: {} Filtered Ports".format(maxlen))
        print(bcolors.HEADER + bcolors.BOLD + "Port\t   STATE\t  SERVICE" + bcolors.ENDC)
        print(bcolors.HEADER + "-"*28 + bcolors.ENDC)
        for i in range(start_port,finish_port+1):
            try:
                portname = socket.getservbyport(i,'tcp')
            except:
                portname = "Unknown"
            if i in final_open:
                print(bcolors.GREEN + "{: <09}  {: <013}  {}".format(str(i)+"/tcp", "Open",portname) + bcolors.ENDC)
            elif i in final_closed:
                print(bcolors.RED + "{: <09}  {: <013}  {}".format(str(i)+"/tcp", "Closed",portname) + bcolors.ENDC)
            elif i in final_unfiltered:
                print(bcolors.GREEN + "{: <09}  {: <013}  {}".format(str(i)+"/tcp", "Unfiltered",portname) + bcolors.ENDC)
    elif maxindex == 2:
        print("Not Shown: {} Unfiltered Ports".format(maxlen))
        print(bcolors.HEADER + bcolors.BOLD + "Port\t   STATE\t  SERVICE" + bcolors.ENDC)
        print(bcolors.HEADER + "-"*28 + bcolors.ENDC)
        for i in range(start_port,finish_port+1):
            try:
                portname = socket.getservbyport(i,'tcp')
            except:
                portname = "Unknown"
            if i in final_filtered:
                print(bcolors.YELLOW + "{: <09}  {: <013}  {}".format(str(i)+"/tcp", "Filtered",portname) + bcolors.ENDC)

    print("Scan Finished in {:.2f} secondes".format(time.time() - start_time))







main()














#ack_res = portscanner.Ack_Scan(tcp_send_socket,raw_rcv_socket,myip,"192.168.1.1",1,100,1)
#print("ack scan :",ack_res)


#syn_res = portscanner.SYN_Scan(tcp_send_socket,raw_rcv_socket,myip,"192.168.1.1",1,450,1)
#print("syn scan open:", syn_res[0] , "filtered:", syn_res[2])


#fin_res = portscanner.FIN_Scan(tcp_send_socket, raw_rcv_socket, myip, "192.168.1.1", 1, 100 , 1)
#print(fin_res)

#window_res = portscanner.Window_scan(tcp_send_socket, raw_rcv_socket, myip, "192.168.1.1", 1, 100 , 1)
#print(window_res)


#con_res = portscanner.Connection_Scan("192.168.1.1",1,500,0.1)
#print(con_res)



#portscanner.TCP_Packet_Sender(tcp_send_socket, myip, "192.168.1.1", 12345, 25, portscanner.SYN_FLAGSET)



#if portscanner.ConnectionTry(con_socket,("192.168.1.1",80)):
#        print("Port {} is Open".format(80))

          
# for port in range(1,445):
#     con_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     time.sleep(0.2)
#     print("trying in for" , port)
#     if portscanner.ConnectionTry(con_socket,("192.168.1.1",port)):
#         print("Port {} is Open".format(port))