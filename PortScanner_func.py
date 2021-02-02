import shlex
import subprocess
import socket
import struct
import array
import time
import random


# TCP Flag set Constants
ACK_FLAGSET = (0,0,0,0,1,0,0,0,0)
RST_FLAGSET = (0,0,0,0,0,0,1,0,0)
SYN_FLAGSET = (0,0,0,0,0,0,0,1,0)
SYNACK_FLAGSET = (0,0,0,0,1,0,0,1,0)
RSTACK_FLAGSET = (0,0,0,0,1,0,1,0,0)
FIN_FLAGSET = (0,0,0,0,0,0,0,0,1)


# Returns the ip address of this machine
def Get_Host_IP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP



# Pings the host to see if its up and available
def ping(host):
    command_line = "ping -c 1 " + host
    args = shlex.split(command_line)
    try:
        subprocess.check_call(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False



#performs Connection scan and returns Open ports
def Connection_Scan(target_ip, start_port, finish_port, timeinterval):
    open_ports = []
    for port in range(start_port, finish_port+1):
        time.sleep(timeinterval)
        consock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        consock.settimeout(timeinterval*2)
        try:
            consock.connect((target_ip,port))
            consock.settimeout(None)
            consock.close()
            open_ports.append(port)
        except:
            consock.settimeout(None)
            consock.close()
    return open_ports



# Creates a TCP packet with given info and Returns Bytes
def TCP_Packet_Generator(src_ip, dst_ip, src_port, dest_port, sqnc_num, ack_num, flags, window = 8192):
    pckt = struct.pack('! H H L L',src_port, dest_port, sqnc_num, ack_num)
    byte13 = (5 << 4) + flags[0]
    byte14 = flags[1]
    for i in range (2,9):
        byte14 = (byte14 << 1) + flags[i]
        #print(bin(byte14))
    
    pckt += struct.pack('! B B H H H',byte13, byte14, window, 0,0)

    pseudo_header = struct.pack('! 4s 4s H H',socket.inet_aton(src_ip), socket.inet_aton(dst_ip), socket.IPPROTO_TCP, len(pckt))
    
    chcksm = Checksum(pckt + pseudo_header)
    #print(chcksm)
    #pckt = struct.pack('! H H L L B B H H H', src_port, dest_port, sqnc_num, ack_num, byte13, byte14, window, chcksm, 0)
    pckt = pckt[:16] + struct.pack('H',chcksm) + pckt[18:]
    return pckt


# Calculates TCP Packet Checksum
def Checksum(packet):
    if len(packet) % 2 != 0:
        packet += b'\0'
    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16
    return (~res) & 0xffff




# Unpack the ethernet frame and return header,data
# implemented according to https://en.wikipedia.org/wiki/Ethernet_frame
def Unpack_eth(data):
    dest_mac, src_mac, networkType = struct.unpack('! 6s 6s H',data[:14])
    return Make_mac_readable(dest_mac), Make_mac_readable(src_mac) , networkType, data[14:]

def Make_mac_readable(mac):
    s = map('{:02x}'.format,mac)
    return ':'.join(s).upper()  



# Unpack Ipv4 Datagram and return data
# implemented according to https://en.wikipedia.org/wiki/IPv4
def Unpack_Ipv4(data):
    firstbyte = data[0]
    version = firstbyte >> 4
    header_length = (firstbyte & 15) #IHL shows the count of 4 Byte Lines in header
    ttl, transportType, src_ip, dest_ip = struct.unpack('! 8x B B 2x 4s 4s',data[:20])
    return version, header_length, ttl, transportType, Make_ipv4_readable(src_ip), Make_ipv4_readable(dest_ip), data[header_length*4:]

def Make_ipv4_readable(ip):
    return '.'.join(map(str, ip))



# Unpack TCP segment and return header,data
# implemented according to https://en.wikipedia.org/wiki/Transmission_Control_Protocol
def Unpack_TCP(data):
    src_port, dest_port, sqnc_num, ack_num, byte1314, window_size, checksum, urg_pointer = struct.unpack('! H H L L H H H H', data[:20])
    data_offset = (byte1314 >> 12)
    NS_flag = (byte1314 & 256) >> 8
    CWR_flag = (byte1314 & 128) >> 7
    ECE_flag = (byte1314 & 64) >> 6
    URG_flag = (byte1314 & 32) >> 5
    ACK_flag = (byte1314 & 16) >> 4
    PSH_flag = (byte1314 & 8) >> 3
    RST_flag = (byte1314 & 4) >> 2
    SYN_flag = (byte1314 & 2) >> 1
    FIN_flag = (byte1314 & 1)
    #if len(data) > data_offset*4:
    return src_port, dest_port, sqnc_num, ack_num, data_offset, NS_flag, CWR_flag, ECE_flag, URG_flag, ACK_flag,\
        PSH_flag, RST_flag, SYN_flag, FIN_flag, window_size, checksum, urg_pointer,data[data_offset*4:]
    # else:
    #     return src_port, dest_port, sqnc_num, ack_num, data_offset, NS_flag, CWR_flag, ECE_flag, URG_flag, ACK_flag,\
    #         PSH_flag, RST_flag, SYN_flag, FIN_flag, window_size, checksum, urg_pointer




# Crates TCP Packet with FLAGSET And Sends it to Target
def TCP_Packet_Sender(sock : socket.socket, src_ip, dest_ip, src_port, dest_port, flagset):
    pckt = TCP_Packet_Generator(src_ip, dest_ip, src_port, dest_port, 0, 0, flagset, 8192)
    sock.sendto(pckt,(dest_ip,dest_port))



# Checks raw_data Packet to see if its sent from target and is a specific FLAGSET Packet
def TCP_Rcvd_Checker(raw_data, target_ip, target_port, flagset):
    eth_payload_type, eth_payload = Unpack_eth(raw_data)[2:4]
    if eth_payload_type == 2048:
        ip_transportType, ip_src_ip, ip_dest_ip, ip_payload = Unpack_Ipv4(eth_payload)[3:7]
        if ip_transportType == 6 and ip_src_ip == target_ip:
            src_port, dest_port, sqnc_num, ack_num, data_offset, NS_flag, CWR_flag, ECE_flag, URG_flag, ACK_flag,\
            PSH_flag, RST_flag, SYN_flag, FIN_flag = Unpack_TCP(ip_payload)[:-4]
            if src_port == target_port:
                if (NS_flag, CWR_flag, ECE_flag, URG_flag, ACK_flag,PSH_flag, RST_flag, SYN_flag, FIN_flag) == flagset:
                    return True
                else: return False


# Checks raw_data Packet to see if its sent from target and is a specific FLAGSET Packet and NonZero Window Size
# returns 2 if the Flagsets are same and window is not zero and returns 1 if flagsets are same and window size is zero
# Used to check Window scan Results
def TCP_Rcvd_Checker_NonZero_Window(raw_data, target_ip, target_port, flagset):
    eth_payload_type, eth_payload = Unpack_eth(raw_data)[2:4]
    if eth_payload_type == 2048:
        ip_transportType, ip_src_ip, ip_dest_ip, ip_payload = Unpack_Ipv4(eth_payload)[3:7]
        if ip_transportType == 6 and ip_src_ip == target_ip:
            src_port, dest_port, sqnc_num, ack_num, data_offset, NS_flag, CWR_flag, ECE_flag, URG_flag, ACK_flag,\
            PSH_flag, RST_flag, SYN_flag, FIN_flag, window_size = Unpack_TCP(ip_payload)[:-3]
            if src_port == target_port:
                if ((NS_flag, CWR_flag, ECE_flag, URG_flag, ACK_flag,PSH_flag, RST_flag, SYN_flag, FIN_flag) == flagset) and window_size != 0:
                    return 2
                elif ((NS_flag, CWR_flag, ECE_flag, URG_flag, ACK_flag,PSH_flag, RST_flag, SYN_flag, FIN_flag) == flagset) and window_size == 0:
                    return 1
                else: return 0




# Main Function To perform ACK Scan
# Returns the List Of Filtered Ports
# this function uses random port selection to prevent blocking
def Ack_Scan(sndr_sock: socket.socket, rcvr_sock : socket.socket, host_ip, target_ip, start_port, finish_port, freeports, timeinterval):
    filtered_ports = []
    for port in range(start_port,finish_port+1):
        host_port = random.randrange(freeports[0],freeports[1])
        TCP_Packet_Sender(sndr_sock, host_ip, target_ip, host_port, port,ACK_FLAGSET)
        start_time = time.time()
        filtered = True
        try:
            while time.time() - start_time < timeinterval:
                rcvr_sock.settimeout(timeinterval*2)
                raw_data, addr = rcvr_sock.recvfrom(65535)
                rcvr_sock.settimeout(None)
                if TCP_Rcvd_Checker(raw_data, target_ip, port, RST_FLAGSET): #port is not filtered and returnd a RST
                    filtered = False
                    time.sleep(timeinterval - (time.time() - start_time)) #wait till the interval is met and go to next port
                    break
        except : None
        if filtered == True: #timed out with no answer or all answers was wrong
            filtered_ports.append(port)
    return filtered_ports



# Main Function To perform SYN Scan
# Returns the List Of Open, Close and Filtered Ports
# this function uses random port selection to prevent blocking
def SYN_Scan(sndr_sock: socket.socket, rcvr_sock : socket.socket, host_ip, target_ip, start_port, finish_port, freeports, timeinterval):
    open_ports = []
    close_ports = []
    filtered_ports = []
    for port in range(start_port,finish_port+1):
        host_port = random.randrange(freeports[0],freeports[1])
        TCP_Packet_Sender(sndr_sock, host_ip, target_ip, host_port, port, SYN_FLAGSET)
        start_time = time.time()
        filtered = True
        try:
            while time.time() - start_time < timeinterval:
                rcvr_sock.settimeout(timeinterval*2)
                raw_data, addr = rcvr_sock.recvfrom(65535)
                rcvr_sock.settimeout(None)
                if TCP_Rcvd_Checker(raw_data, target_ip, port, SYNACK_FLAGSET): # port is open
                    open_ports.append(port)
                    filtered = False
                    time.sleep(timeinterval - (time.time() - start_time)) #wait till the interval is met and go to next port
                    break
                elif TCP_Rcvd_Checker(raw_data, target_ip, port, RSTACK_FLAGSET): # port is closed
                    close_ports.append(port)
                    filtered = False
                    time.sleep(timeinterval - (time.time() - start_time)) #wait till the interval is met and go to next port
                    break
        except: None
        if filtered == True: #timed out with no answer or all answers was wrong
            filtered_ports.append(port)
    return open_ports, close_ports, filtered_ports



# Main Function To perform FIN Scan
# Returns the List Of (Open | Filtered) Ports
# this function uses random port selection to prevent blocking
def FIN_Scan(sndr_sock: socket.socket, rcvr_sock : socket.socket, host_ip, target_ip, start_port, finish_port, freeports, timeinterval):
    open_filtered_ports = []
    for port in range(start_port, finish_port+1):
        host_port = random.randrange(freeports[0],freeports[1])
        TCP_Packet_Sender(sndr_sock, host_ip, target_ip, host_port, port, FIN_FLAGSET)
        start_time = time.time()
        filtered_open = True
        try:
            while time.time() - start_time < timeinterval:
                rcvr_sock.settimeout(timeinterval*2)
                raw_data, addr = rcvr_sock.recvfrom(65535)
                rcvr_sock.settimeout(None)
                if TCP_Rcvd_Checker(raw_data, target_ip, port, RSTACK_FLAGSET): # port is closed
                    filtered_open = False
                    time.sleep(timeinterval - (time.time() - start_time)) #wait till the interval is met and go to next port
                    break
        except: None
        if filtered_open == True: # timed out with no answer or all answers was wrong
            open_filtered_ports.append(port) 
    return open_filtered_ports




# Main Function To perform Window Scan
# Returns the List Of Open, Close and Filtered Ports
# this function uses random port selection to prevent blocking
def Window_scan(sndr_sock: socket.socket, rcvr_sock : socket.socket, host_ip, target_ip, start_port, finish_port, freeports, timeinterval):
    open_ports = []
    close_ports = []
    filtered_ports = []
    for port in range(start_port,finish_port+1):
        host_port = random.randrange(freeports[0],freeports[1])
        TCP_Packet_Sender(sndr_sock, host_ip, target_ip, host_port, port, ACK_FLAGSET)
        start_time = time.time()
        filtered = True
        try:
            while time.time() - start_time < timeinterval:
                rcvr_sock.settimeout(timeinterval*2)
                raw_data, addr = rcvr_sock.recvfrom(65535)
                rcvr_sock.settimeout(None)
                chckr_res = TCP_Rcvd_Checker_NonZero_Window(raw_data, target_ip, port, RST_FLAGSET)
                if chckr_res == 2: #port is open
                    open_ports.append(port)
                    filtered = False
                    time.sleep(timeinterval - (time.time() - start_time)) #wait till the interval is met and go to next port
                    break
                elif chckr_res == 1: # port is closed
                    close_ports.append(port)
                    filtered = False
                    time.sleep(timeinterval - (time.time() - start_time)) #wait till the interval is met and go to next port
                    break
        except: None
        if filtered == True: #timed out with no answer or all answers was wrong
            filtered_ports.append(port)
    return open_ports, close_ports, filtered_ports