from scapy.all import IP,ICMP,TCP,sr1
import sys

#from Ethical Hacking:Hands-on Introduction to Breaking In
#by Daniel G. Graham 
#amazon : 

def icmp_probe(ip):
    'to check if host is connected'
    icmp_packet=IP(dst=ip)/ICMP()
    resp_packet=sr1(icmp_packet,timeout=10)
    return resp_packet is not None

def syn_scan(ip,port):
    'send a syn tcp packet return true if the flag is ack'
    
    tcp_packet=IP(dst=ip)/TCP(dport=port)
    print('Start Scanning Host : {}:{}'.format(ip,port))
    try:
        ack_flag=IP()/TCP(flags=18)
        #ack_flag[TCP].flags='A'
        ack_flag=ack_flag[TCP].flags
        resp_packet=sr1(tcp_packet,timeout=10)
        if  ack_flag in resp_packet[TCP].flags:
            reset_resp=sr1(IP(dst=ip)/TCP(dport=port,flags=4),timeout=10)
            print('\n\t\tport {} open !!\n\n'.format(port))
        else:
            print('\n\t\t port {} closed !! \n\n'.format(port))
        print('packet flags : {}'.format(resp_packet[TCP].flags))
        return resp_packet

    except Exception as e:
        print('Error While Sending Packet : {}'.format(e))
    pass


if __name__=='__main__':
    ip=sys.argv[1]
    port=int(sys.argv[2])
    if icmp_probe(ip):
        syn_ack_packet=syn_scan(ip,port)
        syn_ack_packet.show()
    else:
        print('ICMP Probe Failed !!!')
