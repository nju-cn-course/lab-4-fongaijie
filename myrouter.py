import time 
import switchyard
from switchyard.lib.userlib import *

class Router(object):
    def __init__(self,net:switchyard.llnetbase.LLNetBase):
        self.net=net
        self.ip_eth={}
        self.intf_ipaddr=[intf.ipaddr for intf in self.net.interfaces()]
        for i in self.intf_ipaddr:
            print(i)
        self.intf_ethaddr=[intf.ethaddr for intf in self.net.interfaces()]
        #[networkaddr,netmask,next_hop,intf]
        self.forwardingtable=[]
        self.build_forwardingtable()

        self.queue={}

    
    def handle_packet(self,recv:switchyard.llnetbase.ReceivedPacket):
        timestamp,ifaceName,packet=recv
        #debugger()

        #check the pkt dst MAC Address is in the intf of this router or not
        check=False
        for i in self.net.interfaces():
            if i.ethaddr == packet[Ethernet].dst:
                check=True
                break
        #if yes or MAC Address is broadcast,do it
        #else don't do anythinf
        if check or packet[Ethernet].dst=="ff:ff:ff:ff:ff:ff":
            pass
        else:
            return
        if packet[Ethernet].ethertype == 33024:
            return 

        
        if packet.has_header(Arp):
            arp=packet.get_header(Arp)
            #targetprotoaddr in self.intf_ipaddr means this arp pkt is send to this router
            if arp.targetprotoaddr in self.intf_ipaddr:
                print("ARP_SENDER_IP:",arp.senderprotoaddr," ARP_SENDER_ETH:",arp.senderhwaddr," ARP_TARGET_IP:",arp.targetprotoaddr)
                if arp.operation == ArpOperation.Request:
                    print("RECEIVE ARP_REQUEST")
                    #for i in self.intf_ipaddr:
                    #    print(i)
                    #if arp.senderhwaddr != "ff:ff:ff:ff:ff:ff":  
                    self.ip_eth[arp.senderprotoaddr]=arp.senderhwaddr
                    print("NEW IP_ETH: ",arp.senderprotoaddr," || ",arp.senderhwaddr)
                    intf_eth=self.net.interface_by_ipaddr(arp.targetprotoaddr).ethaddr
                    print("CREATE ARP_REPLY")
                    arp_response=create_ip_arp_reply(intf_eth,arp.senderhwaddr,arp.targetprotoaddr,arp.senderprotoaddr)
                    self.net.send_packet(ifaceName,arp_response)

                elif arp.operation == ArpOperation.Reply:
                    print("RECEIVE ARP_REPLY")
                    print("ARP_SENDER_IP:",arp.senderprotoaddr," ARP_SENDER_ETH:",arp.senderhwaddr," ARP_TARGET_IP:",arp.targetprotoaddr)
                    #router will bot believe any arp_reply pkt which senderhwaddr is broadcast
                    if arp.senderhwaddr == "ff:ff:ff:ff:ff:ff":
                        return
                    #check the targetprotoaddr intf is same with the intf receive this pkt or not
                    for i in self.net.interfaces():
                        if i.ipaddr == arp.targetprotoaddr:
                            if i.name != ifaceName:
                                return
                    print("NEW IP_ETH: ",arp.senderprotoaddr," || ",arp.senderhwaddr," || ",ifaceName)
                    
                    self.ip_eth[arp.senderprotoaddr]=arp.senderhwaddr
                    #renew the arp_table and check have any pkt in queue need to forward 
                    if arp.senderprotoaddr not in self.queue:
                        return
                    
                    self.clear_queue(arp)

        #do this first already
        #if packet[Ethernet].dst != "ff:ff:ff:ff:ff:ff" and packet[Ethernet].dst not in self.intf_ethaddr:
        #   return
        
        elif packet.has_header(IPv4):
            print("RECEIVE IPV4")
            ipv4_header=packet.get_header(IPv4)
            #ipv4_header.ttl-=1
            
            #mean this pkt is send to this router,no need  to do anything
            if ipv4_header.dst in self.intf_ipaddr:
                print('IPV4.dst in router')
                return

            else:
                matched=self.Found_Matching(ipv4_header.dst)
                if matched:
                    print("MATCH")
                    if matched[0]==None:
                        matched[0]=ipv4_header.dst
                    else:
                        matched[0]=IPv4Address(matched[0])
                    #bonus
                    if packet.has_header(UDP) and packet.get_header(UDP).src==0 and packet.get_header(UDP).dst==0:
                        return
                    #expired
                    if (ipv4_header.ttl-1) == 0:
                        print("TTL EXPIRED")
                        return
                    else:
                        print("PKT_NXT_HOP:",matched[0])
                        if matched[0] in self.ip_eth:
                            print("CONSRTUCT PKT")
                            fwdpkt=self.construct_forward_pkt(packet,matched[0],matched[1])
                            self.net.send_packet(matched[1],fwdpkt)
                        else:
                            if matched[0] in self.queue:
                                self.queue[matched[0]][0].append(packet)
                            else:
                                senderhwaddr=self.net.interface_by_name(matched[1]).ethaddr
                                senderprotoaddr=self.net.interface_by_name(matched[1]).ipaddr
                                arp_request=create_ip_arp_request(senderhwaddr,senderprotoaddr,matched[0])
                                self.net.send_packet(matched[1],arp_request)
                                self.queue[matched[0]]=[[packet],time.time(),4,matched[1]]
                            
                            print("IN QUEUE:")
                            for q in self.queue:
                                print("NEXT HOP: ",str(q)," || LENGTH: ",len(self.queue[q][0]))

                                



    

    def start(self):
        while True:
            self.check_queue()
            print("")
            try:
                recv=self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.stop()

    def check_queue(self):
        print("")
        print("CHECK_QUEUE")
        max_count_reached=[]
        for k in self.queue.keys():
            if time.time() - self.queue[k][1] >= 1.0:
                if self.queue[k][2] == 0:
                    max_count_reached.append(k)
                    continue
                senderhwaddr=self.net.interface_by_name(self.queue[k][3]).ethaddr
                senderprotoaddr=self.net.interface_by_name(self.queue[k][3]).ipaddr
                arp_request=create_ip_arp_request(senderhwaddr,senderprotoaddr,k)
                print("SEND ARP_REQ")
                print(type(k))
                self.net.send_packet(self.queue[k][3],arp_request)
                self.queue[k][1]=time.time()
                self.queue[k][2]-=1
        
        for k in max_count_reached:
            ##got something to do in lab 5
            del self.queue[k]
        print("END CHECK_QUEUE")

    def clear_queue(self,arp):
        print("CLEAR QUEUE")
        print(arp.senderprotoaddr)
        #for i in self.queue:
        #   print(i)
            
        #debugger()
        #print(type(arp.senderprotoaddr))

        if arp.senderprotoaddr in self.queue:
            print("arp.senderprotoaddr in self.queue")
            out_intf=self.queue[arp.senderprotoaddr][3]
            for pkt in self.queue[arp.senderprotoaddr][0]:
                print("CONSTRUCT")
                pkt[Ethernet].src=self.net.interface_by_name(out_intf).ethaddr
                pkt[Ethernet].dst=arp.senderhwaddr
                pkt[IPv4].ttl-=1
                #pkt=self.construct_forward_pkt(pkt,arp.senderprotoaddr,out_intf)
                print("END CONSTRUCT")
                print("SEND_PKT")
                self.net.send_packet(out_intf,pkt)
                print("SUCCESS SEND_PKT")
            del self.queue[arp.senderprotoaddr]

        print("END CLEAR QUEUE")

    def construct_forward_pkt(self,pkt,dst,out_intf):
        """
        ipheader=pkt.get_header(IPv4)
        icmpheader=pkt.get_header(ICMP)
        ipheader.ttl-=1
        """
        intf=self.net.interface_by_name(out_intf)
        """
        ethheader = Ethernet()
        ethheader.src=intf.ethaddr
        ethheader.dst=self.ip_eth[dst]
        ethheader.ethertype=EtherType.IPv4

        new_pkt=Packet()
        print(type(ethheader))
        print(type(ipheader))
        print(type(icmpheader))
        new_pkt=ethheader+ipheader+icmpheader
        """
        pkt[Ethernet].src =intf.ethaddr
        pkt[Ethernet].dst =self.ip_eth[dst]
        pkt[IPv4].ttl-=1
        return pkt

    def build_forwardingtable(self):
        for intf in self.net.interfaces():
            temp = []
            ip_network = str(intf.ipinterface.network)[:-3]
            temp.append(ip_network)
            temp.append(str(intf.netmask))
            temp.append(None)
            temp.append(intf.name)
            self.forwardingtable.append(temp)

        file = open("forwarding_table.txt","r")
        lines=file.readlines()
        for line in lines:
            word = line.split()
            self.forwardingtable.append(word)

    def Found_Matching(self,dest):
        max_macth=0
        curr_match=0
        nxt_hop_intf=[]#[nexthop,out_intf]
        for x in self.forwardingtable:
            networkaddr=IPv4Network('{}/{}'.format(x[0],x[1]))
            matches=(int(networkaddr.netmask)&int(dest))==int(networkaddr.network_address)
            if matches:
                curr_match=networkaddr.prefixlen
                if curr_match>max_macth:
                    max_macth=curr_match
                    nxt_hop_intf.clear()
                    nxt_hop_intf.append(x[2])
                    nxt_hop_intf.append(x[3])

        return nxt_hop_intf



    def stop(self):
        self.net.shutdown

def main(net):

    router=Router(net)
    router.start()