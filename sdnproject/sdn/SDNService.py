
"""
An SDN Service orchectration and implementation system for CSC573 Team 7.
"""

from common import *
from SDNServiceAPI import SDNServiceAPI
from SDNFirewall import SDNFirewall
from SDNLoadBalancer import SDNLoadBalancer
from ExternalCache import ExternalCache

class SDNEngine():
    """Represents a sdn based multi-layer switch/router policy based forwarding engine."""


    def __init__(self, ryuapp, datapath, **kwargs):
        """Constructs a new SDNEngine.
           @param ryuapp An instance of a RyuApp that is using this router.
           @param datapath A Ryu datapath object associated with this router.
           @return A new instance of SDNEngine.
        """
        self.startime = time.time()
        self.debug = True
        self.priority = 10
        self.ryuapp = ryuapp
        self.datapath = datapath
        self.macTable = {}
        self.arpTable = {}
        # IP addresses 'owned' by the router for connected networks
        self.addresses = []
        # Packets that couldn't be sent because we need to ARP for them
        self.packetQueue = []
        # default server to send traffic to if lb is disabled and traffic for a VIP comes in
        self.defaultserver = '255.255.255.255'

        # we need to start with a clean slate and make sure all of the flows have been deleted from the datapath.
        self.deleteAllFlows()

        # we construct instances of the firewall, cache, and load balancer
        # even if disabled as they will need to be configured in case they are enabled in the future
        self.firewall = SDNFirewall(self,ryuapp,datapath)
        self.ecache = ExternalCache(self,ryuapp,datapath,"255.255.255.255")
        self.lb = SDNLoadBalancer(self,ryuapp,datapath)

    def delta(self):
        delta = time.time() - self.startime
        return "[Delta-T: %f] " % delta

    def purge(self):
        """purges the system to a default state."""
        self.firewall.purge()
        self.ecache.purge()
        self.lb.purge()
        self.deleteAllFlows()
        self.macTable = {}
        self.arpTable = {}
        self.packetQueue = []
        self.addresses = []
        self.defaultserver = '255.255.255.255'
        self.starttime = time.time()

    def setDefaultServer(self,ip):
        self.defaultserver = ip
        self.arpPrime(ip)

    def deleteAllFlows(self):
        """Called to delete all flows that we have installed onto the datapath.  We have seen that when FlowVisor re-connects
           it does not clear out any of the previous flows that were sent to the datapath."""

        # everything is a wildcard except for the VLAN which ExoGENI requires us to set
        match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN)

        self.ryuapp.logger.debug("%sSDNService.deleteAllFlows: The flow match is : %s" % (self.delta(),match))
        actions = []
        mod = self.datapath.ofproto_parser.OFPFlowMod(self.datapath,
                                                  match=match,
                                                  cookie=0,
                                                  command=self.datapath.ofproto.OFPFC_DELETE,
                                                  idle_timeout=0,
                                                  hard_timeout=0,
                                                  flags=0,
                                                  actions=actions)
        self.ryuapp.logger.debug("%sSDNFirewall.deleteAllFlows: The flow mod is : %s" % (self.delta(),mod))
        self.ryuapp.logger.debug("%sSDNFirewall.deleteAllFlows: Sending OpenFlow flowmod to datapath to delete all flows." % (self.delta()))
        self.datapath.send_msg(mod)


    def apiControl(self,message):
        """Processes the arguments passed to us from the REST API for further processing."""

        if message == "ping":
            return "pong"
        if message == "get-firewall-status":
            if self.firewall.enabled == True:
                return "enabled"
            return "disabled"
        if message == "get-cache-status":
            if self.ecache.enabled == True:
                return "enabled"
            return "disabled"
        if message == "get-loadbalancer-status":
            if self.lb.enabled == True:
                return "enabled"
            return "disabled"
        if message == "set-firewall-enabled":
            self.firewall.setEnabled(True)
            return "enabled"
        if message == "set-cache-enabled":
            self.ecache.setEnabled(True)
            return "enabled"        
        if message == "set-loadbalancer-enabled":
            self.lb.setEnabled(True)
            return "enabled"
        if message == "set-firewall-disabled":      
            self.firewall.setEnabled(False) 
            return "disabled"       
        if message == "set-cache-disabled":      
            self.ecache.setEnabled(False)
            return "disabled"       
        if message == "set-loadbalancer-disabled":
            self.lb.setEnabled(False)
            return "disabled"
        if message == "get-firewall-ruleset":
            # {'protocol' : protocol, 'header' : header, 'srcnet' : nsrcObj, 'dstnet' : ndstObj, 'psrc' : protocolSrc, 'pdst' : protocolDst, 'remark' : remark}
            rs = self.firewall.getRuleset()
            # make a deep copy of the ruleset so our changes here do not impact the real ruleset
            rs = copy.deepcopy(rs) 

            for r in rs:
                r['srcnet'] = str(r['srcnet'])
                r['dstnet'] = str(r['dstnet'])
            return json.dumps(rs)
        if message.startswith("delete-firewall-deny:"):
            # strip command prefix from string
            deny = message.replace("delete-firewall-deny:","")
            deny = json.loads(deny)
            self.firewall.deleteDeny(protocol=deny[0],srcNet=deny[1].replace("_","."),dstNet=deny[2].replace("_","."),protocolSrc=int(deny[3]),protocolDst=int(deny[4]),remark='')
            return "deleted"
        if message.startswith("add-firewall-deny:"):
            # strip command prefix from string
            add = message.replace("add-firewall-deny:","")
            add = json.loads(add)
            self.firewall.addDeny(protocol=add[0],srcNet=add[1].replace("_","."),dstNet=add[2].replace("_","."),protocolSrc=int(add[3]),protocolDst=int(add[4]),remark=add[5])
            return "added"
        if message == "get-lb-policy":
            # {'protocol' : protocol, 'header' : header, 'srcnet' : nsrcObj, 'dstnet' : ndstObj, 'psrc' : protocolSrc, 'pdst' : protocolDst, 'remark' : remark}
            rs = self.lb.getPolicy()
            # make a deep copy of the ruleset so our changes here do not impact the real ruleset
            rs = copy.deepcopy(rs)

            for r in rs:
                r['srcnet'] = str(r['srcnet'])
                r['dstnet'] = str(r['dstnet'])
            return json.dumps(rs)
        if message.startswith("delete-lb-policy:"):
            # strip command prefix from string
            p = message.replace("delete-lb-policy:","")
            p = json.loads(p)
            servers = p[5]
            for i in range(len(servers)):
                servers[i] = servers[i].replace("_",".")
            self.lb.deleteLBPolicy(protocol=p[0],srcNet=p[1].replace("_","."),dstNet=p[2].replace("_","."),protocolSrc=int(p[3]),protocolDst=int(p[4]),servers=servers,remark='')
            return "deleted"
        if message.startswith("add-lb-policy:"):
            # strip command prefix from string
            add = message.replace("add-lb-policy:","")
            add = json.loads(add)
            servers = add[5]
            for i in range(len(servers)):
                servers[i] = servers[i].replace("_",".")
            self.lb.addLBPolicy(protocol=add[0],srcNet=add[1].replace("_","."),dstNet=add[2].replace("_","."),protocolSrc=int(add[3]),protocolDst=int(add[4]),servers=servers,remark=add[6])
            return "added"
        if message.startswith("deploy:"):
            # strip command prefix from string
            config = message.replace("deploy:","")
            # lines of config are split with "\r\n" whitespace, build array of lines
            config = config.split("\r\n")
            cfg = []
            # skip comments starting with # and add other lines
            for i in range(len(config)):
                if config[i].startswith("#") == False:
                    cfg.append(config[i])
            # separate commands with ; to avoid whitespace issues in Python exec() call
            config = ";".join(cfg)
            self.ryuapp.logger.debug("%sSDNEngine.apiControl: Request received to deploy the following configuration: %s" % (self.delta(),config))
            exec(config)
            return "deployed"

        self.ryuapp.logger.debug("%sSDNEngine.apiControl(%s): Received a request to do something via the API that we don't know how to handle." % (self.delta,message))

    def packetIn(self, msg):
        """Processes a message (packet) sent to us by the controller.
           @param mst The packet sent to us by the controller.
           @return None
        """
        # attempt to parse the message into a Ryu Packet object
        pkt = packet.Packet(msg.data)

        # store the headers of the protocols in the packet into a convenient lookup dictionary
        headers = dict((p.protocol_name, p) for p in pkt.protocols if type(p) != str)

        # learn the port that the source MAC showed up on
        self.learnMac(msg.in_port, headers[ETHERNET].src)

        # we pass the packet to the firewall, if it is enabled, it will process it internally as needed.
        result = self.firewall.packetIn(msg,pkt,headers)

        if result == "deny":
            return

        # we pass the packet to the cache, if it is enabled, it will process it internally as needed.
        result = self.ecache.packetIn(msg,pkt,headers)

        if result == "forward":
            return

        # we pass the packet to the load balancer, if it is enabled, it will process it internally as needed.
        result = self.lb.packetIn(msg,pkt,headers)

        if result == "loadbalanced":
            return

        # if we got here then the packet was not dropped by the firewall and was not processed by the cache or the load balancer

        # decide what to do based on the type of packet we received
        if ARP in headers:
            self.arpIn(msg,pkt,headers)
        elif ICMP in headers:
            self.icmpIn(msg,pkt,headers)
        elif TCP in headers:
            self.tcpUdpIn(msg,pkt,headers)
        elif UDP in headers:
            self.tcpUdpIn(msg,pkt,headers)
        else:
            self.ryuapp.logger.debug("%sSDNEngine.packetIn: Recieved [%s] but we aren't ready to deal with it yet." % (self.delta(),str(pkt)))
        
    
    def learnMac(self, port, mac):
        """Installs the specified mac address into the mac address table.
           @param port - the port number the mac address was seen on.
           @param mac  - the mac address to learn.
           @return None
        """
        if mac in self.macTable:
            if self.macTable[mac]['port'] == port:
                self.macTable[mac]['timestamp'] = time.time()
                self.ryuapp.logger.debug("%sSDNEngine.learnMac[time-update]: %s" % (self.delta(),str(self.macTable[mac])))
            else:
                # the mac moved to a different port - update mapping
                self.macTable[mac]['port'] = port
                self.macTable[mac]['timestamp'] = time.time()
                self.ryuapp.logger.debug("%sSDNEngine.learnMac[port-move]: %s" % (self.delta(),str(self.macTable[mac])))
        else:
            self.macTable[mac] = {'mac' : mac, 'port' : port, 'timestamp' : time.time() }
            self.ryuapp.logger.debug("%sSDNEngine.learnMac[learning]: %s" % (self.delta(),str(self.macTable[mac])))

        if self.debug == False:
            # add flow mod to datapath to enable learning multi-layer switch functionality

            match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,
                                                          dl_dst = haddr_to_bin(mac),
                                                          dl_type = ether.ETH_TYPE_IP)

            self.ryuapp.logger.debug("%sSDNEngine.learnMac: The flow match is : %s" % (self.delta(),match))
            # send the frame out the port facing the host
            actions = [self.datapath.ofproto_parser.OFPActionOutput(port)]

            mod = self.datapath.ofproto_parser.OFPFlowMod(self.datapath,
                                                  match,
                                                  cookie=0,
                                                  command=self.datapath.ofproto.OFPFC_ADD,
                                                  idle_timeout=0,
                                                  hard_timeout=0,
                                                  priority=self.priority,
                                                  flags=0,
                                                  actions=actions)
            self.ryuapp.logger.debug("%sSDNEngine.learnMac: The flow mod is : %s" % (self.delta(),mod))
            self.ryuapp.logger.debug("%sSDNEngine.learnMac: Sending OpenFlow flowmod to datapath." % (self.delta()))
            self.datapath.send_msg(mod)

    
    def learnArp(self, ip, mac):
        """Installs the specified ip/mac combo into the ARP cache table.
           @param ip - the IP address in dot-quad A.B.C.D string format.
           @param mac - the MAC address in aa:bb:cc:dd:ee:ff string format.
           @return None
        """
        # we do not want to "learn" one of our own IP addresses...
        for address in self.addresses:
            if str(address.ip) == ip:
                self.ryuapp.logger.debug("%sSDNEngine.learnArp(): Skipping learning one of 'our' IP addresses: %s" % (self.delta(),ip))
                return

        if ip in self.arpTable:
            if self.arpTable[ip]['mac'] == mac:
                self.arpTable[ip]['timestamp'] = time.time()
                self.ryuapp.logger.debug("%sSDNEngine.learnArp()[time-update]: %s" % (self.delta(),str(self.arpTable[ip])))
            else:
                # the ip is now associated with a different mac - update mapping
                self.arpTable[ip]['mac'] = mac
                self.arpTable[ip]['timestamp'] = time.time()
                self.ryuapp.logger.debug("%sSDNEngine.learnArp()[mac-move]: %s" % (self.delta(),str(self.arpTable[ip])))
        else:
            self.arpTable[ip] = {'mac' : mac, 'ip' : ip, 'timestamp' : time.time() }
            self.ryuapp.logger.debug("%sSDNEngine.learnArp()[learning]: %s" % (self.delta(),str(self.arpTable[ip])))

        if self.debug == False and self.macTable.has_key(mac):
            # add flow mod to datapath to enable learning multi-layer switch functionality

            match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,
                                                          # host is sending to gateway, whose address is specified below
                                                          #dl_dst = haddr_to_bin("a8:97:dc:87:8e:00"),
                                                          dl_type = ether.ETH_TYPE_IP,
                                                          nw_dst  = ipv4_to_int(ip),
                                                          #nw_dst_mask = 32
                                                          )

            self.ryuapp.logger.debug("%sSDNEngine.learnArp: Creating Host L3 Binding - the flow match is : %s" % (self.delta(),match))
            # send the frame out the port facing the host
            # we need to set the mac to that of the host in case it was sent to a gateway
            actions = [self.datapath.ofproto_parser.OFPActionSetDlDst(haddr_to_bin(mac)),
                       self.datapath.ofproto_parser.OFPActionOutput(self.macTable[mac]['port'])]

            mod = self.datapath.ofproto_parser.OFPFlowMod(self.datapath,
                                                  match,
                                                  cookie=0,
                                                  command=self.datapath.ofproto.OFPFC_ADD,
                                                  idle_timeout=0,
                                                  hard_timeout=0,
                                                  priority=self.priority+1,
                                                  flags=0,
                                                  actions=actions)
            self.ryuapp.logger.debug("%sSDNEngine.learnArp: Creating Host L3 Binding - the flow mod is : %s" % (self.delta(),mod))
            self.ryuapp.logger.debug("%sSDNEngine.learnArp: Sending OpenFlow flowmod to datapath." % (self.delta()))
            self.datapath.send_msg(mod)


    def addAddress(self,address):
        """Adds an IP interface to this router.
           @param address An IPv4 address in CIDR notation such as A.B.C.D/X
           @return None
        """
        self.addresses.append(netaddr.IPNetwork(address))
        self.ryuapp.logger.debug("%sSDNEngine.addAddress: address %s added.  List: %s" % (self.delta(),address,str(self.addresses)))

    def tcpUdpIn(self,msg,pkt,headers):
        """Processes a TCP/UDP segment received by the datapath.
           @param msg The original un-touched message from the datapath.
           @param pkt The parsed Packet object representing msg.
           @param headers The headers contained within the pkt as a convenient dictionary.
           @return None
        """
        if TCP not in headers and UDP not in headers:
            self.ryuapp.logger.debug("%sSDNEngine.tcpUdpIn: Ignoring non-TCP/UDP segment that we received: %s." % (self.delta(),str(pkt)))
            return

        # we don't have much to do here except to see if the TCP/UDP segment
        # is destined to a router interface which we will drop as that is not allowed
        # if that is not the case, then we will forward it.

        for address in self.addresses:
            if str(address.ip) == headers[IPV4].dst:
                self.ryuapp.logger.debug("%sSDNEngine.tcpUdpIn: We received a TCP/UDP segment to a router interface - seeing if it is to a vip: %s." % (self.delta(),str(pkt)))
                # theoretically we could send an ICMP error message here...
                # but in the real world most routers are configured to not 
                # do that as it can DOS the CPU
                # if we got here, the load balancer must not have matched anything (possibly disabled)
                # we always said that anything destined to a VIP would go to the first server in that case
                # we know if it is a vip if it has a /32 mask
                if address.prefixlen == 32:
                    self.arpPrime(self.defaultserver)
                    if not self.arpTable.has_key(self.defaultserver):
                        self.ryuapp.logger.debug("%sArpTable contains no entry for the default server: %s - discarding" % (self.delta(),self.defaultserver))
                        self.arpPrime(self.defaultserver)
                        return                    
                    acache = self.arpTable[self.defaultserver]

                    data = None
                    if msg.buffer_id == self.datapath.ofproto.OFP_NO_BUFFER:
                        data = msg.data

                    # in order to avoid flooding, we want to see if we have a MAC address table entry
                        port = self.datapath.ofproto.OFPP_FLOOD
                    if acache['mac'] in self.macTable:
                        mcache = self.macTable[acache['mac']]
                        port = mcache['port']

                    actions = [self.datapath.ofproto_parser.OFPActionSetDlDst(haddr_to_bin(acache['mac'])),
                               self.datapath.ofproto_parser.OFPActionOutput(port)]

                    out = self.datapath.ofproto_parser.OFPPacketOut(
                              datapath=self.datapath,
                              buffer_id=msg.buffer_id,
                              in_port=msg.in_port,
                              actions=actions,
                              data=data)
                    self.datapath.send_msg(out)
                    self.ryuapp.logger.debug("%sSDNEngine.tcpUdpIn: We just forwarded this TCP/UDP segment %s which was destined to a VIP to the default server: %s" % (self.delta(),str(pkt),self.defaultserver))
                    return
                
                # we don't want to process the tcp/udp packet destined to us unless it was to a vip above and lb is not handline it.
                self.ryuapp.logger.debug("%sSDNEngine.tcpUdpIn: We received a TCP/UDP segment to a router interface - skipping: %s." % (self.delta(),str(pkt)))
                return

        # now we will attempt to forward the packet 
        # we need to see if we have an ARP cache entry for the destination address
        if headers[IPV4].dst in self.arpTable:
            acache = self.arpTable[headers[IPV4].dst]

            data = None
            if msg.buffer_id == self.datapath.ofproto.OFP_NO_BUFFER:
                data = msg.data

            # in order to avoid flooding, we want to see if we have a MAC address table entry
            port = self.datapath.ofproto.OFPP_FLOOD
            if acache['mac'] in self.macTable:
                mcache = self.macTable[acache['mac']]
                port = mcache['port']

            actions = [self.datapath.ofproto_parser.OFPActionSetDlDst(haddr_to_bin(acache['mac'])),
                       self.datapath.ofproto_parser.OFPActionOutput(port)]

            out = self.datapath.ofproto_parser.OFPPacketOut(
                      datapath=self.datapath,
                      buffer_id=msg.buffer_id,
                      in_port=msg.in_port,
                      actions=actions,
                      data=data)
            self.datapath.send_msg(out)
            self.ryuapp.logger.debug("%sSDNEngine.tcpUdpIn: We just forwarded this TCP/UDP segment: %s" % (self.delta(),str(pkt)))
        else:
            self.ryuapp.logger.debug("%sSDNEngine.tcpUdpIn: We have a TCP/UDP segment to send but no ARP cache entry: %s" % (self.delta(),str(pkt)))
            # save the message to try to send later...
            self.packetQueue.append({'msg' : msg, 'pkt' : pkt, 'headers' : headers, 'timestamp' : time.time()})
            # now we need to generate an ARP to prime our cache for the previous message
            self._sendArp(arpOpCode=arp.ARP_REQUEST,
                          vlanId=SYSTEM_VLAN,
                          srcMac=self.datapath.ports.values()[0].hw_addr,
                          dstMac='ff:ff:ff:ff:ff:ff',
                          arpMac='00:00:00:00:00:00',
                          srcIp=str(self.addresses[0].ip),
                          dstIp=headers[IPV4].dst,
                          outPort=self.datapath.ofproto.OFPP_FLOOD)

    def arpPrime(self,dstIp):
        """Helper utility to prime the ARP cache with interesting destination IP addresses
           such as those of administrator configured objects like servers, etc.
           @param dstIp The destination IP we need to have primed in the arpTable.
        """
        if self.arpTable.has_key(dstIp):
            return
        # try to select the best address to use for the source
        srcIp = '255.255.255.255'

        for address in self.addresses:
            if dstIp in address:
                srcIp = str(address.ip)
                break

        self._sendArp(arpOpCode=arp.ARP_REQUEST,
                      vlanId=SYSTEM_VLAN,
                      srcMac=self.datapath.ports.values()[0].hw_addr,
                      dstMac='ff:ff:ff:ff:ff:ff',
                      arpMac='00:00:00:00:00:00',
                      srcIp=str(srcIp),
                      dstIp=dstIp,
                      outPort=self.datapath.ofproto.OFPP_FLOOD)

        # pause a bit for responses to come back so we can handle via arpIn()
        time.sleep(0.1)

    def arpIn(self,msg,pkt,headers):
        """Processes an ARP packet received by the datapath.
           @param msg The original un-touched message from the datapath.
           @param pkt The parsed Packet object representing msg.
           @param headers The headers contained within the pkt as a convenient dictionary.
           @return None
        """
        if ARP not in headers:
            self.ryuapp.logger.debug("%sSDNEngine.arpIn: Ignoring non-ARP packet that we received: %s." % (self.delta(),str(pkt)))
            return

        a = headers[ARP]
     
        # we want to populate our ARP table with data (source on ARP requests and source on ARP replies)
        self.learnArp(a.src_ip,a.src_mac)

        if a.opcode == arp.ARP_REQUEST:
            # see if it is an ARP request destined to one of our router interfaces
            for address in self.addresses:
                if str(address.ip) == a.dst_ip:
                    self.ryuapp.logger.debug("%sSDNEngine.arpIn: We received an ARP request for a router interface and are replying." % (self.delta()))
                    self._sendArp(arpOpCode=arp.ARP_REPLY,
                                  vlanId=SYSTEM_VLAN,
                                  srcMac=self.datapath.ports.values()[0].hw_addr,
                                  dstMac=a.src_mac,
                                  #arpMac=a.src_mac,
                                  arpMac=self.datapath.ports.values()[0].hw_addr,
                                  srcIp=a.dst_ip,
                                  dstIp=a.src_ip,
                                  outPort=msg.in_port)
                    return

        elif a.opcode == arp.ARP_REPLY:
            # see if it is an ARP reply destined to one of our router interfaces
            for address in self.addresses:
                if(str(address.ip) == a.dst_ip):
                    # it is destined to one of our router interfaces - we may have
                    # initiated the ARP_REQUEST that caused this ARP_REPLY because 
                    # we have packets to deliver and need the destination MAC address
                    # if these packets are in our queue we need to service them...
                    self.ryuapp.logger.debug("%sSDNEngine.arpIn: We received an ARP reply for a router interface we need to send any queued packets." % (self.delta()))
                    self.ryuapp.logger.debug("%sSDNEngine.arpIn: packetQueue prior to analysis [%s]" % (self.delta(),str(self.packetQueue)))
                    packetStaleIfOlderThan = time.time() - 60;
                    for qpacket in self.packetQueue:
                        if qpacket['timestamp'] < packetStaleIfOlderThan:
                            self.packetQueue.remove(qpacket)
                        elif IPV4 in qpacket['headers'] and qpacket['headers'][IPV4].dst == a.src_ip:
                            # we have a match - send this queued packet
                            self.packetIn(qpacket['msg'])
                            self.packetQueue.remove(qpacket)
                    self.ryuapp.logger.debug("%sSDNEngine.arpIn: packetQueue post ARP_REPLY handling [%s]" % (self.delta(),str(self.packetQueue)))
                    return

        # let's just flood it out so everyone else can handle it since it wasn't a request to us directly
        data = None
        if msg.buffer_id == self.datapath.ofproto.OFP_NO_BUFFER:
            data = msg.data

        actions = [self.datapath.ofproto_parser.OFPActionOutput(self.datapath.ofproto.OFPP_FLOOD)]

        out = self.datapath.ofproto_parser.OFPPacketOut(
                  datapath=self.datapath,
                  buffer_id=msg.buffer_id, 
                  in_port=msg.in_port,
                  actions=actions,
                  data=data)
        self.datapath.send_msg(out)
        self.ryuapp.logger.debug("%sSDNEngine.arpIn: We just flooded this ARP packet: %s" % (self.delta(),str(pkt)))

 
    def icmpIn(self,msg,pkt,headers):
        """Processes an ICMP packet received by the datapath.
           @param msg The original un-touched message from the datapath. 
           @param pkt The parsed Packet object representing msg.
           @param headers The headers contained within the pkt as a convenient dictionary.
           @return None
        """
        if ICMP not in headers:
            self.ryuapp.logger.debug("%sSDNEngine.icmpIn: Ignoring non-ICMP packet that we received: %s." % (self.delta(),str(pkt)))
            return
 

        if headers[ICMP].type == icmp.ICMP_ECHO_REQUEST:
            # see if this is an ICMP echo request desgined to one of our router interfaces
            for address in self.addresses:
                if str(address.ip) == headers[IPV4].dst:
                    self.ryuapp.logger.debug("%sSDNEngine.icmpIn (%f): We received an ICMP echo request for a router interface and are replying." % (self.delta(),time.time()))
                    self.ryuapp.logger.debug("%sSleeping for 200ms to introduce debugging delay" % (self.delta()))
                    time.sleep(0.2)
                    self._sendIcmp(icmpType=icmp.ICMP_ECHO_REPLY,
                                   icmpCode=icmp.ICMP_ECHO_REPLY_CODE,
                                   icmpData=headers[ICMP].data,
                                   vlanId=SYSTEM_VLAN,
                                   srcMac=headers[ETHERNET].dst,
                                   dstMac=headers[ETHERNET].src,
                                   srcIp=headers[IPV4].dst,
                                   dstIp=headers[IPV4].src,
                                   outPort=msg.in_port)
                    return

        # now we need to try to send this out since it was not destined to us.
        data = None
        if msg.buffer_id == self.datapath.ofproto.OFP_NO_BUFFER:
            data = msg.data

        # we need to see if we have an ARP cache entry for the destination address
        if headers[IPV4].dst in self.arpTable:
            acache = self.arpTable[headers[IPV4].dst]

            # in order to avoid flooding, we want to see if we have a MAC address table entry
            port = self.datapath.ofproto.OFPP_FLOOD
            if acache['mac'] in self.macTable:
                mcache = self.macTable[acache['mac']]
                port = mcache['port']

            actions = [self.datapath.ofproto_parser.OFPActionSetDlDst(haddr_to_bin(acache['mac'])), 
                       self.datapath.ofproto_parser.OFPActionOutput(port)]

            out = self.datapath.ofproto_parser.OFPPacketOut(
                      datapath=self.datapath,
                      buffer_id=msg.buffer_id,
                      in_port=msg.in_port,
                      actions=actions,
                      data=data)
            self.datapath.send_msg(out)
            self.ryuapp.logger.debug("%sSDNEngine.icmpIn: We just forwarded this ICMP packet: %s" % (self.delta(),str(pkt)))
        else:
            self.ryuapp.logger.debug("%sSDNEngine.icmpIn: We have an ICMP packet to send but no ARP cache entry: %s" % (self.delta(),str(pkt)))
            # save the message to try to send later...
            self.packetQueue.append({'msg' : msg, 'pkt' : pkt, 'headers' : headers, 'timestamp' : time.time()})
            # now we need to generate an ARP to prime our cache for the previous message
            self._sendArp(arpOpCode=arp.ARP_REQUEST,
                          vlanId=SYSTEM_VLAN,
                          srcMac=self.datapath.ports.values()[0].hw_addr,
                          dstMac='ff:ff:ff:ff:ff:ff',
                          arpMac='00:00:00:00:00:00',
                          srcIp=str(self.addresses[0].ip),
                          dstIp=headers[IPV4].dst,
                          outPort=self.datapath.ofproto.OFPP_FLOOD)

    def _sendIcmp(self,icmpType,icmpCode,icmpData,vlanId,srcMac,dstMac,srcIp,dstIp,outPort):
        """
        """
        etherProto = ether.ETH_TYPE_IP
        v = None
      
        if vlanId != VLANID_NONE:
            etherProto = ether.ETH_TYPE_8021Q
            v = vlan.vlan(0,0,vlanId,ether.ETH_TYPE_IP)

        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(dstMac,srcMac,etherProto))
        if v != None:
            pkt.add_protocol(v)
        pkt.add_protocol(ipv4.ipv4(dst=dstIp,src=srcIp,proto=in_proto.IPPROTO_ICMP))
        pkt.add_protocol(icmp.icmp(type_=icmpType,code=icmpCode,csum=0,data=icmpData))
        pkt.serialize()

        # send the packet
        actions = [self.datapath.ofproto_parser.OFPActionOutput(port=outPort)]
        out = self.datapath.ofproto_parser.OFPPacketOut(
            datapath=self.datapath,
            buffer_id=self.datapath.ofproto.OFP_NO_BUFFER,
            in_port=self.datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt.data)
        self.datapath.send_msg(out)
        self.ryuapp.logger.debug("%sSDNEngine._sendIcmp: Sent ICMP packet: %s" % (self.delta(),str(pkt)))

        

    def _sendArp(self,arpOpCode,vlanId,srcMac,dstMac,arpMac,srcIp,dstIp,outPort):
        """
        """
        # construct arp packet
        etherProto = ether.ETH_TYPE_ARP
        v = None

        if vlanId != VLANID_NONE:
            etherProto = ether.ETH_TYPE_8021Q
            v = vlan.vlan(0,0,vlanId,ether.ETH_TYPE_ARP) 

        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(dstMac,srcMac,etherProto))
        if v != None:
            pkt.add_protocol(v)
        pkt.add_protocol(arp.arp(hwtype=arp.ARP_HW_TYPE_ETHERNET,
                                 proto=ether.ETH_TYPE_IP,
                                 hlen=6, # mac address = 6 bytes 
                                 plen=4, # ipv4 address = 4 bytes
                                 opcode=arpOpCode,
                                 src_mac=srcMac,
                                 src_ip=srcIp,
                                 dst_mac=arpMac,
                                 dst_ip=dstIp))

        pkt.serialize()

        # send the packet
        actions = [self.datapath.ofproto_parser.OFPActionOutput(port=outPort)] # 0 = no maximum length
        out = self.datapath.ofproto_parser.OFPPacketOut(
            datapath=self.datapath,
            buffer_id=self.datapath.ofproto.OFP_NO_BUFFER,
            in_port=self.datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt.data)
        self.datapath.send_msg(out)
        self.ryuapp.logger.debug("%sSent ARP packet: %s" % (self.delta(),str(pkt)))
        

class SDNService(app_manager.RyuApp):

    _CONTEXTS = { 'wsgi' : WSGIApplication }

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNService, self).__init__(*args, **kwargs)
        self.dp = {}

        # configure the Ryu WSGI environment for the REST API
        wsgi = kwargs['wsgi']
        wsgi.register(SDNServiceAPI, { REST_API_NAME : self })

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self,ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto

        self.logger.debug("SDNService._packet_in_handler: Sending message [%s] to SDNEngine for packetIn()." % (str(msg)))
        self.dp[dpid]['engine'].packetIn(msg)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self,ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto

        self.logger.debug("SDNService._switch_features_handler: OFPSwitchFeatures received: datapath_id=0x%016x n_buffers=%d n_tables=%d capabilities=0x%08x" % (msg.datapath_id, msg.n_buffers, msg.n_tables, msg.capabilities))

        if dpid not in self.dp:
            # we have not seen this datapath before, save it and construct environment
            self.dp[dpid] = {'engine' : SDNEngine(self,datapath),
                             'datapath' : datapath,
                             'dpid' : datapath.id}

        self.logger.debug("SDNService._switch_features_handler: Constructing SDNEngine due to datapath connection." )


    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("SDNService._port_status_handler: port added %s" % (port_no))
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("SDNService._port_status_handler: port deleted %s" % (port_no))
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("SDNService._port_status_handler: port modified %s" % (port_no))
        else:
            self.logger.info("SDNService._port_status_handler: Illeagal port state %s %s" % (port_no, reason))


