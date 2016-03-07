from common import *

class SDNLoadBalancer():
    """Represents an SDN based load balancer."""
    def __init__(self, sdnengine, ryuapp, datapath):
        """Constructs a new SDNLoadBalancer.
           @param sdnengine An instance of the SDNEngine that is using this load balancer
           @param ryuapp An instance of a RyuApp that is using this load balancer.
           @param datapath A Ryu datapath object associated with this load balancer.
           @return A new instance of SDNLoadBalancer.
        """
        self.sdnengine = sdnengine
        self.ryuapp = ryuapp
        self.datapath = datapath
        self.servers = []
        self.lbpolicy = []
        self.roundrobin = {}
        self.debug = True
        self.enabled = False
        self.priority = 2222

    def purge(self):
        self.deleteAllFlows()
        self.lbpolicy = []
        self.roundrobin = {}

    def getPolicy(self):
        return self.lbpolicy

    def setDebug(self,value):
        self.debug = value
        self.execute()

    def setEnabled(self,value):
        self.enabled = value
        self.execute()

    def execute(self):
        """Updates the state of this module based on the flags "debug" and "enabled"."""
        if (self.debug==True and self.enabled== True):
            self.deleteAllFlows()
        if (self.debug==True and self.enabled== False):
            self.deleteAllFlows()
        if (self.debug==False and self.enabled== True):
            self.addAllFlows()
        if (self.debug==False and self.enabled== False):
            self.deleteAllFlows()

    def addAllFlows(self):
        # there is nothing to do here as we only add flows in the load balancer during packetIn where
        # we process the flow for the first time so we can make a server selection via roundrobin algorithm
        pass

    def deleteAllFlows(self):
        # note that here we are trying a new approach with OFPFC_DELETE_STRICT 
        # that will strictly match on priority - this should remove complications of us not storing client's actual IP and source port
        match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,dl_type = ether.ETH_TYPE_IP)

        self.ryuapp.logger.debug("%s SDNLoadBalancer.deleteAllFlows: !!!!!!! The flow match is : %s" %( self.sdnengine.delta(),match))

        actions = []

        mod = self.datapath.ofproto_parser.OFPFlowMod(self.datapath,
                                                  match,
                                                  cookie=0,
                                                  command=self.datapath.ofproto.OFPFC_DELETE_STRICT,
                                                  idle_timeout=0,
                                                  hard_timeout=0,
                                                  priority=self.priority,
                                                  flags=0,
                                                  actions=actions)


        self.ryuapp.logger.debug("%s SDNLoadBalancer.deleteAllFlows: !!!!!!!!!! The flow mod is : %s" %(self.sdnengine.delta(), mod))
        self.ryuapp.logger.debug("%s SDNLoadBalancer.deleteAllFlows: !!!!!!!!!! Sending OpenFlow flowmod to datapath to drop rules from flow table." %self.sdnengine.delta())
        self.datapath.send_msg(mod)

        return



    def addLBPolicy(self,servers,protocol,srcNet,dstNet,protocolSrc=0,protocolDst=0,remark=''):
        """Adds a load balance policy such that traffic that matches the specification is load balanced to the servers specified.
           @param servers A list of server IPv4 addresses in A.B.C.D dot-quad format: ["a.b.c.d","e.f.g.h"]
           @param protocol A string that can be one of "TCP", "UDP".
           @param srcNet A string dot-quad source IPv4 address: "A.B.C.D/Z" in CIDR notation.
           @param dstNet A string dot-quad destination IPv4 address: "A.B.C.D/Z" in CIDR notation: "A.B.C.D/Z".
           @param protocolSrc Only examined with protocol =~ /TCP|UDP/ and should be an integer source port. Value 0 = ignore (a wildcard)
           @param protocolDst Only examined with protocol =~ /TCP|UDP/ and should be an integer destination port. Value 0 = ignore (a wildcard)
        """
        if protocol == "TCP":
            header = TCP
        elif protocol == "UDP":
            header = UDP
        else:
            self.ryuapp.logger.debug("%s SDNLoadBalancer.addLBPolicy: Invalid protocol specified => skipping: %s" % (self.sdnengine.delta(),protocol))

        self.lbpolicy.append({'servers': servers, 'lastserver': -1, 'protocol' : protocol, 'header' : header, 'srcnet' : netaddr.IPNetwork(srcNet), 'dstnet' : netaddr.IPNetwork(dstNet), 'psrc' : int(protocolSrc), 'pdst' : int(protocolDst), 'remark' : remark})

        # prime the ARP cache for the servers
        for server in servers:
            self.sdnengine.arpPrime(server)

        if self.enabled == True and self.debug == False:
            # there is nothing to do here as we only add flows in the load balancer during packetIn where
            # we process the flow for the first time so we can make a server selection via roundrobin algorithm
            pass

    def deleteLBPolicy(self,servers,protocol,srcNet,dstNet,protocolSrc=0,protocolDst=0,remark=''):
        """Deletes a DENY rule to the load balancer based on the specified parameters:
           @param servers A list of server IPv4 addresses in "A.B.C.D" dot-quad format ["a.b.c.d","e.f.g.h"]
           @param protocol A string that can be one of "IP", "ICMP", "TCP", "UDP".
           @param srcNet A string dot-quad source IPv4 address: "A.B.C.D/Z" in CIDR notation.
           @param dstNet A string dot-quad destination IPv4 address: "A.B.C.D/Z" in CIDR notation: "A.B.C.D/Z".
           @param protocolSrc Only examined with protocol =~ /TCP|UDP/ and should be an integer source port. Value 0 = ignore (a wildcard)
           @param protocolDst Only examined with protocol =~ /TCP|UDP/ and should be an integer destination port. Value 0 = ignore (a wildcard)
        """
        for i in range(len(self.lbpolicy)):
            if(self.lbpolicy[i]['servers'] == servers and
               self.lbpolicy[i]['protocol'] == protocol and
               self.lbpolicy[i]['srcnet'] == netaddr.IPNetwork(srcNet) and
               self.lbpolicy[i]['dstnet'] == netaddr.IPNetwork(dstNet) and
               int(self.lbpolicy[i]['psrc']) == int(protocolSrc) and
               int(self.lbpolicy[i]['pdst']) == int(protocolDst)):
                del(self.lbpolicy[i])
                break

        if self.enabled == True and self.debug == False:
            # there is nothing to do here as we only delete individual flows at idle-timeout or 
            # we can delete all flows if we diable the load balancer as a whole.
            pass


    def roundRobin(self,policy,headers):
        """Performs a round-robin server selection based on the specific policy and packet with the specified headers."""
        self.ryuapp.logger.debug("%sSDNEngine.roundRobin(%s,%s): contents of self.roundrobin: %s" % (self.sdnengine.delta(), policy,headers,self.roundrobin))
        if headers[TCP]:
            key = "%s:%s=>%s:%s" % (headers[IPV4].src,headers[TCP].src_port,headers[IPV4].dst,headers[TCP].dst_port)
        elif headers[UDP]:
            key = "%s:%s=>%s:%s" % (headers[IPV4].src,headers[UDP].src_port,headers[IPV4].dst,headers[UDP].dst_port)
        if key in self.roundrobin:
            if( (time.time() - self.roundrobin[key]['timestamp']) > LB_STICKY_TIMEOUT):
                # we have not seen packets from this guy in a while, the stickyness is lost, select a new server
                self.roundrobin[key]['timestamp'] = time.time()
                # return the next server
                next_index = ( ( policy['servers'].index(self.roundrobin[key]['server']) + 1) % len(policy['servers']))
                self.roundrobin[key]['server'] = policy['servers'][next_index]
                self.ryuapp.logger.debug("%sSDNEngine.roundRobin(%s,%s): Sticky Timeout : Selecting next server: %s" % (self.sdnengine.delta(), policy,headers,str(self.roundrobin[key]['server'])))
                return self.roundrobin[key]['server']
            else:
                self.roundrobin[key]['timestamp'] = time.time()
                self.ryuapp.logger.debug("%sSDNEngine.roundRobin(%s,%s): Sticky Persistence : Selecting current server: %s" % (self.sdnengine.delta(), policy,headers,str(self.roundrobin[key]['server'])))
                return self.roundrobin[key]['server']

        else:
            # we have never seen this guy before... 
            # update the 'last server' handled out in this case to point to one of the other servers
            # for variety and to demonstrate that the load balancer actually works
            policy['lastserver'] = (policy['lastserver'] + 1) % len(policy['servers'])

            self.roundrobin[key] = {'server' : policy['servers'][policy['lastserver']], 'timestamp' : time.time() }
            self.ryuapp.logger.debug("%sSDNEngine.roundRobin(%s,%s): %s" % (self.sdnengine.delta(), policy,headers,str(self.roundrobin[key])))
            return policy['servers'][policy['lastserver']]

    def packetIn(self,msg,pkt,headers):
        """Processes a message (packet) sent to us by the controller.
           @param msg The packet sent to us by the controller.
           @param pkt The parsed Packet object representation of the message
           @param headers The headers contained in the pkt for quick analysis
           @return "permit" if the packet was permitted, else "deny" if the packet should be denied
        """
        if self.enabled == False:
            return "notloadbalanced"

        if TCP not in headers and UDP not in headers:
            self.ryuapp.logger.debug("%sSDNLoadBalancer.packetIn: Non TCP/UDP packet sent to us, skipping %s" % (self.sdnengine.delta(), pkt))
            return "notloadbalanced"

        # we need to loop through and see if the packet matches something in our lbpolicy list and if so, take action
        self.ryuapp.logger.debug("%sSDNLoadBalancer.packetIn: checking to see if this packet should be load balanced: %s" %(self.sdnengine.delta(),  pkt))
        action ="notloadbalanced"
        policy = None
        for rule in self.lbpolicy:
            if rule['header'] in headers:
                # now we check more specific parameters
                srcip = netaddr.IPAddress(headers[IPV4].src)
                dstip = netaddr.IPAddress(headers[IPV4].dst)
                self.ryuapp.logger.debug("%sSDNLoadBalancer.packetIn: checking rule: %s src: %s ; dst: %s for match..." %(self.sdnengine.delta(), rule,srcip,dstip))
                if srcip in rule['srcnet'] and dstip in rule['dstnet']:
                    # ip address checks, lets examine the rest as needed
                    self.ryuapp.logger.debug("%sSDNLoadBalancer.packetIn: we made it here..." %self.sdnengine.delta())
                    if (TCP in headers):
                        if rule['psrc'] == 0 or rule['psrc'] == headers[TCP].src_port:
                            if rule['pdst'] == 0 or rule['pdst'] == headers[TCP].dst_port:
                                self.ryuapp.logger.debug("%sSDNLoadBalancer.packetIn: load balancing packet %s via rule %s. Server will be selected soon." %(self.sdnengine.delta(), pkt,rule))
                                action = "loadbalanced"
                                policy = rule
                    elif(UDP in headers):
                        if rule['psrc'] == 0 or rule['psrc'] == headers[UDP].src_port:
                            if rule['pdst'] == 0 or rule['pdst'] == headers[UDP].dst_port:
                                self.ryuapp.logger.debug("%sSDNLoadBalancer.packetIn: load balancing packet %s via rule %s. Server will be selected soon." %(self.sdnengine.delta(), pkt,rule))
                                action = "loadbalanced"
                                policy = rule

            self.ryuapp.logger.debug("%sSDNLoadBalancer.packetIn: action: %s, policy: %s"  % (self.sdnengine.delta(), action,policy))
            if action == "loadbalanced" and policy != None:
                server = self.roundRobin(policy,headers)
                self.ryuapp.logger.debug("%sSDNLoadBalancer.packetIn: loadbalancing packet %s to server %s via roundrobin algorithm." %(self.sdnengine.delta(), pkt,server))

                ########
                # @TODO Need to make sure the ARP cache lookup below will not fail, or if it does, prime it or something...
                ########
                self.sdnengine.arpPrime(server)
                if not self.sdnengine.arpTable.has_key(server):
                    self.ryuapp.logger.debug("%sSDNLoadBalancer.packetIn: ArpTable contains no entry for %s - queueing packet and sending arp." %(self.sdnengine.delta(), server))
                    self.sdnengine.packetQueue.append({'msg' : msg, 'pkt' : pkt, 'headers' : headers, 'timestamp' : time.time()})
                    self.sdnengine.arpPrime(server)
                    return

                acache = self.sdnengine.arpTable[server]
                mcache = self.sdnengine.macTable[acache['mac']]
                port = mcache['port']
                actions = [#self.datapath.ofproto_parser.OFPActionSetNwDst(dst_addr),
                self.sdnengine.datapath.ofproto_parser.OFPActionSetDlDst(haddr_to_bin(acache['mac'])),
                #self.datapath.ofproto_parser.OFPActionOutput(self.datapath.ofproto.OFPP_FLOOD)]
                self.sdnengine.datapath.ofproto_parser.OFPActionOutput(port)]

                data = None
                if msg.buffer_id == self.datapath.ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = self.datapath.ofproto_parser.OFPPacketOut(
                          datapath=self.datapath,
                          buffer_id=msg.buffer_id,
                          in_port=msg.in_port,
                          actions=actions,
                          data=data)

                if self.debug == False and self.enabled == True:
                    # add flow mod for subsequent packets idle timeout specified
                    nwproto = 0
                    srcport = 0
                    dstport = 0

                    if TCP in headers:
                        nwproto = inet.IPPROTO_TCP
                        srcport = headers[TCP].src_port
                        dstport = headers[TCP].dst_port
                    elif UDP in headers:
                        nwproto = inet.IPPROTO_UDP
                        srcport = headers[UDP].src_port
                        dstport = headers[UDP].dst_port

                    match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,
                                                                  dl_type = ether.ETH_TYPE_IP,
                                                                  nw_src  = ipv4_to_int(headers[IPV4].src),
                                                                  nw_src_mask = 32,
                                                                  nw_dst  = ipv4_to_int(headers[IPV4].dst),
                                                                  nw_dst_mask = 32,
                                                                  nw_proto = nwproto,
                                                                  tp_src = srcport,
                                                                  tp_dst = dstport)

                    self.ryuapp.logger.debug("%sSDNLoadBalancer.packetIn: The flow match is : %s" %(self.sdnengine.delta(), match))
                    actions = [ self.sdnengine.datapath.ofproto_parser.OFPActionSetDlDst(haddr_to_bin(acache['mac'])),self.sdnengine.datapath.ofproto_parser.OFPActionOutput(port)]

                    mod = self.datapath.ofproto_parser.OFPFlowMod(self.datapath,
                                                  match,
                                                  cookie=0,
                                                  command=self.datapath.ofproto.OFPFC_ADD,
                                                  idle_timeout=LB_STICKY_TIMEOUT,
                                                  hard_timeout=0,
                                                  priority=self.priority,
                                                  flags=0,
                                                  actions=actions)

            	    self.ryuapp.logger.debug("%sSDNLoadBalancer.packetIn: The flow mod is : %s" %(self.sdnengine.delta(), mod))
            	    self.ryuapp.logger.debug("%sSDNLoadBalancer.packetIn: Sending OpenFlow flowmod to datapath to loadbalance traffic with idletimeout of: %s" %(self.sdnengine.delta(), LB_STICKY_TIMEOUT))
            	    self.datapath.send_msg(mod)

                self.datapath.send_msg(out)
                return "loadbalanced"
 
        self.ryuapp.logger.debug("%sSDNLoadBalancer.packetIn: NOT load balancing packet %s" % (self.sdnengine.delta(), pkt))
        return "notloadbalanced"

