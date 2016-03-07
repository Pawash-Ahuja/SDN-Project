from common import *

class ExternalCache():
    """Represents a hook between the SDNEngine and an external proxy/cache (squid) server."""
    def __init__(self, sdnengine, ryuapp, datapath, cacheip):
        """Constructs a new ExternalCache.
           @param sdnengine An instance of the SDNEngine that is using this firewall
           @param ryuapp An instance of a RyuApp that is using this router.
           @param datapath A Ryu datapath object associated with this router.
           @param cache The IP address of the external cache in text dot-quad format such as 172.16.1.11
           @return A new instance of ExternalCache.
        """
        self.sdnengine = sdnengine
        self.ryuapp = ryuapp
        self.datapath = datapath
        self.cacheip = cacheip
        self.ruleset = []
        self.debug = True
        self.enabled = False 
        self.priority = 3333

    def purge(self):
        self.deleteAllFlows()
        self.ruleset = []
 
    def setCacheIP(self,ip):
        self.cacheip = ip
        self.sdnengine.arpPrime(self.cacheip)

    def getRuleset(self):
        return self.ruleset

    def setDebug(self,value):
        self.debug = value
        self.execute()

    def setEnabled(self,value):
        self.enabled = value
        self.execute()

    def addAllFlows(self):
        """For all of the flows in the ruleset, add them to the datapath."""
        for i in range(len(self.ruleset)):
            protocol= self.ruleset[i]['protocol']
            srcNet= self.ruleset[i]['srcnet']
            dstNet=  self.ruleset[i]['dstnet']
            protocolSrc= self.ruleset[i]['psrc']
            protocolDst=self.ruleset[i]['pdst']

            nwproto = 0
            if protocol == "ICMP":
                nwproto = inet.IPPROTO_ICMP
            elif protocol == "TCP":
                nwproto = inet.IPPROTO_TCP
            elif protocol == "UDP":
                nwproto = inet.IPPROTO_UDP

            if protocolSrc != 0 and protocolDst != 0:
                match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,dl_type = ether.ETH_TYPE_IP,
                                                              nw_src  = ipv4_to_int(str(srcNet.ip)),
                                                              nw_src_mask = srcNet.prefixlen, nw_dst  = ipv4_to_int(str(dstNet.ip)),
                                                              nw_dst_mask = dstNet.prefixlen, nw_proto = nwproto,
                                                              tp_src = protocolSrc, tp_dst = protocolDst)
            if protocolSrc != 0 and protocolDst == 0:
                match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,dl_type = ether.ETH_TYPE_IP,
                                                              nw_src  = ipv4_to_int(str(srcNet.ip)),
                                                              nw_src_mask = srcNet.prefixlen, nw_dst  = ipv4_to_int(str(dstNet.ip)),
                                                              nw_dst_mask = dstNet.prefixlen, nw_proto = nwproto,
                                                              tp_src = protocolSrc)
            if protocolSrc == 0 and protocolDst != 0:
                match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,dl_type = ether.ETH_TYPE_IP,
                                                              nw_src  = ipv4_to_int(str(srcNet.ip)),
                                                              nw_src_mask = srcNet.prefixlen, nw_dst  = ipv4_to_int(str(dstNet.ip)),
                                                              nw_dst_mask = dstNet.prefixlen, nw_proto = nwproto,
                                                              tp_dst = protocolDst)
            if protocolSrc == 0 and protocolDst == 0:
                match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,dl_type = ether.ETH_TYPE_IP,
                                                              nw_src  = ipv4_to_int(str(srcNet.ip)),
                                                              nw_src_mask = srcNet.prefixlen, nw_dst  = ipv4_to_int(str(dstNet.ip)),
                                                              nw_dst_mask = srcNet.prefixlen, nw_proto = nwproto)

            self.ryuapp.logger.debug("%sExternalCache.addAllFlows: The flow match is : %s" % (self.sdnengine.delta(),match))

            self.sdnengine.arpPrime(self.cacheip)
            if not self.sdnengine.arpTable.has_key(self.cacheip):
                self.ryuapp.logger.debug("%sExternalCache.addAllFlows: Unable to add entry as arpTable for : %s is empty" % (self.sdnengine.delta(),self.cacheip))
                self.sdnengine.arpPrime(self.cacheip)
                return
            acache = self.sdnengine.arpTable[self.cacheip]
            mcache = self.sdnengine.macTable[acache['mac']]
            port = mcache['port']
            actions = [self.sdnengine.datapath.ofproto_parser.OFPActionSetDlDst(haddr_to_bin(acache['mac'])),
                       self.sdnengine.datapath.ofproto_parser.OFPActionOutput(port)]


            mod = self.datapath.ofproto_parser.OFPFlowMod(self.datapath,
                                                  match,
                                                  cookie=0,
                                                  command=self.datapath.ofproto.OFPFC_ADD,
                                                  idle_timeout=0,
                                                  hard_timeout=0,
                                                  priority=self.priority,
                                                  flags=0,
                                                  actions=actions)


            self.ryuapp.logger.debug("%sExternalCache.addAllFlows: The flow mod is : %s" % (self.sdnengine.delta(),mod))
            self.ryuapp.logger.debug("%sExternalCache.addAllFlows: Sending OpenFlow flowmod to datapath to drop rules from flow table." % self.sdnengine.delta())
            self.datapath.send_msg(mod)


    def deleteAllFlows(self):
        """For all the rules in the ruleset, remove them from the datapath."""

        # note that here we are trying a new approach with OFPFC_DELETE_STRICT 
        # that will strictly match on priority
        match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,dl_type = ether.ETH_TYPE_IP)

        self.ryuapp.logger.debug("%sExternalCache.deleteAllFlows: !!!!!!! The flow match is : %s" % (self.sdnengine.delta(),match))

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


        self.ryuapp.logger.debug("%sExternalCache.deleteAllFlows: !!!!!!!!!! The flow mod is : %s" % (self.sdnengine.delta(),mod))
        self.ryuapp.logger.debug("%sExternalCache.deleteAllFlows: !!!!!!!!!! Sending OpenFlow flowmod to datapath to drop rules from flow table." % self.sdnengine.delta())
        #self.datapath.send_msg(mod)

        #return

        # original longer approach were we had to have multiple matches... keeping it around in case the above doesn't work out....
        for i in range(len(self.ruleset)):
            protocol= self.ruleset[i]['protocol']
            srcNet= self.ruleset[i]['srcnet']
            dstNet=  self.ruleset[i]['dstnet']
            protocolSrc= self.ruleset[i]['psrc']
            protocolDst=self.ruleset[i]['pdst']

            nwproto = 0
            if protocol == "ICMP":
                nwproto = inet.IPPROTO_ICMP
            elif protocol == "TCP":
                nwproto = inet.IPPROTO_TCP
            elif protocol == "UDP":
                nwproto = inet.IPPROTO_UDP

            if protocolSrc != 0 and protocolDst != 0:
                match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,dl_type = ether.ETH_TYPE_IP,
                                                              nw_src  = ipv4_to_int(str(srcNet.ip)),
                                                              nw_src_mask = srcNet.prefixlen, nw_dst  = ipv4_to_int(str(dstNet.ip)),
                                                              nw_dst_mask = dstNet.prefixlen, nw_proto = nwproto,
                                                              tp_src = protocolSrc, tp_dst = protocolDst)
            if protocolSrc != 0 and protocolDst == 0:
                match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,dl_type = ether.ETH_TYPE_IP,
                                                              nw_src  = ipv4_to_int(str(srcNet.ip)),
                                                              nw_src_mask = srcNet.prefixlen, nw_dst  = ipv4_to_int(str(dstNet.ip)),
                                                              nw_dst_mask = dstNet.prefixlen, nw_proto = nwproto,
                                                              tp_src = protocolSrc)
            if protocolSrc == 0 and protocolDst != 0:
                match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,dl_type = ether.ETH_TYPE_IP,
                                                              nw_src  = ipv4_to_int(str(srcNet.ip)),
                                                              nw_src_mask = srcNet.prefixlen, nw_dst  = ipv4_to_int(str(dstNet.ip)),
                                                              nw_dst_mask = dstNet.prefixlen, nw_proto = nwproto,
                                                              tp_dst = protocolDst)
            if protocolSrc == 0 and protocolDst == 0:
                match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,dl_type = ether.ETH_TYPE_IP,
                                                              nw_src  = ipv4_to_int(str(srcNet.ip)),
                                                              nw_src_mask = srcNet.prefixlen, nw_dst  = ipv4_to_int(str(dstNet.ip)),
                                                              nw_dst_mask = srcNet.prefixlen, nw_proto = nwproto)

            self.ryuapp.logger.debug("%sExternalCache.deleteAllFlows: The flow match is : %s" % (self.sdnengine.delta(),match))

            actions = []
 
            mod = self.datapath.ofproto_parser.OFPFlowMod(self.datapath,
                                                  match,
                                                  cookie=0,
                                                  command=self.datapath.ofproto.OFPFC_DELETE,
                                                  idle_timeout=0,
                                                  hard_timeout=0,
                                                  priority=self.priority,
                                                  flags=0,
                                                  actions=actions)


            self.ryuapp.logger.debug("%sExternalCache.deleteAllFlows: The flow mod is : %s" % (self.sdnengine.delta(),mod))
            self.ryuapp.logger.debug("%sExternalCache.deleteAllFlows: Sending OpenFlow flowmod to datapath to drop rules from flow table." % self.sdnengine.delta())
            self.datapath.send_msg(mod)

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

    def addForward(self,protocol,srcNet,dstNet,protocolSrc=0,protocolDst=0,remark=''):
        """Adds a forwarding rule to cause traffic to be steered towards the specified cache.
           @param protocol A string that specifies the protocol.  At the moment it can only be "TCP".
           @param srcNet A string dot-quad source IPv4 address: "A.B.C.D/Z" in CIDR notation.
           @param dstNet A string dot-quad destination IPv4 address: "A.B.C.D/Z" in CIDR notation: "A.B.C.D/Z".
           @param protocolSrc Only examined with protocol =~ /TCP|UDP/ and should be an integer source port. Value 0 = ignore (a wildcard)
           @param protocolDst Only examined with protocol =~ /TCP|UDP/ and should be an integer destination port. Value 0 = ignore (a wildcard)
        """
        nwproto = 0
        header = IPV4
        if protocol != "TCP":
            self.ryuapp.logger.debug("%sExternalCache.addForward: Non TCP protocol specified - ignoring request: %s" % (self.sdnengine.delta(),protocol))
            return
     
        header = TCP
	nwproto = inet.IPPROTO_TCP

	nsrcObj = netaddr.IPNetwork(srcNet)
	ndstObj = netaddr.IPNetwork(dstNet)

        self.ruleset.append({'protocol' : protocol, 'header' : header, 'srcnet' : nsrcObj, 'dstnet' : ndstObj, 'psrc' : protocolSrc, 'pdst' : protocolDst, 'remark' : remark})

        if self.debug == False and self.enabled == True :
            # add the flow to the datapath

            if protocolSrc != 0 and protocolDst != 0:
                match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,dl_type = ether.ETH_TYPE_IP,
                                                              nw_src  = ipv4_to_int(str(nsrcObj.ip)),
                                                              nw_src_mask = srcNet.prefixlen, nw_dst  = ipv4_to_int(str(ndstObj.ip)),
                                                              nw_dst_mask = dstNet.prefixlen, nw_proto = nwproto,
                                                              tp_src = protocolSrc, tp_dst = protocolDst)
            if protocolSrc != 0 and protocolDst == 0:
                match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,dl_type = ether.ETH_TYPE_IP,
                                                              nw_src  = ipv4_to_int(str(nsrcObj.ip)),
                                                              nw_src_mask = srcNet.prefixlen, nw_dst  = ipv4_to_int(str(ndstObj.ip)),
                                                              nw_dst_mask = dstNet.prefixlen, nw_proto = nwproto,
                                                              tp_src = protocolSrc)
            if protocolSrc == 0 and protocolDst != 0:
                match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,dl_type = ether.ETH_TYPE_IP,
                                                              nw_src  = ipv4_to_int(str(nsrcObj.ip)),
                                                              nw_src_mask = srcNet.prefixlen, nw_dst  = ipv4_to_int(str(ndstObj.ip)),
                                                              nw_dst_mask = dstNet.prefixlen, nw_proto = nwproto,
                                                              tp_dst = protocolDst)
            if protocolSrc == 0 and protocolDst == 0:
                match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,dl_type = ether.ETH_TYPE_IP,
                                                              nw_src  = ipv4_to_int(str(nsrcObj.ip)),
                                                              nw_src_mask = srcNet.prefixlen, nw_dst  = ipv4_to_int(str(ndstObj.ip)),
                                                              nw_dst_mask = srcNet.prefixlen, nw_proto = nwproto)

            self.ryuapp.logger.debug("%sExternalCache.addForward: The flow match is : %s" % (self.sdnengine.delta(),match))

            # @TODO - prevent the lookup below from failing
            self.sdnengine.arpPrime(self.cacheip)
            # we can only continue if we have an arp entry
            if not self.sdnengine.arpTable.has_key(self.cacheip):
                self.ryuapp.logger.debug("%sExternalCache.addForward: arpTable has no entry for : %s, can't continue" % (self.sdnengine.delta(),self.cacheip))
                return
            acache = self.sdnengine.arpTable[self.cacheip]
            mcache = self.sdnengine.macTable[acache['mac']]
            port = mcache['port']
            actions = [self.sdnengine.datapath.ofproto_parser.OFPActionSetDlDst(haddr_to_bin(acache['mac'])),
                       self.sdnengine.datapath.ofproto_parser.OFPActionOutput(port)]

            mod = self.datapath.ofproto_parser.OFPFlowMod(self.datapath,
                                                  match,
                                                  cookie=0,
                                                  command=self.datapath.ofproto.OFPFC_ADD,
                                                  idle_timeout=0,
                                                  hard_timeout=0,
                                                  priority=self.priority,
                                                  flags=0,
                                                  actions=actions)


            self.ryuapp.logger.debug("%sExternalCache.addAddForward: The flow mod is : %s" % (self.sdnengine.delta(),mod))
            self.ryuapp.logger.debug("%sExternalCache.addAddForward: Sending OpenFlow flowmod to datapath to drop rules from flow table." % self.sdnengine.delta())
            self.datapath.send_msg(mod)
	


    def deleteForward(self,protocol,srcNet,dstNet,protocolSrc=0,protocolDst=0,remark=''):
        """Deletes a forwarding rule to cause traffic to be sterred towards the specified cache.
           @param protocol A string that specifies the protocol.  At the moment it can only be "TCP".
           @param srcNet A string dot-quad source IPv4 address: "A.B.C.D/Z" in CIDR notation.
           @param dstNet A string dot-quad destination IPv4 address: "A.B.C.D/Z" in CIDR notation: "A.B.C.D/Z".
           @param protocolSrc Only examined with protocol =~ /TCP|UDP/ and should be an integer source port. Value 0 = ignore (a wildcard)
           @param protocolDst Only examined with protocol =~ /TCP|UDP/ and should be an integer destination port. Value 0 = ignore (a wildcard)
        """
        for i in range(len(self.ruleset)):
            if(self.ruleset[i]['protocol'] == protocol and
               str(self.ruleset[i]['srcnet'].ip) == nsrcObj and
               str(self.ruleset[i]['dstnet'].ip) == ndstObj and
               int(self.ruleset[i]['psrc']) == int(protocolSrc) and
               int(self.ruleset[i]['pdst']) == int(protocolDst)):
                del(self.ruleset[i])
                break



        if self.debug == False and self.enabled == True :
            nwproto = 0
            header = IPV4
            if protocol != "TCP":
                self.ryuapp.logger.debug("%sExternalCache.deleteForward: Non TCP protocol specified - ignoring request: %s" % (self.sdnengine.delta(),protocol))
                return
    
            header = TCP
            nwproto = inet.IPPROTO_TCP

            nsrcObj = netaddr.IPNetwork(srcNet)
            ndstObj = netaddr.IPNetwork(dstNet)

            # delete the flow to the datapath

            if protocolSrc != 0 and protocolDst != 0:
                match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,dl_type = ether.ETH_TYPE_IP,
                                                              nw_src  = ipv4_to_int(str(nsrcObj.ip)),
                                                              nw_src_mask = srcNet.prefixlen, nw_dst  = ipv4_to_int(str(ndstObj.ip)),
                                                              nw_dst_mask = dstNet.prefixlen, nw_proto = nwproto,
                                                              tp_src = protocolSrc, tp_dst = protocolDst)
            if protocolSrc != 0 and protocolDst == 0:
                match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,dl_type = ether.ETH_TYPE_IP,
                                                              nw_src  = ipv4_to_int(str(nsrcObj.ip)),
                                                              nw_src_mask = srcNet.prefixlen, nw_dst  = ipv4_to_int(str(ndstObj.ip)),
                                                              nw_dst_mask = dstNet.prefixlen, nw_proto = nwproto,
                                                              tp_src = protocolSrc)
            if protocolSrc == 0 and protocolDst != 0:
                match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,dl_type = ether.ETH_TYPE_IP,
                                                              nw_src  = ipv4_to_int(str(nsrcObj.ip)),
                                                              nw_src_mask = srcNet.prefixlen, nw_dst  = ipv4_to_int(str(ndstObj.ip)),
                                                              nw_dst_mask = dstNet.prefixlen, nw_proto = nwproto,
                                                              tp_dst = protocolDst)
            if protocolSrc == 0 and protocolDst == 0:
                match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,dl_type = ether.ETH_TYPE_IP,
                                                              nw_src  = ipv4_to_int(str(nsrcObj.ip)),
                                                              nw_src_mask = srcNet.prefixlen, nw_dst  = ipv4_to_int(str(ndstObj.ip)),
                                                              nw_dst_mask = srcNet.prefixlen, nw_proto = nwproto)

            self.ryuapp.logger.debug("%sExternalCache.deleteForward: The flow match is : %s" % (self.sdnengine.delta(),match))

            # @TODO - prevent the lookup below from failing
            self.sdnengine.arpPrime(self.cacheip)
            if not self.sdnengine.arpTable.has_key(self.cacheip):
                self.ryuapp.logger.debug("%sArpTable contains no entry for %s - unable to add flow mod" % (self.sdnengine.delta(),self.cacheip))
                return

            acache = self.sdnengine.arpTable[self.cacheip]
            mcache = self.sdnengine.macTable[acache['mac']]
            port = mcache['port']
            actions = [self.sdnengine.datapath.ofproto_parser.OFPActionSetDlDst(haddr_to_bin(acache['mac'])),
                       self.sdnengine.datapath.ofproto_parser.OFPActionOutput(port)]

            mod = self.datapath.ofproto_parser.OFPFlowMod(self.datapath,
                                                  match,
                                                  cookie=0,
                                                  command=self.datapath.ofproto.OFPFC_DELETE,
                                                  idle_timeout=0,
                                                  hard_timeout=0,
                                                  priority=self.priority,
                                                  flags=0,
                                                  actions=actions)


            self.ryuapp.logger.debug("%sExternalCache.deleteForward: The flow mod is : %s" % (self.sdnengine.delta(),mod))
            self.ryuapp.logger.debug("%sExternalCache.deleteForward: Sending OpenFlow flowmod to datapath to drop rules from flow table." % self.sdnengine.delta())
            self.datapath.send_msg(mod)


    def packetIn(self,msg,pkt,headers):
        """Processes a message (packet) sent to us by the controller.
           @param msg The packet sent to us by the controller.
           @param pkt The parsed Packet object representation of the message
           @param headers The headers contained in the pkt for quick analysis
           @return "permit" if the packet was permitted, else "deny" if the packet should be denied
        """
        if self.enabled == False:
            return "notforwarded"

        if IPV4 not in headers:
            self.ryuapp.logger.debug("%sExternalCache.packetIn: Non IPV4 packet sent to us, skipping %s" % (self.sdnengine.delta(),pkt))

        # we need to loop through and see if the packet matches something in our forward list and if so, forward it
        for rule in self.ruleset:
            if rule['header'] in headers:
                # now we check more specific parameters
                srcip = netaddr.IPAddress(headers[IPV4].src)
                dstip = netaddr.IPAddress(headers[IPV4].dst)
                if srcip in rule['srcnet'] and dstip in rule['dstnet']:
                    # ip address checks, lets examine the rest as needed
                    if (TCP in headers):
                        if rule['psrc'] == 0 or rule['psrc'] == headers[TCP].src_port:
                            if rule['pdst'] == 0 or rule['pdst'] == headers[TCP].dst_port:

                                # found out the hard way that the underlying switch does not support destination address re-write
                                #dst_addr = int(netaddr.IPAddress('172.16.1.12'))
                                ########
                                # @TODO Need to make sure the ARP cache lookup below will not fail, or if it does, prime it or something...
                                ########
                                self.sdnengine.arpPrime(self.cacheip)
                                if not self.sdnengine.arpTable.has_key(self.cacheip):                                   
                                    self.ryuapp.logger.debug("%sArpTable contains no entry for %s - queueing packet and sending arp." % (self.sdnengine.delta(),self.cacheip)) 
                                    self.sdnengine.packetQueue.append({'msg' : msg, 'pkt' : pkt, 'headers' : headers, 'timestamp' : time.time()})
                                    self.sdnengine.arpPrime(self.cacheip)
                                    return
                                acache = self.sdnengine.arpTable[self.cacheip]
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
                                self.datapath.send_msg(out)

                                self.ryuapp.logger.debug("%sExternalCache.packetIn: FORWARDing packet to cache/proxy: %s via rule: %s" % (self.sdnengine.delta(),pkt,rule))
                                return "forward"

        self.ryuapp.logger.debug("%sExternalCache.packetIn: No rule match - not FORWARDing packet to cache: %s" % (self.sdnengine.delta(),pkt))
        return "notforward"

