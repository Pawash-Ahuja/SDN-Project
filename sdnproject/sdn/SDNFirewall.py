from common import *

class SDNFirewall():
    """Represents a stateless ACL based firewall where DENYs can be specified.  Implicit rule is PERMIT."""
    def __init__(self, sdnengine, ryuapp, datapath):
        """Constructs a new SDNFirewall.
           @param sdnengine An instance of the SDNEngine that is using this firewall
           @param ryuapp An instance of a RyuApp that is using this firewall.
           @param datapath A Ryu datapath object associated with this firewall.
           @return A new instance of SDNFirewall.
        """
        self.sdnengine = sdnengine
        self.ryuapp = ryuapp
        self.datapath = datapath
        self.ruleset = []
        self.debug = True
	self.priority= 5555
	self.enabled= False
	self.nwproto=0

    def purge(self):
        self.deleteAllFlows()
        self.ruleset = []

    def getRuleset(self):
        return self.ruleset

    def setDebug(self,value):
        self.debug= value
        self.execute()

    def setEnabled(self,value):
        self.enabled= value
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

            self.ryuapp.logger.debug("%sSDNFirewall.deleteAllFlows: The flow match is : %s" % (self.sdnengine.delta(),match))
 
            actions = []
 
            mod = self.datapath.ofproto_parser.OFPFlowMod(self.datapath,
                                                  match,
                                                  cookie=0,
                                                  command=self.datapath.ofproto.OFPFC_ADD,
                                                  idle_timeout=0,
                                                  hard_timeout=0,
                                                  priority=self.priority,
                                                  flags=0,
                                                  actions=actions)


            self.ryuapp.logger.debug("%sSDNFirewall.addAllFlows: The flow mod is : %s" % (self.sdnengine.delta(),mod))
            self.ryuapp.logger.debug("%sSDNFirewall.addAllFlows: Sending OpenFlow flowmod to datapath to drop rules from flow table." % (self.sdnengine.delta()))
            self.datapath.send_msg(mod)

	
    def deleteAllFlows(self):
        """For all the rules in the ruleset, remove them from the datapath."""
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

    	    self.ryuapp.logger.debug("%sSDNFirewall.deleteAllFlows: The flow match is : %s" % (self.sdnengine.delta(),match))
        
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


            self.ryuapp.logger.debug("%sSDNFirewall.deleteFlow: The flow mod is : %s" % (self.sdnengine.delta(),mod))
            self.ryuapp.logger.debug("%sSDNFirewall.deleteFlow: Sending OpenFlow flowmod to datapath to drop rules from flow table." % (self.sdnengine.delta()))
            self.datapath.send_msg(mod)






    def addDeny(self,protocol,srcNet,dstNet,protocolSrc=0,protocolDst=0,remark=''):
        """Adds a DENY rule to the firewall based on the specified parameters:
           @param protocol A string that can be one of "IP", "ICMP", "TCP", "UDP".
           @param srcNet A string dot-quad source IPv4 address: "A.B.C.D/Z" in CIDR notation.
           @param dstNet A string dot-quad destination IPv4 address: "A.B.C.D/Z" in CIDR notation: "A.B.C.D/Z".
           @param protocolSrc Only examined with protocol =~ /TCP|UDP/ and should be an integer source port. Value 0 = ignore (a wildcard)
           @param protocolDst Only examined with protocol =~ /TCP|UDP/ and should be an integer destination port. Value 0 = ignore (a wildcard)
        """
        nwproto = 0
        header = IPV4
        if protocol == "ICMP":
            header = ICMP
            nwproto = inet.IPPROTO_ICMP
        elif protocol == "TCP":
            header = TCP
            nwproto = inet.IPPROTO_TCP
        elif protocol == "UDP":
            header = UDP
            nwproto = inet.IPPROTO_UDP

        nsrcObj = netaddr.IPNetwork(srcNet)
        ndstObj = netaddr.IPNetwork(dstNet)

        self.ruleset.append({'protocol' : protocol, 'header' : header, 'srcnet' : nsrcObj, 'dstnet' : ndstObj, 'psrc' : protocolSrc, 'pdst' : protocolDst, 'remark' : remark})

        if self.debug == False and self.enabled==True:
            # add flow mod to datapath to drop packets matching specificationi -  any parameter not specified is a wildcard

            if protocolSrc != 0 and protocolDst != 0:
                match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,dl_type = ether.ETH_TYPE_IP, nw_src  = ipv4_to_int(str(nsrcObj.ip)),
                                                              nw_src_mask = nsrcObj.prefixlen, nw_dst  = ipv4_to_int(str(ndstObj.ip)),
                                                              nw_dst_mask = ndstObj.prefixlen, nw_proto = nwproto, tp_src = protocolSrc, tp_dst = protocolDst)
            if protocolSrc != 0 and protocolDst == 0:
                match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,dl_type = ether.ETH_TYPE_IP, nw_src  = ipv4_to_int(str(nsrcObj.ip)),
                                                              nw_src_mask = nsrcObj.prefixlen, nw_dst  = ipv4_to_int(str(ndstObj.ip)),
                                                              nw_dst_mask = ndstObj.prefixlen, nw_proto = nwproto, tp_src = protocolSrc)
            if protocolSrc == 0 and protocolDst != 0:
                match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,dl_type = ether.ETH_TYPE_IP, nw_src  = ipv4_to_int(str(nsrcObj.ip)),
                                                              nw_src_mask = nsrcObj.prefixlen, nw_dst  = ipv4_to_int(str(ndstObj.ip)),
                                                              nw_dst_mask = ndstObj.prefixlen, nw_proto = nwproto, tp_dst = protocolDst)
            if protocolSrc == 0 and protocolDst == 0:
                match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,dl_type = ether.ETH_TYPE_IP, nw_src  = ipv4_to_int(str(nsrcObj.ip)),
                                                              nw_src_mask = nsrcObj.prefixlen, nw_dst  = ipv4_to_int(str(ndstObj.ip)),
                                                              nw_dst_mask = ndstObj.prefixlen, nw_proto = nwproto)


            self.ryuapp.logger.debug("%sSDNFirewall.addDeny: The flow match is : %s" % (self.sdnengine.delta(),match))
            # empty actions will drop the packet                         
            actions = []
            mod = self.datapath.ofproto_parser.OFPFlowMod(self.datapath,
                                                  match,
                                                  cookie=0,
                                                  command=self.datapath.ofproto.OFPFC_ADD,
                                                  idle_timeout=0,
                                                  hard_timeout=0,
                                                  priority=self.priority,
                                                  flags=0,
                                                  actions=actions)
            self.ryuapp.logger.debug("%sSDNFirewall.addDeny: The flow mod is : %s" % (self.sdnengine.delta(),mod))
            self.ryuapp.logger.debug("%sSDNFirewall.addDeny: Sending OpenFlow flowmod to datapath to drop traffic." % (self.sdnengine.delta()))
            self.datapath.send_msg(mod)

    def deleteDeny(self,protocol,srcNet,dstNet,protocolSrc=0,protocolDst=0,remark=''):

        """Deletes a DENY rule to the firewall based on the specified parameters:
           @param protocol A string that can be one of "IP", "ICMP", "TCP", "UDP".
           @param srcNet A string dot-quad source IPv4 address: "A.B.C.D/Z" in CIDR notation.
           @param dstNet A string dot-quad destination IPv4 address: "A.B.C.D/Z" in CIDR notation: "A.B.C.D/Z".
           @param protocolSrc Only examined with protocol =~ /TCP|UDP/ and should be an integer source port. Value 0 = ignore (a wildcard)
           @param protocolDst Only examined with protocol =~ /TCP|UDP/ and should be an integer destination port. Value 0 = ignore (a wildcard)
        """
        nsrcObj = netaddr.IPNetwork(srcNet)
        ndstObj = netaddr.IPNetwork(dstNet)

        self.ryuapp.logger.debug("%sSDNFirewall.deleteDeny(protocol:%s,srcNet:%s,dstNet:%s,protocolSrc:%s,protocolDst:%s" % (self.sdnengine.delta(),protocol,nsrcObj,ndstObj,protocolSrc,protocolDst))

        for i in range(len(self.ruleset)):
            self.ryuapp.logger.debug("%sSDNFirewall.deleteDeny: comparing rule: %s" % (self.sdnengine.delta(),self.ruleset[i]))
            if(self.ruleset[i]['protocol'] == protocol and
               self.ruleset[i]['srcnet'] == nsrcObj and
               self.ruleset[i]['dstnet'] == ndstObj and
               int(self.ruleset[i]['psrc']) == int(protocolSrc) and
               int(self.ruleset[i]['pdst']) == int(protocolDst)):
                self.ryuapp.logger.debug("%sSDNFirewall.deleteDeny: match - deleting rule: %s " % (self.sdnengine.delta(),self.ruleset[i]))
                del(self.ruleset[i])
                break


        if self.debug == False and self.enabled==True:

            nwproto = 0
            if protocol == "ICMP":
                nwproto = inet.IPPROTO_ICMP
            elif protocol == "TCP":
                nwproto = inet.IPPROTO_TCP
            elif protocol == "UDP":
                nwproto = inet.IPPROTO_UDP


            # DELETE flow mod matching specifications -  any parameter not specified is a wildcard
	    # building match:


            if protocolSrc != 0 and protocolDst != 0:
                match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,dl_type = ether.ETH_TYPE_IP, nw_src  = ipv4_to_int(str(nsrcObj.ip)),
                                                              nw_src_mask = nsrcObj.prefixlen, nw_dst  = ipv4_to_int(str(ndstObj.ip)),
                                                              nw_dst_mask = ndstObj.prefixlen, nw_proto = nwproto, tp_src = protocolSrc, tp_dst = protocolDst)
            if protocolSrc != 0 and protocolDst == 0:
                match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,dl_type = ether.ETH_TYPE_IP, nw_src  = ipv4_to_int(str(nsrcObj.ip)),
                                                              nw_src_mask = nsrcObj.prefixlen, nw_dst  = ipv4_to_int(str(ndstObj.ip)),
                                                              nw_dst_mask = ndstObj.prefixlen, nw_proto = nwproto, tp_src = protocolSrc)
            if protocolSrc == 0 and protocolDst != 0:
                match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,dl_type = ether.ETH_TYPE_IP, nw_src  = ipv4_to_int(str(nsrcObj.ip)),
                                                              nw_src_mask = nsrcObj.prefixlen, nw_dst  = ipv4_to_int(str(ndstObj.ip)),
                                                              nw_dst_mask = ndstObj.prefixlen, nw_proto = nwproto, tp_dst = protocolDst)
            if protocolSrc == 0 and protocolDst == 0:
                match = self.datapath.ofproto_parser.OFPMatch(dl_vlan = SYSTEM_VLAN,dl_type = ether.ETH_TYPE_IP, nw_src  = ipv4_to_int(str(nsrcObj.ip)),
                                                              nw_src_mask = nsrcObj.prefixlen, nw_dst  = ipv4_to_int(str(ndstObj.ip)),
                                                              nw_dst_mask = ndstObj.prefixlen, nw_proto = nwproto)

            self.ryuapp.logger.debug("%sSDNFirewall.addDeny: The flow match is : %s" % (self.sdnengine.delta(),match))

            # because  empty actions will drop the packet as stated above

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

            self.ryuapp.logger.debug("%sSDNFirewall.deleteFlow: The flow mod is : %s" % (self.sdnengine.delta(),mod))
            self.ryuapp.logger.debug("%sSDNFirewall.deleteFlow: Sending OpenFlow flowmod to datapath to drop rules from flow table." % (self.sdnengine.delta()))
            self.datapath.send_msg(mod)





    def packetIn(self,msg,pkt,headers):
        """Processes a message (packet) sent to us by the controller.
           @param msg The packet sent to us by the controller.
           @param pkt The parsed Packet object representation of the message
           @param headers The headers contained in the pkt for quick analysis
           @return "permit" if the packet was permitted, else "deny" if the packet should be denied
        """
        if self.enabled == False:
            return "permit"

        if IPV4 not in headers:
            self.ryuapp.logger.debug("%sSDNFirewall.packetIn: Non IPV4 packet sent to us, skipping %s" % (self.sdnengine.delta(),pkt))

        # we need to loop through and see if the packet matches something in our deny list and if so, drop it
        for rule in self.ruleset:
            if rule['header'] in headers:
                # now we check more specific parameters
                srcip = netaddr.IPAddress(headers[IPV4].src)
                dstip = netaddr.IPAddress(headers[IPV4].dst)
                if srcip in rule['srcnet'] and dstip in rule['dstnet']:
                    # ip address checks, lets examine the rest as needed
                    if ICMP in headers:
                        self.ryuapp.logger.debug("%sSDNFirewall.packetIn: DENYing packet %s via rule %s" % (self.sdnengine.delta(),pkt,rule))
                        return "deny"
                    elif (TCP in headers):
                        if rule['psrc'] == 0 or rule['psrc'] == headers[TCP].src_port:
                            if rule['pdst'] == 0 or rule['pdst'] == headers[TCP].dst_port:
                                self.ryuapp.logger.debug("%sSDNFirewall.packetIn: DENYing packet %s via rule %s" % (self.sdnengine.delta(),pkt,rule))
                                return "deny"
                    elif(UDP in headers):
                        if rule['psrc'] == 0 or rule['psrc'] == headers[UDP].src_port:
                            if rule['pdst'] == 0 or rule['pdst'] == headers[UDP].dst_port:
                                self.ryuapp.logger.debug("%sSDNFirewall.packetIn: DENYing packet %s via rule %s" % (self.sdnengine.delta(),pkt,rule))
                                return "deny"

        self.ryuapp.logger.debug("%sSDNFirewall.packetIn: PERMITing packet %s" % (self.sdnengine.delta(),pkt))
        return "permit"

