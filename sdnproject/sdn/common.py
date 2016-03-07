import time
import copy
import json
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ether
from ryu.ofproto import inet
#from ryu.lib import addrconv
#from ryu.lib.mac import haddr_to_bin
from ryu.lib.ofctl_v1_0 import ipv4_to_int, haddr_to_bin, haddr_to_str
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import vlan
from ryu.lib.packet import in_proto
from webob import Response
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
import netaddr

# define "constants" to make it easy to refer certain data
UINT32_MAX = 0xffffffff
ETHERNET = ethernet.ethernet.__name__
VLAN = vlan.vlan.__name__
IPV4 = ipv4.ipv4.__name__
ARP = arp.arp.__name__
ICMP = icmp.icmp.__name__
TCP = tcp.tcp.__name__
UDP = udp.udp.__name__
VLANID_NONE = 0

# specifies the VLAN used by GENI.  Set to VLANID_NONE if not required.
SYSTEM_VLAN = 9

# local constants
LB_STICKY_TIMEOUT = 2
REST_API_NAME = "sdnservice_api"
