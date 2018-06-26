# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import os
import logging
import six
import array

from ryu.lib import hub, alert
from ryu.base import app_manager
from ryu.controller import event


import ryu.app.ofctl.api as ofctl_api
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser as parser
from ryu.controller import ofp_event
from ryu.lib.packet import packet
from ryu.controller.handler import set_ev_cls
from ryu.controller import handler

from ryu.ofproto import inet
from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
import ryu.app.ofctl.api as ofctl_api

BUFSIZE = alert.AlertPkt._ALERTPKT_SIZE
SOCKFILE = "/tmp/snort_alert"



      

	

class EventAlert(event.EventBase):
    def __init__(self, msg):
        super(EventAlert, self).__init__()
        self.msg = msg

class EventPacketIn(event.EventBase):
    def __init__(self, msg):
        super(EventPacketIn, self).__init__()
        self.msg = msg


class SnortLib2(app_manager.RyuApp):

    def __init__(self):
        super(SnortLib2, self).__init__()
        self.name = 'snortlib_2'
        self.config = {'unixsock': True}
	self.net_config = {'snort_port': 3, 
			   'sw_snort': 1, 
			   'port_vig': 1}
        self._set_logger()
        self.sock = None
        self.nwsock = None
	


    def set_config(self, config):
        assert isinstance(config, dict)
        self.config = config
	

   #NET CONFIG#

    def network_config(self, net_config):
        assert isinstance(net_config, dict)
        self.net_config = net_config
	self.logger.info(self.net_config)
	
	
    def start_net(self):
	snort_port = self.net_config.get('snort_port')
	sw_snort = self.net_config.get('sw_snort')
	port_vig = self.net_config.get('port_vig')
	self.logger.info( "SW en el que esta SNORT: SW" + str(sw_snort) + " Y PUERTO A ESCUCHAR: PORT" + str(snort_port))
	self.decorator_OFPPacketOut(parser.OFPPacketOut) 
	self.decorator_OFPFlowMod(parser.OFPFlowMod)
	

    #ADD_FLOW
    def add_drop_rule(self, datapath, priority, match):
        
	ofproto = datapath.ofproto
        of_parser = datapath.ofproto_parser
        inst = [of_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])]
        mod = of_parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
	

    #DELETE_FLOW
    def delete_flow(self, datapath):
	   
	ofp = datapath.ofproto
	parser = datapath.ofproto_parser    
	port_vig= self.net_config.get('port_vig')
	match = parser.OFPMatch(in_port=port_vig)
	instructions= []
	flow_mod = parser.OFPFlowMod(datapath, 0, 0, 0,ofp.OFPFC_DELETE, 0, 0, 1,ofp.OFPCML_NO_BUFFER,ofp.OFPP_ANY,ofp.OFPP_ANY, ofp.OFPFF_SEND_FLOW_REM, match, instructions)
	datapath.send_msg(flow_mod)

	
    def decorator_OFPPacketOut(self, func):
	
	old_constructorPOut=func.__init__	
	snort_port = self.net_config.get('snort_port')
	sw_snort = self.net_config.get('sw_snort')
	
	def new_constructorPOut(self, datapath, buffer_id=None, in_port=None, actions=None,
                 data=None, actions_len=None):
	    if datapath.id == sw_snort and actions is not None:
		    for action in actions:
			if action.type == 0:
		    	    actions.append(parser.OFPActionOutput(snort_port))
			    
			    return old_constructorPOut(self, datapath, buffer_id, in_port, actions,
		 data, actions_len)
	    return old_constructorPOut(self, datapath, buffer_id, in_port, actions,
                 data, actions_len)

	func.__init__= new_constructorPOut 


    def decorator_OFPFlowMod(self, func):

	old_constructorFlowMod=func.__init__	

	snort_port = self.net_config.get('snort_port')
	sw_snort = self.net_config.get('sw_snort')

	def new_contstructorFlowMod(self, datapath, cookie=0, cookie_mask=0, table_id=0,
                 command=ofproto_v1_3.OFPFC_ADD,
                 idle_timeout=0, hard_timeout=0,
                 priority=ofproto_v1_3.OFP_DEFAULT_PRIORITY,
                 buffer_id=ofproto_v1_3.OFP_NO_BUFFER,
                 out_port=0, out_group=0, flags=0,
                 match=None,
                 instructions=None):

            if instructions is not None and datapath.id == sw_snort:
			    for instruction in instructions:
				if (instruction.type == 4 or instruction.type == 3):

					if (instruction.actions is not None):
						for action in instruction.actions:
						    if action.type == 0:

							if action.port == snort_port:

								return old_constructorFlowMod(self, datapath, cookie, cookie_mask, table_id, command, idle_timeout, hard_timeout, priority, buffer_id, out_port, out_group, flags, match, instructions)
							else:
					
								instruction.actions.append(parser.OFPActionOutput(snort_port))
								
								return old_constructorFlowMod(self, datapath, cookie, cookie_mask, table_id, command, idle_timeout, hard_timeout, priority, buffer_id, out_port, out_group, flags, match, instructions)
                                                  
	    return old_constructorFlowMod(self, datapath, cookie, cookie_mask, table_id, command, idle_timeout, hard_timeout, priority, buffer_id, out_port, out_group, flags, match, instructions)

	func.__init__ = new_contstructorFlowMod 

	    
   
    @set_ev_cls(EventAlert, handler.MAIN_DISPATCHER)
    def _dump_alert(self, ev):
	
	msg = ev.msg
	sw_snort = self.net_config.get('sw_snort')
	print("ALERTA---")
        print('alertmsg: %s' % ''.join(msg.alertmsg))	
    
	pkt = packet.Packet(array.array('B', msg.pkt))
        eth = pkt.get_protocol(ethernet.ethernet)
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        _icmp = pkt.get_protocol(icmp.icmp)
	
        if _icmp:
            self.logger.info("%r", _icmp)

        if _ipv4:
            self.logger.info("%r", _ipv4)
	    

        if eth:
            self.logger.info("%r", eth)


	datapath_sw_snort = ofctl_api.get_datapath(self, dpid=sw_snort)

	#Modifying flow
        of_parser = datapath_sw_snort.ofproto_parser
	block_dst = _ipv4.dst
	block_src = _ipv4.src
	match = of_parser.OFPMatch(eth_dst = eth.dst, eth_type=ether.ETH_TYPE_IP, ip_proto= inet.IPPROTO_ICMP, ipv4_dst=block_dst)
	self.add_drop_rule(datapath_sw_snort, 5, match)

	#Deleting_flow
	self.delete_flow(datapath_sw_snort)

   ############



    def start_socket_server(self):
        if not self.config.get('unixsock'):

            if self.config.get('port') is None:
                self.config['port'] = 51234

            self._start_recv_nw_sock(self.config.get('port'))
        else:
            self._start_recv()

        self.logger.info(self.config)

    def _recv_loop(self):
        self.logger.info("Unix socket start listening...")
        while True:
            data = self.sock.recv(BUFSIZE)
            msg = alert.AlertPkt.parser(data)
            if msg:
                self.send_event_to_observers(EventAlert(msg))

    def _start_recv(self):
        if os.path.exists(SOCKFILE):
            os.unlink(SOCKFILE)

        self.sock = hub.socket.socket(hub.socket.AF_UNIX,
                                      hub.socket.SOCK_DGRAM)
        self.sock.bind(SOCKFILE)
        hub.spawn(self._recv_loop)

    def _start_recv_nw_sock(self, port):

        self.nwsock = hub.socket.socket(hub.socket.AF_INET,
                                        hub.socket.SOCK_STREAM)
        self.nwsock.setsockopt(hub.socket.SOL_SOCKET,
                               hub.socket.SO_REUSEADDR, 1)
        self.nwsock.bind(('0.0.0.0', port))
        self.nwsock.listen(5)

        hub.spawn(self._accept_loop_nw_sock)

    def _accept_loop_nw_sock(self):
        self.logger.info("Network socket server start listening...")
        while True:
            conn, addr = self.nwsock.accept()
            self.logger.info("Connected with %s", addr[0])
            hub.spawn(self._recv_loop_nw_sock, conn, addr)

    def _recv_loop_nw_sock(self, conn, addr):
        buf = six.binary_type()
        while True:
            ret = conn.recv(BUFSIZE)
            if len(ret) == 0:
                self.logger.info("Disconnected from %s", addr[0])
                break

            buf += ret
            while len(buf) >= BUFSIZE:
                # self.logger.debug("Received buffer size: %d", len(buf))
                data = buf[:BUFSIZE]
                msg = alert.AlertPkt.parser(data)
                if msg:
                    self.send_event_to_observers(EventAlert(msg))
                buf = buf[BUFSIZE:]

    def _set_logger(self):
        """change log format."""
        self.logger.propagate = False
        hdl = logging.StreamHandler()
        fmt_str = '[snort][%(levelname)s] %(message)s'
        hdl.setFormatter(logging.Formatter(fmt_str))
        self.logger.addHandler(hdl)


#####






