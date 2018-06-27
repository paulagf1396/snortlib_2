# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.lib import snortlib_2


class prueba__4(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib_2': snortlib_2.SnortLib2}

    def __init__(self, *args, **kwargs):
        super(prueba__4, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

	#Inicializacion de Snort
	self.snort = kwargs['snortlib_2']
        self.snort_port = 3

        socket_config = {'unixsock': True}
	
	net_config = {'snort_port': 3,
		      'sw_snort': 1, 
		      'port_vig': 1}


        self.snort.set_config(socket_config)
        self.snort.start_socket_server()

	self.snort.network_config(net_config)
	self.snort.start_net()


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        
	
	actions=[parser.OFPActionOutput(2)]
	mensaje = parser.OFPFlowMod(datapath=datapath, match=parser.OFPMatch(), instructions=[parser.OFPInstructionActions(ofproto_v1_3.OFPIT_CLEAR_ACTIONS, actions)]) 
        


	print
        print ("Prueba realizada con el siguiente mensaje: ")

	print(mensaje.__dict__)
	print
	print 'Lista de acciones del mensaje'
	
	for inst in mensaje.instructions:
		print(inst.actions)
	

