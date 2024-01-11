##! Add VLAN to all logs with an "id" field.

module Corelight;

redef record conn_id += {
    orig_ep_status: string &log &optional;
    orig_ep_uid: string &log &optional;
    orig_ep_cid: string &log &optional;
    orig_ep_source: string &log &optional;
    resp_ep_status: string &log &optional;
    resp_ep_uid: string &log &optional;
    resp_ep_cid: string &log &optional;
    resp_ep_source: string &log &optional;
};

event new_onnection(c: connection) &priority=4
	{
	if ( c?$vlan )
		c$id$vlan = c$vlan;

	if ( c?$inner_vlan )
		c$id$vlan_inner = c$inner_vlan;
	}
