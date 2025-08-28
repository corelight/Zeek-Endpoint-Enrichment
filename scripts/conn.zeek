module EndpointEnrichment;

## Enrich Conn.log ##
export {
	## Enables the logging of endpoint details to the conn log.
	option extra_logging_conn = F;
	option extra_logging_conn_cid = F;
}

redef record Conn::Info += {
	orig_ep_status: string &log &optional;
	orig_ep_uid: string &log &optional;
	orig_ep_cid: string &log &optional;
	orig_ep_source: string &log &optional;

	resp_ep_status: string &log &optional;
	resp_ep_uid: string &log &optional;
	resp_ep_cid: string &log &optional;
	resp_ep_source: string &log &optional;
};

event new_connection(c: connection)
	{
	if ( ! extra_logging_conn )
		return;

	local conn = c$conn;
	local id = c$id;

	# If the orig IP is local and in the list, update the conn log.
	if ( conn?$local_orig && id$orig_h in hosts_data )
		{
		local orig_data = hosts_data[id$orig_h];

		if ( orig_data?$status )
			conn$orig_ep_status = orig_data$status;
		if ( orig_data?$uid )
			conn$orig_ep_uid = orig_data$uid;
		if ( orig_data?$cid && extra_logging_conn_cid )
			conn$orig_ep_cid = orig_data$cid;

		conn$orig_ep_source = orig_data$source;
		}

	# If the resp IP is local and in the list, update the conn log.
	if ( conn?$local_resp && id$resp_h in hosts_data )
		{
		local resp_data = hosts_data[id$resp_h];

		if ( resp_data?$status )
			conn$resp_ep_status = resp_data$status;
		if ( resp_data?$uid )
			conn$resp_ep_uid = resp_data$uid;
		if ( resp_data?$cid && extra_logging_conn_cid )
			conn$resp_ep_cid = resp_data$cid;

		conn$resp_ep_source = resp_data$source;
		}
	}
