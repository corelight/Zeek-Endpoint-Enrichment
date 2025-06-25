module EndpointEnrichment;

## Enrich Conn.log ##
export {
        ## Enables the logging of endpoint details to the conn log.
        option extra_logging_conn = F;
        option extra_logging_conn_cid = F;
        option extra_logging_conn_hostname = F;
        option extra_logging_conn_type = F;
        option extra_logging_conn_ostype = F;
}

redef record Conn::Info += {
        orig_ep_status: string &log &optional;
        orig_ep_uid: string &log &optional;
        orig_ep_cid: string &log &optional;
        orig_ep_name: string &log &optional;
        orig_ep_ostype: string &log &optional;
        orig_ep_type: string &log &optional;
        orig_ep_source: string &log &optional;
        resp_ep_status: string &log &optional;
        resp_ep_uid: string &log &optional;
        resp_ep_cid: string &log &optional;
        resp_ep_name: string &log &optional;
        resp_ep_ostype: string &log &optional;
        resp_ep_type: string &log &optional;
        resp_ep_source: string &log &optional;
};

event new_connection(c: connection)
        {
        if (extra_logging_conn)
                {
                if ( !c$conn?$local_orig && !c$conn?$local_resp )
                        return;

                # If the orig IP is local and in the list, update the conn log.
                if ( c$conn?$local_orig && c$id$orig_h in hosts_data )
                        {
                        local orig_data = hosts_data[c$id$orig_h];
                        if ( orig_data?$status )
                                c$conn$orig_ep_status = orig_data$status;
                        if ( orig_data?$uid )
                                c$conn$orig_ep_uid = orig_data$uid;
                        if ( orig_data?$hostname && extra_logging_conn_hostname )
                                c$conn$orig_ep_name = orig_data$hostname;
                        if ( orig_data?$os_type && extra_logging_conn_ostype )
                                c$conn$orig_ep_ostype = orig_data$os_type;
                        if ( orig_data?$machine_type && extra_logging_conn_type )
                                c$conn$orig_ep_type = orig_data$machine_type;
                        if ( orig_data?$cid && extra_logging_conn_cid )
                                c$conn$orig_ep_cid = orig_data$cid;
                        c$conn$orig_ep_source = orig_data$source;
                        }

                # If the resp IP is local and in the list, update the conn log.
                if ( c$conn?$local_resp && c$id$resp_h in hosts_data )
                        {
                        local resp_data = hosts_data[c$id$resp_h];
                        if ( resp_data?$status )
                                c$conn$resp_ep_status = resp_data$status;
                        if ( resp_data?$uid )
                                c$conn$resp_ep_uid = resp_data$uid;
                        if ( resp_data?$hostname && extra_logging_conn_hostname )
                                c$conn$resp_ep_name = resp_data$hostname;
                        if ( resp_data?$os_type && extra_logging_conn_ostype )
                                c$conn$resp_ep_ostype = resp_data$os_type;
                        if ( resp_data?$machine_type && extra_logging_conn_type )
                                c$conn$resp_ep_type = resp_data$machine_type;
                        if ( resp_data?$cid && extra_logging_conn_cid )
                                c$conn$resp_ep_cid = resp_data$cid;
                        c$conn$resp_ep_source = resp_data$source;
                        }
                }
        }

event connection_flipped(c: connection)
        {
        if ( extra_logging_conn && c?$conn )
                {
                if ( !c$conn?$local_orig && !c$conn?$local_resp )
                        return;

                # Clear old fields set before the connection flipped.
                if ( c$conn?$orig_ep_status )
                        c$conn$orig_ep_status = "";
                if ( c$conn?$orig_ep_uid )
                        c$conn$orig_ep_uid = "";
                if ( c$conn?$orig_ep_ostype )
                        c$conn$orig_ep_ostype = "";
                if ( c$conn?$orig_ep_type )
                        c$conn$orig_ep_type = "";
                if ( c$conn?$orig_ep_cid )
                        c$conn$orig_ep_cid = "";
                if ( c$conn?$orig_ep_source )
                        c$conn$orig_ep_source = "";
                if ( c$conn?$orig_ep_name )
                        c$conn$orig_ep_name = "";
                if ( c$conn?$resp_ep_status )
                        c$conn$resp_ep_status = "";
                if ( c$conn?$resp_ep_uid )
                        c$conn$resp_ep_uid = "";
                if ( c$conn?$resp_ep_ostype )
                        c$conn$resp_ep_ostype = "";
                if ( c$conn?$resp_ep_type )
                        c$conn$resp_ep_type = "";
                if ( c$conn?$resp_ep_cid )
                        c$conn$resp_ep_cid = "";
                if ( c$conn?$resp_ep_source )
                        c$conn$resp_ep_source = "";
                if ( c$conn?$resp_ep_name )
                        c$conn$resp_ep_name = "";

                # Once the old fields are erased, run through the enrichment again.
                # If the orig IP is local and in the list, update the conn log.
                if ( c$conn?$local_orig && c$id$orig_h in hosts_data )
                        {
                        local orig_data = hosts_data[c$id$orig_h];
                        if ( orig_data?$status )
                                c$conn$orig_ep_status = orig_data$status;
                        if ( orig_data?$uid )
                                c$conn$orig_ep_uid = orig_data$uid;
                        if ( orig_data?$hostname && extra_logging_conn_hostname )
                                c$conn$orig_ep_name = orig_data$hostname;
                        if ( orig_data?$os_type && extra_logging_conn_ostype )
                                c$conn$orig_ep_ostype = orig_data$os_type;
                        if ( orig_data?$machine_type && extra_logging_conn_type )
                                c$conn$orig_ep_type = orig_data$machine_type;
                        if ( orig_data?$cid && extra_logging_conn_cid )
                                c$conn$orig_ep_cid = orig_data$cid;
                        c$conn$orig_ep_source = orig_data$source;
                        }

                # If the resp IP is local and in the list, update the conn log.
                if ( c$conn?$local_resp && c$id$resp_h in hosts_data )
                        {
                        local resp_data = hosts_data[c$id$resp_h];
                        if ( resp_data?$status )
                                c$conn$resp_ep_status = resp_data$status;
                        if ( resp_data?$uid )
                                c$conn$resp_ep_uid = resp_data$uid;
                        if ( resp_data?$hostname && extra_logging_conn_hostname )
                                c$conn$resp_ep_name = resp_data$hostname;
                        if ( resp_data?$os_type && extra_logging_conn_ostype )
                                c$conn$resp_ep_ostype = resp_data$os_type;
                        if ( resp_data?$machine_type && extra_logging_conn_type )
                                c$conn$resp_ep_type = resp_data$machine_type;
                        if ( resp_data?$cid && extra_logging_conn_cid )
                                c$conn$resp_ep_cid = resp_data$cid;
                        c$conn$resp_ep_source = resp_data$source;
                        }
                }
        }
