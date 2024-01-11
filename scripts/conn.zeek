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


event new_connection(c: connection) &priority=4
{
    if (extra_logging_conn) {
        if ( !c$conn?$local_orig && !c$conn?$local_resp ) {
            return;
        }

        # If the orig IP is local and in the list, update the conn log.
        if ( c$conn?$local_orig && c$id$orig_h in hosts_data ) {
            local orig_data = hosts_data[c$id$orig_h];
            if ( orig_data ?$ status)
                c$conn$orig_ep_status = orig_data$status;
            if ( orig_data ?$ host_uid)
                c$conn$orig_ep_host_uid = orig_data$host_uid;
            if ( orig_data ?$ cid && extra_logging_conn_cid)
                c$conn$orig_ep_cid = orig_data$cid;
            c$conn$orig_ep_source = orig_data$source;
        }

        # If the resp IP is local and in the list, update the conn log.
        if ( c$conn?$local_resp && c$id$resp_h in hosts_data ) {
            local resp_data = hosts_data[c$id$resp_h];
            if ( resp_data ?$ status)
                c$conn$resp_ep_status = resp_data$status;
            if ( resp_data ?$ host_uid)
                c$conn$resp_ep_host_uid = resp_data$host_uid;
            if ( resp_data ?$ cid && extra_logging_conn_cid)
                c$conn$resp_ep_cid = resp_data$cid;
            c$conn$resp_ep_source = resp_data$source;
        }
    }
}
