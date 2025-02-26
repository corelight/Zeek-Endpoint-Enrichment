module EndpointEnrichment;

## Add VLAN to all logs with an "id" field.
export {
    ## Enables the logging of endpoint details to the conn log.
    option extra_logging_all = F;
    option extra_logging_all_cid = F;
    option extra_logging_all_hostname = F;
    option extra_logging_all_type = F;
    option extra_logging_all_ostype = F;
}

redef record conn_id += {
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


event new_connection(c: connection) {
    if (extra_logging_all) {
        if ( !c$conn?$local_orig && !c$conn?$local_resp ) {
            return;
        }

        # If the orig IP is local and in the list, update the conn log.
        if ( c$conn?$local_orig && c$id$orig_h in hosts_data ) {
            local orig_data = hosts_data[c$id$orig_h];
            if ( orig_data ?$ status)
                c$id$orig_ep_status = orig_data$status;
            if ( orig_data ?$ uid)
                c$id$orig_ep_uid = orig_data$uid;
            if ( orig_data ?$ hostname && extra_logging_all_hostname)
                c$id$orig_ep_name = orig_data$hostname;
            if ( orig_data ?$ os_type && extra_logging_all_ostype)
                c$id$orig_ep_ostype = orig_data$os_type;
            if ( orig_data ?$ machine_type && extra_logging_all_type)
                c$id$orig_ep_type = orig_data$machine_type;
            if ( orig_data ?$ cid && extra_logging_all_cid)
                c$id$orig_ep_cid = orig_data$cid;
            c$id$orig_ep_source = orig_data$source;
        }

        # If the resp IP is local and in the list, update the conn log.
        if ( c$conn?$local_resp && c$id$resp_h in hosts_data ) {
            local resp_data = hosts_data[c$id$resp_h];
            if ( resp_data ?$ status)
                c$id$resp_ep_status = resp_data$status;
            if ( resp_data ?$ uid)
                c$id$resp_ep_uid = resp_data$uid;
            if ( resp_data ?$ hostname && extra_logging_all_hostname)
                c$id$resp_ep_name = resp_data$hostname;
            if ( resp_data ?$ os_type && extra_logging_all_ostype)
                c$id$resp_ep_ostype = resp_data$os_type;
            if ( resp_data ?$ machine_type && extra_logging_all_type)
                c$id$resp_ep_type = resp_data$machine_type;
            if ( resp_data ?$ cid && extra_logging_all_cid)
                c$id$resp_ep_cid = resp_data$cid;
            c$id$resp_ep_source = resp_data$source;
        }
    }
}

event connection_flipped(c: connection) {
    if ( extra_logging_all  && c?$conn ) {
        if ( !c$conn?$local_orig && !c$conn?$local_resp ) {
            return;
        }
        # Clear old fields set before the connection flipped.
        if ( c$id ?$ orig_ep_status)
            c$id$orig_ep_status = "";
        if ( c$id ?$ orig_ep_uid)
            c$id$orig_ep_uid = "";
        if ( c$id ?$ orig_ep_ostype)
            c$id$orig_ep_ostype = "";
        if ( c$id ?$ orig_ep_type)
            c$id$orig_ep_type = "";
        if ( c$id ?$ orig_ep_cid)
            c$id$orig_ep_cid = "";
        if ( c$id ?$ orig_ep_source)
            c$id$orig_ep_source = "";
        if ( c$id ?$ orig_ep_name)
            c$id$orig_ep_name = "";
        if ( c$id ?$ resp_ep_status)
            c$id$resp_ep_status = "";
        if ( c$id ?$ resp_ep_uid)
            c$id$resp_ep_uid = "";
        if ( c$id ?$ resp_ep_ostype)
            c$id$resp_ep_ostype = "";
        if ( c$id ?$ resp_ep_type)
            c$id$resp_ep_type = "";
        if ( c$id ?$ resp_ep_cid)
            c$id$resp_ep_cid = "";
        if ( c$id ?$ resp_ep_source)
            c$id$resp_ep_source = "";
        if ( c$id ?$ resp_ep_name)
            c$id$resp_ep_name = "";

        # Once the old fields are erased, run through the enrichment again.

        # If the orig IP is local and in the list, update the conn log.
        if ( c$conn?$local_orig && c$id$orig_h in hosts_data ) {
            local orig_data = hosts_data[c$id$orig_h];
            if ( orig_data ?$ status)
                c$id$orig_ep_status = orig_data$status;
            if ( orig_data ?$ uid)
                c$id$orig_ep_uid = orig_data$uid;
            if ( orig_data ?$ hostname && extra_logging_all_hostname)
                c$id$orig_ep_name = orig_data$hostname;
            if ( orig_data ?$ os_type && extra_logging_all_ostype)
                c$id$orig_ep_ostype = orig_data$os_type;
            if ( orig_data ?$ machine_type && extra_logging_all_type)
                c$id$orig_ep_type = orig_data$machine_type;
            if ( orig_data ?$ cid && extra_logging_all_cid)
                c$id$orig_ep_cid = orig_data$cid;
            c$id$orig_ep_source = orig_data$source;
        }

        # If the resp IP is local and in the list, update the conn log.
        if ( c$conn?$local_resp && c$id$resp_h in hosts_data ) {
            local resp_data = hosts_data[c$id$resp_h];
            if ( resp_data ?$ status)
                c$id$resp_ep_status = resp_data$status;
            if ( resp_data ?$ uid)
                c$id$resp_ep_uid = resp_data$uid;
            if ( resp_data ?$ hostname && extra_logging_all_hostname)
                c$id$resp_ep_name = resp_data$hostname;
            if ( resp_data ?$ os_type && extra_logging_all_ostype)
                c$id$resp_ep_ostype = resp_data$os_type;
            if ( resp_data ?$ machine_type && extra_logging_all_type)
                c$id$resp_ep_type = resp_data$machine_type;
            if ( resp_data ?$ cid && extra_logging_all_cid)
                c$id$resp_ep_cid = resp_data$cid;
            c$id$resp_ep_source = resp_data$source;
        }
    }
}
