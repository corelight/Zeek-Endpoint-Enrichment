module EndpointEnrichment;

## Add VLAN to all logs with an "id" field.

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

event new_connection(c: connection)
        {
        if ( ! extra_logging_all )
                return;

        if ( !c$conn?$local_orig && !c$conn?$local_resp )
                return;

        local conn = c$conn;
        local id = c$id;

        # If the orig IP is local and in the list, update the conn log.
        if ( conn?$local_orig && id$orig_h in hosts_data )
                {
                local orig_data = hosts_data[id$orig_h];

                if ( orig_data?$status )
                        id$orig_ep_status = orig_data$status;
                if ( orig_data?$uid )
                        id$orig_ep_uid = orig_data$uid;
                if ( orig_data?$hostname )
                        id$orig_ep_name = orig_data$hostname;
                if ( orig_data?$os_type )
                        id$orig_ep_ostype = orig_data$os_type;
                if ( orig_data?$machine_type )
                        id$orig_ep_type = orig_data$machine_type;
                if ( orig_data?$cid )
                        id$orig_ep_cid = orig_data$cid;

                id$orig_ep_source = orig_data$source;
                }

        # If the resp IP is local and in the list, update the conn log.
        if ( conn?$local_resp && id$resp_h in hosts_data )
                {
                local resp_data = hosts_data[id$resp_h];

                if ( resp_data?$status )
                        id$resp_ep_status = resp_data$status;
                if ( resp_data?$uid )
                        id$resp_ep_uid = resp_data$uid;
                if ( resp_data?$hostname )
                        id$resp_ep_name = resp_data$hostname;
                if ( resp_data?$os_type )
                        id$resp_ep_ostype = resp_data$os_type;
                if ( resp_data?$machine_type )
                        id$resp_ep_type = resp_data$machine_type;
                if ( resp_data?$cid )
                        id$resp_ep_cid = resp_data$cid;

                id$resp_ep_source = resp_data$source;
                }
        }

event connection_flipped(c: connection)
        {
        if ( extra_logging_all  && c?$conn )
                {

                if ( !c$conn?$local_orig && !c$conn?$local_resp )
                        return;

                local conn = c$conn;
                local id = c$id;

                # Clear old fields set before the connection flipped.
                if ( id?$orig_ep_status )
                        id$orig_ep_status = "";
                if ( id?$orig_ep_uid )
                        id$orig_ep_uid = "";
                if ( id?$orig_ep_ostype )
                        id$orig_ep_ostype = "";
                if ( id?$orig_ep_type )
                        id$orig_ep_type = "";
                if ( id?$orig_ep_cid )
                        id$orig_ep_cid = "";
                if ( id?$orig_ep_source )
                        id$orig_ep_source = "";
                if ( id?$orig_ep_name )
                        id$orig_ep_name = "";

                if ( id?$resp_ep_status )
                        id$resp_ep_status = "";
                if ( id?$resp_ep_uid )
                        id$resp_ep_uid = "";
                if ( id?$resp_ep_ostype )
                        id$resp_ep_ostype = "";
                if ( id?$resp_ep_type )
                        id$resp_ep_type = "";
                if ( id?$resp_ep_cid )
                        id$resp_ep_cid = "";
                if ( id?$resp_ep_source )
                        id$resp_ep_source = "";
                if ( id?$resp_ep_name )
                        id$resp_ep_name = "";

                # Once the old fields are erased, run through the enrichment again.
                # If the orig IP is local and in the list, update the conn log.
                if ( conn?$local_orig && id$orig_h in hosts_data )
                        {
                        local orig_data = hosts_data[id$orig_h];

                        if ( orig_data?$status )
                                id$orig_ep_status = orig_data$status;
                        if ( orig_data?$uid )
                                id$orig_ep_uid = orig_data$uid;
                        if ( orig_data?$hostname )
                                id$orig_ep_name = orig_data$hostname;
                        if ( orig_data?$os_type )
                                id$orig_ep_ostype = orig_data$os_type;
                        if ( orig_data?$machine_type )
                                id$orig_ep_type = orig_data$machine_type;
                        if ( orig_data?$cid )
                                id$orig_ep_cid = orig_data$cid;

                        id$orig_ep_source = orig_data$source;
                        }

                # If the resp IP is local and in the list, update the conn log.
                if ( conn?$local_resp && id$resp_h in hosts_data )
                        {
                        local resp_data = hosts_data[id$resp_h];

                        if ( resp_data?$status )
                                id$resp_ep_status = resp_data$status;
                        if ( resp_data?$uid )
                                id$resp_ep_uid = resp_data$uid;
                        if ( resp_data?$hostname )
                                id$resp_ep_name = resp_data$hostname;
                        if ( resp_data?$os_type )
                                id$resp_ep_ostype = resp_data$os_type;
                        if ( resp_data?$machine_type )
                                id$resp_ep_type = resp_data$machine_type;
                        if ( resp_data?$cid )
                                id$resp_ep_cid = resp_data$cid;

                        id$resp_ep_source = resp_data$source;
                        }
                }
        }
