module EndpointEnrichment;

## Enrich Conn.log only ##

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
        if ( ! extra_logging_conn )
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
                        conn$orig_ep_status = orig_data$status;
                if ( orig_data?$uid )
                        conn$orig_ep_uid = orig_data$uid;
                if ( orig_data?$hostname )
                        conn$orig_ep_name = orig_data$hostname;
                if ( orig_data?$os_type )
                        conn$orig_ep_ostype = orig_data$os_type;
                if ( orig_data?$machine_type )
                        conn$orig_ep_type = orig_data$machine_type;
                if ( orig_data?$cid )
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
                if ( resp_data?$hostname )
                        conn$resp_ep_name = resp_data$hostname;
                if ( resp_data?$os_type )
                        conn$resp_ep_ostype = resp_data$os_type;
                if ( resp_data?$machine_type )
                        conn$resp_ep_type = resp_data$machine_type;
                if ( resp_data?$cid )
                        conn$resp_ep_cid = resp_data$cid;

                c$conn$resp_ep_source = resp_data$source;
                }
        }

event connection_flipped(c: connection)
        {
        if ( extra_logging_conn && c?$conn )
                {

                if ( !c$conn?$local_orig && !c$conn?$local_resp )
                        return;

                local conn = c$conn;
                local id = c$id;

                # Clear old fields set before the connection flipped.
                if ( conn?$orig_ep_status )
                        conn$orig_ep_status = "";
                if ( conn?$orig_ep_uid )
                        conn$orig_ep_uid = "";
                if ( conn?$orig_ep_ostype )
                        conn$orig_ep_ostype = "";
                if ( conn?$orig_ep_type )
                        conn$orig_ep_type = "";
                if ( conn?$orig_ep_cid )
                        conn$orig_ep_cid = "";
                if ( conn?$orig_ep_source )
                        conn$orig_ep_source = "";
                if ( conn?$orig_ep_name )
                        conn$orig_ep_name = "";

                if ( conn?$resp_ep_status )
                        conn$resp_ep_status = "";
                if ( conn?$resp_ep_uid )
                        conn$resp_ep_uid = "";
                if ( conn?$resp_ep_ostype )
                        conn$resp_ep_ostype = "";
                if ( conn?$resp_ep_type )
                        conn$resp_ep_type = "";
                if ( conn?$resp_ep_cid )
                        conn$resp_ep_cid = "";
                if ( conn?$resp_ep_source )
                        conn$resp_ep_source = "";
                if ( conn?$resp_ep_name )
                        conn$resp_ep_name = "";

                # Once the old fields are erased, run through the enrichment again.
                # If the orig IP is local and in the list, update the conn log.
                if ( conn?$local_orig && id$orig_h in hosts_data )
                        {
                        local orig_data = hosts_data[id$orig_h];

                        if ( orig_data?$status )
                                conn$orig_ep_status = orig_data$status;
                        if ( orig_data?$uid )
                                conn$orig_ep_uid = orig_data$uid;
                        if ( orig_data?$hostname )
                                conn$orig_ep_name = orig_data$hostname;
                        if ( orig_data?$os_type )
                                conn$orig_ep_ostype = orig_data$os_type;
                        if ( orig_data?$machine_type )
                                conn$orig_ep_type = orig_data$machine_type;
                        if ( orig_data?$cid )
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
                        if ( resp_data?$hostname )
                                conn$resp_ep_name = resp_data$hostname;
                        if ( resp_data?$os_type )
                                conn$resp_ep_ostype = resp_data$os_type;
                        if ( resp_data?$machine_type )
                                conn$resp_ep_type = resp_data$machine_type;
                        if ( resp_data?$cid )
                                conn$resp_ep_cid = resp_data$cid;

                        c$conn$resp_ep_source = resp_data$source;
                        }
                }
        }
