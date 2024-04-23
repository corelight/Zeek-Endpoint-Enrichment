module EndpointEnrichment;

## Enrich known_hosts ##
export {
    ## Enables the logging of endpoint details to the Known-entities.
    option extra_logging_known = T;
}
redef record Known::HostDetails += {
    ep: Val &log &optional;
};

hook Known::add_host_details(h: Known::HostDetails, d: Known::HostDetails){
    #d is from worker
    #h is the internal table
    if (d ?$ ep){
        h$ep = d$ep;
    }
}

# update logs
function knownEndpoint (kep: Known::Endpoint) {
    local data = hosts_data[kep$ip];
    # Reporter::info (cat(data));
    if ( data ?$ hostname) {
        # add source to protocol field
        Known::get_name_details(kep, data$hostname)$protocols+=set(data$source);
        # # add source to annotation field
        Known::add_name_annotation(kep, data$hostname, set(data$source+"/"+data$status));
    }
    if ( data ?$ mac) {
        # some MAC's have "-" and should have ":", normalize to ":"
        local mac = subst_string(data$mac, "-", ":");
        # add source to protocol field
        Known::get_device_details(kep, mac)$protocols+=set(data$source);
        # # add source to annotation field
        Known::add_device_annotation(kep, mac, set(data$source+"/"+data$status));
    }
    if ( data ?$ machine_domain) {
        # add source to protocol field
        Known::get_domain_details(kep, data$machine_domain)$protocols+=set(data$source);
        # # add source to annotation field
        Known::add_domain_annotation(kep, data$machine_domain, set(data$source+"/"+data$status));
    }
    # add new fields to hosts log
    Known::get_host_details(kep)$ep = data;
}
function unknownEndpoint (kep: Known::Endpoint) {
    # TODO: create a list of all possible sources from the input file, or don't include a source with unknown hosts
    # local data: Val = [$status = "unknown", $source = unknownSource];
    local data: Val = [$status = "unknown"];
    Known::get_host_details(kep)$ep = data;
}

# priority of -5 to make sure the Known-entities creates an entry first
# note: priority of -5, the connection will already be removed from memory
event connection_state_remove(c: connection) &priority=-5 {
    if (extra_logging_known) {
        local ep: Known::Endpoint;

        if ( !c$conn?$local_orig && !c$conn?$local_resp ) {
            return;
        }

        # If the orig IP is local, check the list, update the following logs.
        if ( c$conn?$local_orig ) {
            ep = Common::get_endpoint(c, c$id$orig_h);
            # If it's in the list, update the fields, else flag it as unknown
            if ( c$id$orig_h in hosts_data ) {
                knownEndpoint(ep);
            } else {
                unknownEndpoint(ep);
            }
        }

        # If the resp IP is local, check the list, update the following logs.
        if ( c$conn?$local_resp ) {
            ep = Common::get_endpoint(c, c$id$resp_h);
            # If it's in the list, update the fields, else flag it as unknown
            if ( c$id$resp_h in hosts_data ) {
                knownEndpoint(ep);
            } else {
                unknownEndpoint(ep);
            }
        }
    }
}
