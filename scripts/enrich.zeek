module EndpointEnrichment;

type Idx: record {
  ip: addr;
};

type Val: record {
    ## The description of the endpoint.
    desc: string &log &optional;
    ## The status of the endpoint host.
    status: string &log &optional;
    ## The unique identifier, assigned by the source, of the endpoint host.
    host_uid: string &log &optional;
    ## The customer ID the host belongs to.
    cid: string &log &optional;
    ## The Operating System version of the endpoint host.
    os_version: string &log &optional;
    ## The source of the endpoint information.
    source: string &log &optional;
    ## The criticality of the endpoint host.
    criticality: string &log &optional;
    ## The MAC address of the endpoint host.
    mac: string &optional;
    ## The hostname of the vulnerable host.
    hostname: string &optional;
    ## The machine domain of the endpoint host.
    machine_domain: string &optional;
};

type ConnVal: record {
    ## The status of the endpoint host.
    status: string &log &optional;
    ## The unique identifier, assigned by the source, of the endpoint host.
    host_uid: string &log &optional;
    ## The customer ID the host belongs to.
    cid: string &log &optional;
    ## The source of the endpoint information.
    source: string &log &optional;

}

global hosts_data: table[addr] of Val = table();
# # source to use for all unknown IPs
# global unknownSource: string;

event zeek_init() {
    Input::add_table([
        $source="hosts_data.tsv",
        $name="hosts_data",
        $idx=Idx,
        $val=Val,
        $destination=hosts_data,
        $mode=Input::REREAD
    ]);
}

# TODO: create a list of all possible sources from the input file, or don't include a source with unknown hosts
# # grab the source from any record in the table and update unknownSource each time the input file is loaded.
# event Input::end_of_data(name: string, source: string) {
#     for ( _, val in hosts_data ) {
#         unknownSource = val$source;
#         break;
#     }
# }

export {
    ## Enables the logging of endpoint details to the conn log.
    option extra_logging_conn = T;
}

## conn - move to separate script
redef record Conn::Info += {
    orig_endpoint: ConnVal &log &optional;
    resp_endpoint: ConnVal &log &optional;
}

## known_hosts
redef record Known::HostDetails += {
    endpoint: Val &log &optional;
};

hook Known::add_host_details(h: Known::HostDetails, d: Known::HostDetails){
    #d is from worker
    #h is the internal table
    if (d ?$ endpoint){
        h$endpoint = d$endpoint;
    }
}

# update logs
function knownEndpoint (ip: addr) {
    local data = hosts_data[ip];
    # Reporter::info (cat(data));
    if ( data ?$ hostname) {
        # add source to protocol field
        Known::get_name_details(ip, data$hostname)$protocols+=set(data$source);
        # # add source to annotation field
        Known::add_name_annotation(ip, data$hostname, set(data$source+"/"+data$status));
    }
    if ( data ?$ mac) {
        # some MAC's have "-" and should have ":", normalize to ":"
        local mac = subst_string(data$mac, "-", ":");
        # add source to protocol field
        Known::get_device_details(ip, mac)$protocols+=set(data$source);
        # # add source to annotation field
        Known::add_device_annotation(ip, mac, set(data$source+"/"+data$status));
    }
    if ( data ?$ machine_domain) {
        # add source to protocol field
        Known::get_domain_details(ip, data$machine_domain)$protocols+=set(data$source);
        # # add source to annotation field
        Known::add_domain_annotation(ip, data$machine_domain, set(data$source+"/"+data$status));
    }
    # add new fields to hosts log
    Known::get_host_details(ip)$endpoint = data;
}
function unknownEndpoint (ip: addr) {
    # TODO: create a list of all possible sources from the input file, or don't include a source with unknown hosts
    # local data: Val = [$status = "unknown", $source = unknownSource];
    local data: Val = [$status = "unknown"];
    Known::get_host_details(ip)$endpoint = data;
}

# priority of -5 to make sure the Known-entities creates an entry first
event connection_state_remove(c: connection) &priority=-5
{
    local orig = c$id$orig_h;
    local resp = c$id$resp_h;

    local orig_local = c$conn?$local_orig;
    local resp_local = c$conn?$local_resp;

    if ( !orig_local && !resp_local ) {
        return;
    }

    # If the orig IP is local, check the list, update the following logs.
    if ( orig_local ) {
        # If it's in the list, update the fields, else flag it as unknown
        if ( orig in hosts_data ) {
            knownEndpoint(orig);
            if (extra_logging_conn)
                c$orig_endpoint = hosts_data[orig];
        } else {
            unknownEndpoint(orig);
        }
    }

    # If the resp IP is local, check the list, update the following logs.
    if ( resp_local ) {
        # If it's in the list, update the fields, else flag it as unknown
        if ( resp in hosts_data ) {
            knownEndpoint(resp);
            if (extra_logging_conn)
                c$resp_endpoint = hosts_data[resp];
        } else {
            unknownEndpoint(resp);
        }
    }
}
