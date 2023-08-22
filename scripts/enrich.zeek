module EndpointEnrichment;

type Idx: record {
  ip: addr;
};

type Val: record {
    ## The description of the endpoint.
    desc: string &log &optional;
    ## The status of the endpoint host.
    status: string &log;
    ## The unique identifier, assigned by the source, of the endpoint host.
    host_uid: string &log &optional;
    ## The Operating System version of the endpoint host.
    os_version: string &log &optional;
    ## The source of the endpoint information.
    source: string &log;
    ## The MAC address of the endpoint host.
    mac: string &optional;
    ## The hostname of the vulnerable host.
    hostname: string &optional;
    ## The machine domain of the endpoint host.
    machine_domain: string &optional;
};

global hosts_data: table[addr] of Val = table();
# source to use for all unknown IPs
global unknownSource: string;

# event entry(description: Input::TableDescription, tpe: Input::Event,
#             left: Idx, right: Val) {
#     # do something here...
#     Reporter::info (fmt("%s = %s", left, right));
# }

event zeek_init() {
    Input::add_table([
        $source="hosts_data.tsv",
        $name="hosts_data",
        $idx=Idx,
        $val=Val,
        $destination=hosts_data,
        $mode=Input::REREAD
        # $ev=entry
    ]);
}

# grab the source from any record in the table and update unknownSource each time the input file is loaded.
event Input::end_of_data(name: string, source: string) {
    for ( _, val in hosts_data ) {
        unknownSource = val$source;
        break;
    }
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
        Known::get_name_details(ip, data$hostname)$protocols=set(data$source);
        # add source to annotation field
        Known::add_name_annotation(ip, data$hostname, set(data$source));
    }
    if ( data ?$ mac) {
        # add source to protocol field
        Known::get_device_details(ip, data$mac)$protocols=set(data$source);
        # add source to annotation field
        Known::add_device_annotation(ip, data$mac, set(data$source));
    }
    if ( data ?$ machine_domain) {
        # add source to protocol field
        Known::get_domain_details(ip, data$machine_domain)$protocols=set(data$source);
        # add source to annotation field
        Known::add_domain_annotation(ip, data$machine_domain, set(data$source));
    }
    # add new fields to hosts log
    Known::get_host_details(ip)$endpoint = data;
}
function unknownEndpoint (ip: addr) {
    local data: Val = [$status = "unknown", $source = unknownSource];
    Known::get_host_details(ip)$endpoint = data;
}

# priority of -5 to make sure the Known-entities creates an entry first
event connection_state_remove(c: connection) &priority=-5
{
    local orig = c$id$orig_h;
    local resp = c$id$resp_h;

    local orig_local = Site::is_local_addr(orig);
    local resp_local = Site::is_local_addr(resp);

    if (!orig_local && !resp_local) {
        return;
    }

    # If the IP is in the list, update the following logs.
    if (orig_local && orig in hosts_data) {
        knownEndpoint(orig);
    }
    # If the IP is not in the list, add the field to flag it as unknown.
    if (orig_local && orig !in hosts_data) {
        unknownEndpoint(orig);
    }

    # If the IP is in the list, update the following logs.
    if (resp_local && resp in hosts_data) {
        knownEndpoint(resp);
    }
    # If the IP is not in the list, add the field to flag it as unknown.
    if (resp_local && resp !in hosts_data) {
        unknownEndpoint(resp);
    }

}
