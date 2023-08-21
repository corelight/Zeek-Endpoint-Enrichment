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
    ## The Operating System version of the endpoint host.
    os_version: string &log &optional;
    ## The source of the endpoint information.
    source: string &log &optional;
    ## The MAC address of the endpoint host.
    mac: string &optional;
    ## The hostname of the vulnerable host.
    hostname: string &optional;
    ## The machine domain of the endpoint host.
    machine_domain: string &optional;
};

global hosts_data: table[addr] of Val = table();

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

## known_hosts
redef record Known::HostDetails += {
  endpoint: Val &log &optional;
};

hook Known::add_host_details(h: Known::HostDetails, d: Known::HostDetails)
	{
    #d is from worker
    #h is the internal table
    if (h$host_ip == d$host_ip)
      h$endpoint = d$endpoint;
	}



# update logs
function knownEndpoint (ip: addr) {
    local data = hosts_data[ip];
    if data$hostname ?$ {
        Known::add_name_annotation(ip, data$hostname, set(data$source));
    }
    if data$mac ?$ {
        Known::add_device_annotation(ip, data$mac, set(data$source));
        # Known::get_device_details(ip, data$mac)$protocols=set(data.source);
    }
    if data$machine_domain ?$ {
        Known::add_domain_annotation(ip, data$machine_domain, set(data$source));
    }
    Known::get_host_details(ip)$endpoint = data;
}
function unknownEndpoint (ip: addr) {
    return;
    # local data = Val;
    # data$status="unknown"
    # Known::get_host_details(ip)$endpoint = data;
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
