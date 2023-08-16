@load ./names
@load ./devices
@load ./domains
@load ./hosts

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
    mac: string;
    ## The hostname of the vulnerable host.
    hostname: string;
    ## The machine domain of the endpoint host.
    machine_domain: string;
}

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
redef record HostDetails += {
  endpoint: Val &log &optional;
};

hook add_host_details(h: HostDetails, d: HostDetails)
	{
    #d is from worker
    #h is the internal table
    if (h$host_ip == d$host_ip)
      h$endpoint = d$endpoint;
	}


event connection_state_remove(c: connection)
{
    local orig = c$id$orig_h;
    local resp = c$id$resp_h;

    local orig_local = Site::is_local_addr(orig);
    local resp_local = Site::is_local_addr(resp);

    if (!orig_local && !resp_local) {
        return;
    }

    if (orig_local && orig in hosts_data) {
        local data = hosts_data[orig];
        Known::add_name_annotation(orig, data.hostname, set(data.source));
        Known::add_device_annotation(orig, data.mac, set(data.source));
        Known::add_domain_annotation(orig, data.machine_domain, set(data.source));
        Known::get_host_details(orig)$endpoint = endpoint;
    }
    if (orig_local && orig !in host_data) {
      #hosts(orig, )
    }

    if (resp_local && resp in hosts_data) {
        local data = hosts_data[resp];
        Known::add_name_annotation(resp, data.hostname, set(data.source));
        Known::add_device_annotation(resp, data.mac, set(data.source));
        Known::add_domain_annotation(resp, data.machine_domain, set(data.source));
        Known::get_host_details(resp)$endpoint = endpoint;
    }
    if (resp_local && resp !in host_data) {
      #hosts(resp, )
    }

}
