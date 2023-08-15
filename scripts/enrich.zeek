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

## known_names (Hostname only)
redef record NameDetails += {
	counter: count &log &default=0;
};

hook add_name_details(h: NameDetails, d: NameDetails)
	{
	h$counter += d$counter;
	}

## known_devices (MAC address only)
redef record DeviceDetails += {
	counter: count &log &default=0;
};

hook add_device_details(h: DeviceDetails, d: DeviceDetails)
	{
	h$counter += d$counter;
	}

## known_domains (Domain only)
redef record DomainDetails += {
	counter: count &log &default=0;
};

hook add_domain_details(h: DomainDetails, d: DomainDetails)
	{
	h$counter += d$counter;
	}

## known_hosts
redef record HostDetails += {
	counter: count &log &default=0;
  endpoint: Val &log &optional;
};

hook add_host_details(h: HostDetails, d: HostDetails)
	{
	h$counter += d$counter;
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
        names(orig, data.hostname, data.source);
        devices(orig, data.mac, data.source)
        domains(orig, data.machine_domain, data.source)
        #hosts(orig, data.)
    }
    if (resp_local && resp in hosts_data) {
        local data = hosts_data[resp];
        names(resp, data.hostname, data.source);
        devices(resp, data.mac, data.source)
        domains(resp, data.machine_domain, data.source)
        #hosts(resp, data.)
    }

}
