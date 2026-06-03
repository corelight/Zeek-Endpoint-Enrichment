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
        uid: string &log &optional;
        ## The customer ID the host belongs to.
        cid: string &log &optional;
        ## The Operating System version of the endpoint host.
        os_version: string &log &optional;
        ## The Operation System type of the endpoint host.
        os_type: string &log &optional;
        ## The source of the endpoint information.
        source: string &log &optional;
        ## The criticality of the endpoint host.
        criticality: string &log &optional;
        ## The MAC address of the endpoint host.
        mac: string &optional;
        ## The hostname of the endpoint host.
        hostname: string &log &optional;
        ## The machine domain of the endpoint host.
        machine_domain: string &optional;
        ## The machine type of the endpoint host.
        machine_type: string &log &optional;
};

global hosts_data: table[addr] of Val = table();


event zeek_init()
        {
        if ( reading_traces() )
                suspend_processing();

        Input::add_table([ $source="hosts_data.tsv", $name="hosts_data", $idx=Idx,
            $val=Val, $destination=hosts_data, $mode=Input::REREAD ]);
        }

event Input::end_of_data(name: string, source: string)
        {
        if ( name != "hosts_data" )
                return;

        if ( reading_traces() )
                continue_processing();
        }
