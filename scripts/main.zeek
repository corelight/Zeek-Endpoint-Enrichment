module EndpointEnrichment;

export {
	option hosts_data_file = "hosts_data.tsv";
}

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

global hosts_data: table[addr] of Val;

# # source to use for all unknown IPs
# global unknownSource: string;

event zeek_init()
	{
	if ( reading_traces() )
		suspend_processing();

	Input::add_table([$source=hosts_data_file, $name="hosts_data",
				$idx=Idx, $val=Val, $destination=hosts_data,
				$mode=Input::REREAD]);
	}

event Input::end_of_data(name: string, source: string)
	{
	if ( name != "hosts_data" )
		return;

	if ( reading_traces() )
		continue_processing();
	}
