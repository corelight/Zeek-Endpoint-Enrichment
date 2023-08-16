## known_hosts
redef record HostDetails += {
	counter: count &log &default=0;
  endpoint: Val &log &optional;
};

hook add_host_details(h: HostDetails, d: HostDetails)
	{
	h$counter += d$counter;
	}

function hosts(ip: string, endpoint: Val):
{

  ++Known::get_host_details(ip)$counter;
	$endpoint = host_data[ip];


}
