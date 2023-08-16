## known_names (Hostname only)
redef record NameDetails += {
	counter: count &log &default=0;
};

hook add_name_details(h: NameDetails, d: NameDetails)
	{
	h$counter += d$counter;
	}

function names(ip: string, name: string, source: string):
{
  ++Known::get_name_details(ip, name)$counter;
	Known::add_name_annotation(ip, name, set(source));
}
