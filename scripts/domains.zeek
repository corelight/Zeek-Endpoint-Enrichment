## known_domains (Domain only)
redef record DomainDetails += {
	counter: count &log &default=0;
};

hook add_domain_details(h: DomainDetails, d: DomainDetails)
	{
	h$counter += d$counter;
	}

function domains(ip: string, domain: string, source: string):
{
  ++Known::get_domain_details(ip, domain)$counter;
	Known::add_domain_annotation(ip, domain, set(source));
}
