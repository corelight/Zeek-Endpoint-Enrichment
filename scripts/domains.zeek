function domains(ip: string, domain: string, source: string):
{
  ++Known::get_domain_details(ip, domain)$counter;
	Known::add_domain_annotation(ip, domain, set(source));
}
