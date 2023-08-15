function devices(ip: string, mac: string, source: string):
{
  ++Known::get_device_details(ip, mac)$counter;
	Known::add_device_annotation(ip, mac, set(source));
}
