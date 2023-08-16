## known_devices (MAC address only)
redef record DeviceDetails += {
	counter: count &log &default=0;
};

hook add_device_details(h: DeviceDetails, d: DeviceDetails)
	{
	h$counter += d$counter;
	}

function devices(ip: string, mac: string, source: string):
{
  ++Known::get_device_details(ip, mac)$counter;
	Known::add_device_annotation(ip, mac, set(source));
}
