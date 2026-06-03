module EndpointEnrichment;

## Enrich known_hosts ##
# VLAN tag support version

redef record Known::HostInfo += {
        ep: Val &log &optional;
};

hook Known::update_host_info(en: Known::HostInfo, d: Known::HostData)
        {
        if ( ! extra_logging_known )
                return;

        if ( en?$ep )
                # Have already enriched this entry.
                return;

        local h = en$host_ip;
        if ( h !in hosts_data )
                return;

        local data = hosts_data[h];
        local ep = Known::addr_to_endpoint(h);
        local ts = d$ts;
        local source = data$source;
        local anno = source + "/" + data$status;

        if ( data?$hostname )
                {
                Known::track_name(ts, source, ep, data$hostname);
                Known::add_name_annotation(ep, data$hostname, anno);
                }

        if ( data?$mac )
                {
                # Some MAC's have "-" and should have ":", normalize to ":".
                local mac = subst_string(data$mac, "-", ":");
                Known::track_mac(ts, source, ep, mac, mac);
                Known::add_device_annotation(ep, mac, anno);
                }

        if ( data?$machine_domain )
                {
                Known::track_name(ts, source,  ep, data$machine_domain);
                Known::add_domain_annotation(ep, data$machine_domain, anno);
                }

        en$ep = data;
        }
