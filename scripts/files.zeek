module EndpointEnrichment;

## Add VLAN to all logs with an "id" field.
export {
    ## Enables the logging of endpoint details to the conn log.
    option extra_logging_files = F;
    option extra_logging_files_cid = F;
}

redef record Files::Info += {
    orig_ep_status: string &log &optional;
    orig_ep_uid: string &log &optional;
    orig_ep_cid: string &log &optional;
    orig_ep_source: string &log &optional;
    resp_ep_status: string &log &optional;
    resp_ep_uid: string &log &optional;
    resp_ep_cid: string &log &optional;
    resp_ep_source: string &log &optional;
};

# event file_sniff(f: fa_file, meta: fa_metadata) 	{
#     if (extra_logging_files) {
#         for ( tx in f$tx_hosts ) {
#             if ( id?$vlan )
#                 f$info$vlan = id$vlan;
#             if ( id?$vlan_inner )
#                 f$info$vlan_inner = id$vlan_inner;
#             # just grab the first one
#             break;
#         }
#     }
# }
