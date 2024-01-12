module EndpointEnrichment;

## Add VLAN to all logs with an "id" field.
export {
    ## Enables the logging of endpoint details to the conn log.
    option extra_logging_x509 = F;
    option extra_logging_x509_cid = F;
}

redef record X509::Info += {
    orig_ep_status: string &log &optional;
    orig_ep_uid: string &log &optional;
    orig_ep_cid: string &log &optional;
    orig_ep_source: string &log &optional;
    resp_ep_status: string &log &optional;
    resp_ep_uid: string &log &optional;
    resp_ep_cid: string &log &optional;
    resp_ep_source: string &log &optional;
};

# event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
#     {
#     for ( id in f$conns )
#         {
#         if ( id?$vlan )
#             f$info$x509$vlan = id$vlan;
#         if ( id?$vlan_inner )
#             f$info$x509$vlan_inner = id$vlan_inner;
#         # just grab the first one
#         break;
#         }
#     }
