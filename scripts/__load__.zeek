@load ./new_conn.zeek
@load ./main.zeek
@load ./conn.zeek
@load ./id-logs.zeek

# Only load known.zeek if Known Entities package is enabled..
@ifdef (Known::tracking)
  #Load new version if Known Entities with VLAN support is enabled.
  @ifdef (Known::Endpoint)
    @load ./known.zeek
  @else
    #Load older version
    @load ./known_old.zeek
  @endif
@endif
