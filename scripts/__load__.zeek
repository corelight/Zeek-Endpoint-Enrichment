@load ./new_conn.zeek
@load ./main.zeek
@load ./conn.zeek
@load ./id-logs.zeek

# Only load known.zeek if Known Entities package is enabled..
@ifdef (Known::tracking)
@load ./known.zeek
@endif
