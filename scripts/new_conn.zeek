module Conn;

event new_connection(c: connection) &priority=10
{
	set_conn(c, F);
}
