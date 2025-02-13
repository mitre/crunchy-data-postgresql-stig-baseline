control 'V-233606' do
  title 'PostgreSQL must invalidate session identifiers upon user logout or other session termination.'
  desc %q(Captured sessions can be reused in "replay" attacks. This requirement limits the ability of
	adversaries to capture and continue to employ previously valid session IDs.

This requirement focuses on communications protection for PostgreSQL session rather than for the network packet.
The intent of this control is to establish grounds for confidence at each end of a communications session in the
ongoing identity of the other party and in the validity of the information being transmitted.

Session IDs are tokens generated by PostgreSQLs to uniquely identify a user's (or process's) session. DBMSs will
make access decisions and execute logic based on the session ID.

Unique session IDs help to reduce predictability of said identifiers. Unique session IDs address man-in-the-middle
attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to
identify or guess the session information related to pending application traffic, they will have more difficulty in
hijacking the session or otherwise manipulating valid sessions.

When a user logs out, or when any other session termination event occurs, PostgreSQL must terminate the user
session(s) to minimize the potential for sessions to be hijacked.)
  desc 'check', 'As the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -c "SHOW tcp_keepalives_idle"
$ psql -c "SHOW tcp_keepalives_interval"
$ psql -c "SHOW tcp_keepalives_count"
$ psql -c "SHOW statement_timeout"

If these settings are not set to something other than zero, this is a finding.'
  desc 'fix', 'Note: The following instructions use the PGDATA and PGVER environment variables. See
	supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

As the database administrator (shown here as "postgres"), edit postgresql.conf:

$ sudo su - postgres
$ vi $PGDATA/postgresql.conf

Set the following parameters to organizational requirements:

statement_timeout = 10000 #milliseconds
tcp_keepalives_idle = 10 # seconds
tcp_keepalives_interval = 10 # seconds
tcp_keepalives_count = 10

Now, as the system administrator, restart the server with the new configuration:

$ sudo systemctl restart postgresql-${PGVER?}'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000220-DB-000149'
  tag gid: 'V-233606'
  tag rid: 'SV-233606r961113_rule'
  tag stig_id: 'CD12-00-010600'
  tag fix_id: 'F-36765r607042_fix'
  tag cci: ['CCI-001185']
  tag nist: ['SC-23 (1)']

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  describe sql.query('SHOW tcp_keepalives_idle;', [input('pg_db')]) do
    its('output') { should_not cmp 0 }
  end

  describe sql.query('SHOW tcp_keepalives_interval;', [input('pg_db')]) do
    its('output') { should_not cmp 0 }
  end

  describe sql.query('SHOW tcp_keepalives_count;', [input('pg_db')]) do
    its('output') { should_not cmp 0 }
  end

  describe sql.query('SHOW statement_timeout;', [input('pg_db')]) do
    its('output') { should_not cmp 0 }
  end
end
