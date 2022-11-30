# encoding: UTF-8

control	'V-233558' do
	title	"PostgreSQL must generate audit records when successful logons or connections occur."
	desc	"For completeness of forensic analysis, it is necessary to track who/what (a user or other principal) 
	logs on to PostgreSQL."
	desc	'rationale', ''
	desc	'check', "Note: The following instructions use the PGDATA and PGLOG environment variables. See 
	supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for PGLOG.

First, as the database administrator (shown here as \"postgres\"), check if log_connections is enabled by running 
the following SQL:

$ sudo su - postgres
$ psql -c \"SHOW log_connections\"

If log_connections is off, this is a finding.

Next, verify the logs that the previous connection to the database was logged:

$ sudo su - postgres
$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
< 2016-02-16 15:54:03.934 EST postgres postgres 56c64b8b.aeb: >LOG: connection authorized: user=postgres 
database=postgres

If an audit record is not generated each time a user (or other principal) logs on or connects to PostgreSQL, this is 
a finding."
	desc	'fix', "Note: The following instructions use the PGDATA and PGVER environment variables. See 
	supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

If logging is enabled the following configurations must be made to log connections, date/time, username, and session 
identifier.

First, as the database administrator (shown here as \"postgres\"), edit postgresql.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Edit the following parameters as such:

log_connections = on
log_line_prefix = '< %m %u %d %c: >'

Where:
* %m is the time and date
* %u is the username
* %d is the database
* %c is the session ID for the connection

Now, as the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}"
	impact 0.5
	tag severity: 'medium'
  tag gtitle: 'SRG-APP-000503-DB-000350'
  tag gid: 'V-233558'
  tag rid: 'SV-233558r617333_rule'
  tag stig_id: 'CD12-00-005100'
  tag fix_id: 'F-36717r606898_fix'
  tag cci: ["CCI-000172"]
  tag nist: ["AU-12 c"]

pg_ver = input('pg_version')

pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

pg_log_dir = input('pg_log_dir')

pg_audit_log_dir = input('pg_audit_log_dir')

sql = postgres_session(pg_dba, pg_dba_password, pg_host, input('pg_port'))

	if file(pg_audit_log_dir).exist?
		describe sql.query('SHOW log_connections;', [pg_db]) do
		  its('stdout') { should match /on/ }
		end
	   
		 describe command("grep -r \"connection authorized\" #{pg_audit_log_dir}") do
		   its('stdout') { should match /^.*user=postgres.*$/ }
		 end 
	   else
		 describe "The #{pg_audit_log_dir} directory was not found. Check path for this postgres version/install to define the value for the 'pg_audit_log_dir' inspec input parameter." do
		   skip "The #{pg_audit_log_dir} directory was not found. Check path for this postgres version/install to define the value for the 'pg_audit_log_dir' inspec input parameter."
		 end
	   end
	   
	   end

