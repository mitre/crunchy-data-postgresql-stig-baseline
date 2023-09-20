# encoding: UTF-8

control	'V-233553' do
	title	"PostgreSQL must generate audit records when unsuccessful logons or connection attempts occur."
	desc	"For completeness of forensic analysis, it is necessary to track failed attempts to log on to 
	PostgreSQL. While positive identification may not be possible in a case of failed authentication, as much 
		information as possible about the incident must be captured."
	desc	'rationale', ''
	desc	'check', "Note: The following instructions use the PGDATA and PGLOG environment variables. See 
	supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I on PGLOG.

In this example the user \"joe\" will log in to the Postgres database unsuccessfully:

$ psql -d postgres -U joe

As the database administrator (shown here as \"postgres\"), check ${PGLOG?} for a FATAL connection audit trail:

$ sudo su - postgres
$ cat ${PGDATA?}/${PGLOG?}/{latest_log>
< 2016-02-16 16:18:13.027 EST joe 56c65135.b5f postgres: >LOG: connection authorized: user=joe database=postgres
< 2016-02-16 16:18:13.027 EST joe 56c65135.b5f postgres: >FATAL: role \"joe\" does not exist

If an audit record is not generated each time a user (or other principal) attempts, but fails to log on or 
connect to PostgreSQL (including attempts where the user ID is invalid/unknown), this is a finding."
	desc	'fix', "Note: The following instructions use the PGDATA and PGVER environment variables. See 
	supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

If logging is enabled the following configurations must be made to log unsuccessful connections, date/time, 
username, and session identifier.

First, as the database administrator (shown here as \"postgres\"), edit postgresql.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Edit the following parameters:

log_connections = on
log_line_prefix = '< %m %u %c: >'

Where:
* %m is the time and date
* %u is the username
* %c is the session ID for the connection

Next, as the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}"
	impact 0.5
	tag severity: 'medium'
  tag gtitle: 'SRG-APP-000503-DB-000351'
  tag gid: 'V-233553'
  tag rid: 'SV-233553r617333_rule'
  tag stig_id: 'CD12-00-004600'
  tag fix_id: 'F-36712r606883_fix'
  tag cci: ["CCI-000172"]
  tag nist: ["AU-12 c"]

sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

	if file(input('pg_audit_log_dir')).exist?

		describe sql.query('SET ROLE pgauditrolefailuretest;', [input('pg_db')]) do
		  its('output') { should match // }
		end
	  
		describe command("grep -r \"does not exist\" #{input('pg_audit_log_dir')}") do
		  its('stdout') { should match /^.*role \"\"pgauditrolefailuretest\"\" does not exist.*$/ }
		end 
	  else
		describe "The #{input('pg_audit_log_dir')} directory was not found. Check path for this postgres version/install to define the value for the 'input('pg_audit_log_dir')' inspec input parameter." do
		  skip "The #{input('pg_audit_log_dir')} directory was not found. Check path for this postgres version/install to define the value for the 'input('pg_audit_log_dir')' inspec input parameter."
		end 
	  end
	  
	  end

