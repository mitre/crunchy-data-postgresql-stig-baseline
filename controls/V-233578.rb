# encoding: UTF-8

control	'V-233578' do
	title	"PostgreSQL must produce audit records containing sufficient information to establish where the events 
	occurred."
	desc	"Information system auditing capability is critical for accurate forensic analysis. Without establishing 
	where events occurred, it is impossible to establish, correlate, and investigate the events relating to an incident.

To compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to 
know where events occurred, such as application components, modules, session identifiers, filenames, host names, 
and functionality. 

Associating information about where the event occurred within the application provides a means of investigating an 
attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application."
	desc	'rationale', ''
	desc	'check', "First, as the database administrator (shown here as \"postgres\"), check the current 
	log_line_prefix setting by running the following SQL:

$ sudo su - postgres
$ psql -c \"SHOW log_line_prefix\"

If log_line_prefix does not contain \"%m %u %d %s\", this is a finding."
	desc	'fix', "Note: The following instructions use the PGDATA and PGVER environment variables. See 
	supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To check that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

First edit the postgresql.conf file as the database administrator (shown here as \"postgres\"):

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Extra parameters can be added to the setting log_line_prefix to log application related information:

# %a = application name
# %u = user name
# %d = database name
# %r = remote host and port
# %p = process ID
# %m = timestamp with milliseconds
# %i = command tag
# %s = session startup
# %e = SQL state

For example:

log_line_prefix = '< %m %a %u %d %r %p %i %e %s>'

Now, as the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}"
	impact 0.5
	tag severity: 'medium'
  tag gtitle: 'SRG-APP-000097-DB-000041'
  tag gid: 'V-233578'
  tag rid: 'SV-233578r617333_rule'
  tag stig_id: 'CD12-00-007100'
  tag fix_id: 'F-36737r606958_fix'
  tag cci: ["CCI-000132"]
  tag nist: ["AU-3"]

pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

	sql = postgres_session(pg_dba, pg_dba_password, pg_host, input('pg_port'))

	log_line_prefix_escapes = %w(%m %u %d %s)
  
	log_line_prefix_escapes.each do |escape|
	  describe sql.query('SHOW log_line_prefix;', [pg_db]) do
		its('output') { should include escape }
	  end
	end
  end
