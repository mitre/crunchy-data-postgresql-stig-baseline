<<<<<<< HEAD
control	'V-233591' do
  title	"PostgreSQL must produce audit records containing sufficient information to establish the sources
	(origins) of the events."
  desc	"Information system auditing capability is critical for accurate forensic analysis. Without
	establishing the source of the event, it is impossible to establish, correlate, and investigate the events
	relating to an incident.

To compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to
know where events occurred, such as application components, modules, session identifiers, filenames, host names,
and functionality.

In addition to logging where events occur within the application, the application must also produce audit records
that identify the application itself as the source of the event.

Associating information about the source of the event within the application provides a means of investigating an
attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application."
  desc	'rationale', ''
  desc	'check', "Check PostgreSQL settings and existing audit records to verify information specific to the
	source (origin) of the event is being captured and stored with audit records.

As the database administrator (usually postgres, check the current log_line_prefix and log_hostname setting by
	running the following SQL:

$ sudo su - postgres
$ psql -c \"SHOW log_line_prefix\"
$ psql -c \"SHOW log_hostname\"

For a complete list of extra information that can be added to log_line_prefix, see the official documentation:
https://www.postgresql.org/docs/current/static/runtime-config-logging.html#GUC-LOG-LINE-PREFIX.

If the current settings do not provide enough information regarding the source of the event, this is a finding."
  desc	'fix', "Note: The following instructions use the PGDATA and PGVER environment variables. See
	supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

If logging is enabled, the following configurations can be made to log the source of an event.

First, as the database administrator, edit postgresql.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

###### Log Line Prefix

Extra parameters can be added to the setting log_line_prefix to log source of event:

# %a = application name
# %u = user name
# %d = database name
# %r = remote host and port
# %p = process ID
# %m = timestamp with milliseconds

For example:
log_line_prefix = '< %m %a %u %d %r %p %m >'

###### Log Hostname

By default only IP address is logged. To also log the hostname the following parameter can also be set in
postgresql.conf:

log_hostname = on

Now, as the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000098-DB-000042'
  tag gid: 'V-233591'
  tag rid: 'SV-233591r617333_rule'
  tag stig_id: 'CD12-00-008800'
  tag fix_id: 'F-36750r606997_fix'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3']

  pg_ver = input('pg_version') # not in use

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  log_line_prefix_escapes = %w(%m %u %d %s)
  log_line_prefix_escapes.each do |escape|
    describe sql.query('SHOW log_line_prefix;', [input('pg_db')]) do
      its('output') { should include escape }
    end
  end

  describe sql.query('SHOW log_hostname;', [input('pg_db')]) do
    its('output') { should match /(on|true)/i }
  end
end
=======
# encoding: UTF-8

control	'V-233591' do
	title	"PostgreSQL must produce audit records containing sufficient information to establish the sources 
	(origins) of the events."
	desc	"Information system auditing capability is critical for accurate forensic analysis. Without 
	establishing the source of the event, it is impossible to establish, correlate, and investigate the events 
	relating to an incident.

To compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to 
know where events occurred, such as application components, modules, session identifiers, filenames, host names, 
and functionality. 

In addition to logging where events occur within the application, the application must also produce audit records 
that identify the application itself as the source of the event.

Associating information about the source of the event within the application provides a means of investigating an 
attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application."
	desc	'rationale', ''
	desc	'check', "Check PostgreSQL settings and existing audit records to verify information specific to the 
	source (origin) of the event is being captured and stored with audit records.

As the database administrator (usually postgres, check the current log_line_prefix and log_hostname setting by 
	running the following SQL:

$ sudo su - postgres
$ psql -c \"SHOW log_line_prefix\"
$ psql -c \"SHOW log_hostname\"

For a complete list of extra information that can be added to log_line_prefix, see the official documentation: 
https://www.postgresql.org/docs/current/static/runtime-config-logging.html#GUC-LOG-LINE-PREFIX.

If the current settings do not provide enough information regarding the source of the event, this is a finding."
	desc	'fix', "Note: The following instructions use the PGDATA and PGVER environment variables. See 
	supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

If logging is enabled, the following configurations can be made to log the source of an event.

First, as the database administrator, edit postgresql.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

###### Log Line Prefix

Extra parameters can be added to the setting log_line_prefix to log source of event:

# %a = application name
# %u = user name
# %d = database name
# %r = remote host and port
# %p = process ID
# %m = timestamp with milliseconds

For example:
log_line_prefix = '< %m %a %u %d %r %p %m >'

###### Log Hostname

By default only IP address is logged. To also log the hostname the following parameter can also be set in 
postgresql.conf:

log_hostname = on

Now, as the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}"
	impact 0.5
	tag severity: 'medium'
  tag gtitle: 'SRG-APP-000098-DB-000042'
  tag gid: 'V-233591'
  tag rid: 'SV-233591r617333_rule'
  tag stig_id: 'CD12-00-008800'
  tag fix_id: 'F-36750r606997_fix'
  tag cci: ["CCI-000133"]
  tag nist: ["AU-3"]

	sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

	log_line_prefix_escapes = %w(%m %u %d %s)
	log_line_prefix_escapes.each do |escape|
	  describe sql.query('SHOW log_line_prefix;', [input('pg_db')]) do
		its('output') { should include escape }
	  end
	end
  
	describe sql.query('SHOW log_hostname;', [input('pg_db')]) do
	  its('output') { should match /(on|true)/i }
	end
  end

>>>>>>> c8099699c8781ddc2c93c9e881ef02f71486898f
