control 'V-233622' do
  title 'PostgreSQL must generate audit records for all direct access to the database(s).'
  desc 'In this context, direct access is any query, command, or call to the DBMS that comes from any source
	other than the application(s) that it supports. Examples would be the command line or a database management
	utility program. The intent is to capture all activity from administrative and non-standard sources.'
  desc 'check', 'As the database administrator, verify pgaudit is enabled by running the following SQL:

$ sudo su - postgres
$ psql -c "SHOW shared_preload_libraries"

If the output does not contain "pgaudit", this is a finding.

Verify that connections and disconnections are being logged by running the following SQL:

$ sudo su - postgres
$ psql -c "SHOW log_connections"
$ psql -c "SHOW log_disconnections"

If the output does not contain "on", this is a finding.'
  desc 'fix', "Note: The following instructions use the PGDATA and PGVER environment variables. See
	supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

Using pgaudit, PostgreSQL can be configured to audit these requests. See supplementary content APPENDIX-B for
documentation on installing pgaudit.

With pgaudit installed, the following configurations should be made:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.log='ddl, role, read, write'
log_connections='on'
log_disconnections='on'

Now, as the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000508-DB-000358'
  tag gid: 'V-233622'
  tag rid: 'SV-233622r879879_rule'
  tag stig_id: 'CD12-00-012700'
  tag fix_id: 'F-36781r607090_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  describe sql.query('SHOW shared_preload_libraries;', [input('pg_db')]) do
    its('output') { should include 'pgaudit' }
  end

  describe sql.query('SHOW log_connections;', [input('pg_db')]) do
    its('output') { should match /on|true/i }
  end

  describe sql.query('SHOW log_disconnections;', [input('pg_db')]) do
    its('output') { should match /on|true/i }
  end
end
