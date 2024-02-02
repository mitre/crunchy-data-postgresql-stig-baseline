control 'V-233560' do
  title 'PostgreSQL must generate audit records when unsuccessful attempts to retrieve privileges/permissions
	occur.'
  desc 'Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role
	information. Therefore, it must be possible to configure auditing to do this. PostgreSQLs typically make such
		information available through views or functions.

This requirement addresses explicit requests for privilege/permission/role membership information. It does not refer
to the implicit retrieval of privileges/permissions/role memberships that PostgreSQL continually performs to
determine if any and every action on the database is permitted.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', 'Note: The following instructions use the PGLOG environment variables. See supplementary content
	APPENDIX-I for instructions on configuring PGLOG.

First, as the database administrator (shown here as "postgres"), create a role "bob" by running the following SQL:

$ sudo su - postgres
$ psql -c "CREATE ROLE bob"

Next, attempt to retrieve information from the pg_authid table:

$ psql -c "SET ROLE bob; SELECT * FROM pg_authid"
$ psql -c "DROP ROLE bob;"

Now, as the database administrator (shown here as "postgres"), verify the event was logged in pg_log:

$ sudo su - postgres
$ cat ${PGLOG?}/<latest_log>
< 2016-07-13 16:49:58.864 EDT postgres postgres ERROR: > permission denied for relation pg_authid
< 2016-07-13 16:49:58.864 EDT postgres postgres STATEMENT: > SELECT * FROM pg_authid;

If the above steps cannot verify that audit records are produced when PostgreSQL denies retrieval of
privileges/permissions/role memberships, this is a finding.'
  desc 'fix', 'Configure PostgreSQL to produce audit records when unsuccessful attempts to access privileges
	occur.

All denials are logged if logging is enabled. To ensure that logging is enabled, review supplementary content
APPENDIX-C for instructions on enabling logging.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000091-DB-000325'
  tag gid: 'V-233560'
  tag rid: 'SV-233560r606905_rule'
  tag stig_id: 'CD12-00-005300'
  tag fix_id: 'F-36719r606904_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  if input('aws_rds')
    describe 'Requires manual review of the RDS audit log system.' do
      skip 'Requires manual review of the RDS audit log system.'
    end
  else
  
    sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))
  
    if file(input('pg_audit_log_dir')).exist?
      describe sql.query('CREATE ROLE fooaudit; SET ROLE fooaudit; SELECT * FROM pg_authid; SET ROLE postgres; DROP ROLE fooaudit;', [input('pg_db')]) do
        its('output') { should match // }
      end
  
      describe command("grep -r \"permission denied for table\\|relation\" #{input('pg_audit_log_dir')}") do
        its('stdout') { should match /^.*pg_authid.*$/ }
      end
    else
      describe "The #{input('pg_audit_log_dir')} directory was not found. Check path for this postgres version/install to define the value for the 'input('pg_audit_log_dir')' inspec input parameter." do
        skip "The #{input('pg_audit_log_dir')} directory was not found. Check path for this postgres version/install to define the value for the 'input('pg_audit_log_dir')' inspec input parameter."
      end
    end

  end
end
