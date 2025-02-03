control 'V-233559' do
  title 'PostgreSQL must generate audit records when security objects are deleted.'
  desc "The removal of security objects from the database/PostgreSQL would seriously degrade a system's
	information assurance posture. If such an event occurs, it must be logged."
  desc 'check', %q(Note: The following instructions use the PGDATA and PGLOG environment variables. See
	supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for PGLOG.

First, as the database administrator (shown here as "postgres"), create a test table stig_test, enable row level
security, and create a policy by running the following SQL:

$ sudo su - postgres
$ psql -c "CREATE TABLE stig_test(id INT)"
$ psql -c "ALTER TABLE stig_test ENABLE ROW LEVEL SECURITY"
$ psql -c "CREATE POLICY lock_table ON stig_test USING ('postgres' = current_user)"

Next, drop the policy and disable row level security:

$ psql -c "DROP POLICY lock_table ON stig_test"
$ psql -c "ALTER TABLE stig_test DISABLE ROW LEVEL SECURITY"

Now, as the database administrator (shown here as "postgres"), verify the security objects deletions were logged:

$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
2016-03-30 14:54:18.991 EDT postgres postgres LOG: AUDIT: SESSION,11,1,DDL,DROP POLICY,,,DROP POLICY lock_table ON
stig_test;,<none>
2016-03-30 14:54:42.373 EDT postgres postgres LOG: AUDIT: SESSION,12,1,DDL,ALTER TABLE,,,ALTER TABLE stig_test
DISABLE ROW LEVEL SECURITY;,<none>

If audit records are not produced when security objects are dropped, this is a finding.)
  desc 'fix', "Note: The following instructions use the PGDATA and PGVER environment variables. See supplementary
	content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Using pgaudit PostgreSQL can be configured to audit these requests. See supplementary content APPENDIX-B for
documentation on installing pgaudit.

With pgaudit installed the following configurations can be made:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.log = 'ddl'

Now, as the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000501-DB-000336'
  tag gid: 'V-233559'
  tag rid: 'SV-233559r961818_rule'
  tag stig_id: 'CD12-00-005200'
  tag fix_id: 'F-36718r606901_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  if file(input('pg_audit_log_dir')).exist?
    describe sql.query("CREATE TABLE stig_test(id INT); ALTER TABLE stig_test ENABLE ROW LEVEL SECURITY; CREATE POLICY lock_table ON stig_test USING ('postgres' = current_user); DROP POLICY lock_table ON stig_test; ALTER TABLE stig_test DISABLE ROW LEVEL SECURITY; DROP TABLE stig_test;", [input('pg_db')]) do
      its('output') { should match // }
    end

    describe command("grep -r \"AUDIT: SESSION\" #{input('pg_audit_log_dir')}") do
      its('stdout') { should match /^.*CREATE TABLE,,,CREATE TABLE stig_test.*$/ }
    end

    describe command("grep -r \"AUDIT: SESSION\" #{input('pg_audit_log_dir')}") do
      its('stdout') { should match /^.*ALTER TABLE stig_test ENABLE ROW LEVEL SECURITY.*$/ }
    end

    describe command("grep -r \"AUDIT: SESSION\" #{input('pg_audit_log_dir')}") do
      its('stdout') { should match /^.*CREATE POLICY lock_table ON stig_test.*$/ }
    end

    describe command("grep -r \"AUDIT: SESSION\" #{input('pg_audit_log_dir')}") do
      its('stdout') { should match /^.*DROP POLICY lock_table ON stig_test.*$/ }
    end

    describe command("grep -r \"AUDIT: SESSION\" #{input('pg_audit_log_dir')}") do
      its('stdout') { should match /^.*ALTER TABLE stig_test DISABLE ROW LEVEL SECURITY.*$/ }
    end

    describe command("grep -r \"AUDIT: SESSION\" #{input('pg_audit_log_dir')}") do
      its('stdout') { should match /^.*DROP TABLE stig_test.*$/ }
    end
  else
    describe "The #{input('pg_audit_log_dir')} directory was not found. Check path for this postgres version/install to define the value for the 'input('pg_audit_log_dir')' inspec input parameter." do
      skip "The #{input('pg_audit_log_dir')} directory was not found. Check path for this postgres version/install to define the value for the 'input('pg_audit_log_dir')' inspec input parameter."
    end
  end
end
