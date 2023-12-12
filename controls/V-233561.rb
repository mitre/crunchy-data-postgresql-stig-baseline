control	'V-233561' do
  title	'PostgreSQL must generate audit records when unsuccessful attempts to delete privileges/permissions occur.'
  desc	"Failed attempts to change the permissions, privileges, and roles granted to users and roles must be
	tracked. Without an audit trail, unauthorized attempts to elevate or restrict privileges could go undetected.

In a SQL environment, deleting permissions is typically done via the REVOKE command.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones."
  desc	'rationale', ''
  desc	'check', "Note: The following instructions use the PGDATA and PGLOG environment variables. See
	supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for PGLOG.

First, as the database administrator (shown here as \"postgres\"), create the roles \"joe\" and \"bob\" with LOGIN
by running the following SQL:

$ sudo su - postgres
$ psql -c \"CREATE ROLE joe LOGIN\"
$ psql -c \"CREATE ROLE bob LOGIN\"

Next, set current role to \"bob\" and attempt to alter the role \"joe\":

$ psql -c \"SET ROLE bob; ALTER ROLE joe NOLOGIN;\"

Now, as the database administrator (shown here as \"postgres\"), verify the denials are logged:

$ sudo su - postgres
$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
< 2016-03-17 11:28:10.004 EDT bob 56eacd05.cda postgres: >ERROR: permission denied to alter role
< 2016-03-17 11:28:10.004 EDT bob 56eacd05.cda postgres: >STATEMENT: ALTER ROLE joe;

If audit logs are not generated when unsuccessful attempts to delete privileges/permissions occur, this is a finding."
  desc	'fix', "Configure PostgreSQL to produce audit records when unsuccessful attempts to delete privileges occur.

All denials are logged if logging is enabled. To ensure logging is enabled, review supplementary content APPENDIX-C
for instructions on enabling logging."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000499-DB-000331'
  tag gid: 'V-233561'
  tag rid: 'SV-233561r617333_rule'
  tag stig_id: 'CD12-00-005400'
  tag fix_id: 'F-36720r606907_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  if file(input('pg_audit_log_dir')).exist?
    describe sql.query('CREATE ROLE pgauditrolefailuretest; SET ROLE pgauditrolefailuretest; DROP ROLE postgres; SET ROLE postgres; DROP ROLE pgauditrolefailuretest;', [input('pg_db')]) do
      its('output') { should match // }
    end

    describe command("grep -r \"permission denied to drop role\" #{input('pg_audit_log_dir')}") do
      its('stdout') { should match /^.*permission denied to drop role.*$/ }
    end
  else
    describe "The #{input('pg_audit_log_dir')} directory was not found. Check path for this postgres version/install to define the value for the 'input('pg_audit_log_dir')' inspec input parameter." do
      skip "The #{input('pg_audit_log_dir')} directory was not found. Check path for this postgres version/install to define the value for the 'input('pg_audit_log_dir')' inspec input parameter."
    end
  end
end
