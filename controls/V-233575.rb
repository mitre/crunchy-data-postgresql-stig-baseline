# encoding: UTF-8

control	'V-233575' do
	title	"PostgreSQL must generate audit records when unsuccessful attempts to modify privileges/permissions occur."
	desc	"Failed attempts to change the permissions, privileges, and roles granted to users and roles must be 
	tracked. Without an audit trail, unauthorized attempts to elevate or restrict privileges could go undetected.

Modifying permissions is done via the GRANT and REVOKE commands.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones."
	desc	'rationale', ''
	desc	'check', "Note: The following instructions use the PGDATA and PGLOG environment variables. See 
	supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for PGLOG.

First, as the database administrator (shown here as \"postgres\"), create a role \"bob\" and a test table by 
running the following SQL:

$ sudo su - postgres
$ psql -c \"CREATE ROLE bob; CREATE TABLE test(id INT)\"

Next, set current role to \"bob\" and attempt to modify privileges:

$ psql -c \"SET ROLE bob; GRANT ALL PRIVILEGES ON test TO bob;\"
$ psql -c \"SET ROLE bob; REVOKE ALL PRIVILEGES ON test FROM bob;\"

Now, as the database administrator (shown here as \"postgres\"), verify the unsuccessful attempt was logged:

$ sudo su - postgres
$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
2016-07-14 18:12:23.208 EDT postgres postgres ERROR: permission denied for relation test
2016-07-14 18:12:23.208 EDT postgres postgres STATEMENT: GRANT ALL PRIVILEGES ON test TO bob;
2016-07-14 18:14:52.895 EDT postgres postgres ERROR: permission denied for relation test
2016-07-14 18:14:52.895 EDT postgres postgres STATEMENT: REVOKE ALL PRIVILEGES ON test FROM bob;

If audit logs are not generated when unsuccessful attempts to modify privileges/permissions occur, this is a finding."
	desc	'fix', "Configure PostgreSQL to produce audit records when unsuccessful attempts to modify privileges occur.

All denials are logged by default if logging is enabled. To ensure that logging is enabled, review supplementary 
content APPENDIX-C for instructions on enabling logging."
	impact 0.5
	tag severity: 'medium'
  tag gtitle: 'SRG-APP-000495-DB-000329'
  tag gid: 'V-233575'
  tag rid: 'SV-233575r617333_rule'
  tag stig_id: 'CD12-00-006800'
  tag fix_id: 'F-36734r606949_fix'
  tag cci: ["CCI-000172"]
  tag nist: ["AU-12 c"]

pg_ver = input('pg_version')

pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

pg_log_dir = input('pg_log_dir')

pg_audit_log_dir = input('pg_audit_log_dir')

	if file(pg_audit_log_dir).exist?
		describe command("PGPASSWORD='#{pg_dba_password}' psql -U #{pg_dba} -d #{pg_db} -h #{pg_host} -A -t -c \"CREATE ROLE fooaudit; CREATE TABLE fooaudittest (id int); SET ROLE fooaudit; GRANT ALL PRIVILEGES ON fooaudittest TO fooaudit; DROP TABLE IF EXISTS fooaudittest;\"") do
		  its('stdout') { should match // }
		end
	  
		describe command("grep -r \"permission denied for relation\\|table\" #{pg_audit_log_dir}") do
		 its('stdout') { should match /^.*pg_authid.*$/ }
		end 
	  else
		describe "The #{pg_audit_log_dir} directory was not found. Check path for this postgres version/install to define the value for the 'pg_audit_log_dir' inspec input parameter." do
		  skip "The #{pg_audit_log_dir} directory was not found. Check path for this postgres version/install to define the value for the 'pg_audit_log_dir' inspec input parameter."
		end
	  end
	  
	  end

