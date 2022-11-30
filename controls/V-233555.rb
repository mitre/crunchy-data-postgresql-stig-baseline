# encoding: UTF-8

control	'V-233555' do
	title	"PostgreSQL must generate audit records when unsuccessful attempts to modify security objects occur."
	desc	"Changes in the database objects (tables, views, procedures, functions) that record and control 
	permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, 
	unauthorized changes to the security subsystem could go undetected. The database could be severely compromised 
	or rendered inoperative.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones."
	desc	'rationale', ''
	desc	'check', "Note: The following instructions use the PGDATA and PGLOG environment variables. See 
	supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for PGLOG.

As the database administrator (shown here as \"postgres\"), create a test role by running the following SQL:

$ sudo su - postgres
$ psql -c \"CREATE ROLE bob\"

Next, to test if audit records are generated from unsuccessful attempts at modifying security objects, run the 
following SQL:

$ sudo su - postgres
$ psql -c \"SET ROLE bob; UPDATE pg_authid SET rolsuper = 't' WHERE rolname = 'bob';\"

Next, as the database administrator (shown here as \"postgres\"), verify the denials were logged:

$ sudo su - postgres
$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
< 2016-03-17 10:34:00.017 EDT bob 56eabf52.b62 postgres: >ERROR: permission denied for relation pg_authid
< 2016-03-17 10:34:00.017 EDT bob 56eabf52.b62 postgres: >STATEMENT: UPDATE pg_authid SET rolsuper = 't' WHERE 
rolname = 'bob';

If denials are not logged, this is a finding."
	desc	'fix', "Configure PostgreSQL to produce audit records when unsuccessful attempts to modify security 
	objects occur.

Unsuccessful attempts to modify security objects can be logged if logging is enabled. To ensure logging is enabled,
 review supplementary content APPENDIX-C for instructions on enabling logging."
	impact 0.5
	tag severity: 'medium'
  tag gtitle: 'SRG-APP-000496-DB-000335'
  tag gid: 'V-233555'
  tag rid: 'SV-233555r617333_rule'
  tag stig_id: 'CD12-00-004800'
  tag fix_id: 'F-36714r606889_fix'
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
		describe sql.query('CREATE ROLE permdeniedtest; SET ROLE permdeniedtest; UPDATE pg_authid SET rolsuper = 't' WHERE rolname = 'permdeniedtest'; DROP ROLE IF EXISTS permdeniedtest;', [pg_db]) do
		  its('stdout') { should match // }
		end
	  
		describe command("grep -r \"permission denied for relation\\|table pg_authid\" #{pg_audit_log_dir}") do
		  its('stdout') { should match /^.*permission denied for (relation|table) pg_authid.*$/ }
		end 
	  else
		describe "The #{pg_audit_log_dir} directory was not found. Check path for this postgres version/install to define the value for the 'pg_audit_log_dir' inspec input parameter." do
		  skip "The #{pg_audit_log_dir} directory was not found. Check path for this postgres version/install to define the value for the 'pg_audit_log_dir' inspec input parameter."
		end
	  end
	  
	  end

