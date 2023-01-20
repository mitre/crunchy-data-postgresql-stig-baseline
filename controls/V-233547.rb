# encoding: UTF-8

control	'V-233547' do
	title	"PostgreSQL must produce audit records of its enforcement of access restrictions associated with changes 
	to the configuration of PostgreSQL or database(s)."
	desc	"Without auditing the enforcement of access restrictions against changes to configuration, it would be 
	difficult to identify attempted attacks and an audit trail would not be available for forensic investigation for 
	after-the-fact actions.

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. 
Enforcement action methods may be as simple as denying access to a file based on the application of file permissions 
(access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes 
identified after the fact."
	desc	'rationale', ''
	desc	'check', "Note: The following instructions use the PGDATA environment variable. See supplementary 
	content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for PGLOG.

To verify that system denies are logged when unprivileged users attempt to change database configuration, as the 
database administrator (shown here as \"postgres\"), run the following commands:

$ sudo su - postgres
$ psql

Next, create a role with no privileges, change the current role to that user and attempt to change a configuration 
by running the following SQL:

CREATE ROLE bob;
SET ROLE bob;
SET pgaudit.role='test';
RESET ROLE;
DROP ROLE bob;

Now check ${PGLOG?} (use the latest log):

$ cat ${PGDATA?}/${PGLOG?}/postgresql-Thu.log
< 2016-01-28 17:57:34.092 UTC bob postgres: >ERROR: permission denied to set parameter \"pgaudit.role\"
< 2016-01-28 17:57:34.092 UTC bob postgres: >STATEMENT: SET pgaudit.role='test';

If the denial is not logged, this is a finding.

By default PostgreSQL configuration files are owned by the postgres user and cannot be edited by non-privileged users:

$ ls -la ${PGDATA?} | grep postgresql.conf
-rw-------. 1 postgres postgres 21758 Jan 22 10:27 postgresql.conf

If postgresql.conf is not owned by the database owner and does not have read and write permissions for the owner, 
this is a finding."
	desc	'fix', "Enable logging.

All denials are logged by default if logging is enabled. To ensure that logging is enabled, review supplementary 
content APPENDIX-C for instructions on enabling logging."
	impact 0.5
	tag severity: 'medium'
  tag gtitle: 'SRG-APP-000381-DB-000361'
  tag gid: 'V-233547'
  tag rid: 'SV-233547r617333_rule'
  tag stig_id: 'CD12-00-004100'
  tag fix_id: 'F-36706r606865_fix'
  tag cci: ["CCI-001814"]
  tag nist: ["CM-5 (1)"]

sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  #Execute an incorrectly-formed SQL statement with bad syntax, to prompt log ouput
  if file(input('pg_audit_log_dir')).exist?

	describe sql.query("CREATE ROLE pgauditrolefailuretest; SET ROLE pgauditrolefailuretest; SET pgaudit.role='test'; SET ROLE postgres; DROP ROLE IF EXISTS pgauditrolefailuretest;", [input('pg_db')]) do
	  its('output') { should match // }
	end
  
	#Find the most recently modified log file in the pg_audit_log_dir, grep for the syntax error statement, and then
	#test to validate the output matches the regex.
  
	describe command("grep -r \"permission denied to set parameter\" #{input('pg_audit_log_dir')}") do
	  its('stdout') { should match /^.*permission denied to set parameter ..pgaudit.role..*$/ }
	end 
  else
	describe "The #{input('pg_audit_log_dir')} directory was not found. Check path for this postgres version/install to define the value for the 'pg_audit_log_dir' inspec input parameter." do
	  skip "The #{input('pg_audit_log_dir')} directory was not found. Check path for this postgres version/install to define the value for the 'pg_audit_log_dir' inspec input parameter."
	end
  end
	
  end

