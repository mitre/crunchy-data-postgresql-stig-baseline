# encoding: UTF-8

control	'V-233589' do
	title	"PostgreSQL must initiate session auditing upon startup."
	desc	"Session auditing is for use when a user's activities are under investigation. To ensure the capture 
	of all activity during those periods when session auditing is in use, it needs to be in operation for the whole 
	time PostgreSQL is running."
	desc	'rationale', ''
	desc	'check', "As the database administrator (shown here as \"postgres\"), check the current settings by 
	running the following SQL: 

$ sudo su - postgres 
$ psql -c \"SHOW shared_preload_libraries\" 

If pgaudit is not in the current setting, this is a finding. 

As the database administrator (shown here as \"postgres\"), check the current settings by running the following SQL: 

$ psql -c \"SHOW log_destination\" 

If stderr or syslog are not in the current setting, this is a finding."
	desc	'fix', "Configure PostgreSQL to enable auditing.

To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

For session logging, using pgaudit is recommended. For instructions on how to setup pgaudit, see supplementary 
content APPENDIX-B."
	impact 0.5
	tag severity: 'medium'
  tag gtitle: 'SRG-APP-000092-DB-000208'
  tag gid: 'V-233589'
  tag rid: 'SV-233589r617333_rule'
  tag stig_id: 'CD12-00-008600'
  tag fix_id: 'F-36748r606991_fix'
  tag cci: ["CCI-001464"]
  tag nist: ["AU-14 (1)"]

pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

	sql = postgres_session(pg_dba, pg_dba_password, pg_host, input('pg_port'))

	describe sql.query('SHOW shared_preload_libraries;', [pg_db]) do
	  its('output') { should include 'pgaudit' }
	end
  
	describe sql.query('SHOW log_destination;', [pg_db]) do
	  its('output') { should match /stderr|syslog/i }
	end
  end

