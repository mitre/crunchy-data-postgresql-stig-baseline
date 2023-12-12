# encoding: UTF-8

control	'V-233557' do
	title	"PostgreSQL must generate audit records when unsuccessful attempts to delete categorized information 
	(e.g., classification levels/security levels) occur."
	desc	"Changes in categorized information must be tracked. Without an audit trail, unauthorized access to 
	protected data could go undetected.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.

For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security 
Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security 
Requirements for Federal Information and Information Systems."
	desc	'rationale', ''
	desc	'check', "First, as the database administrator, verify pgaudit is enabled by running the following SQL:

$ sudo su - postgres
$ psql -c \"SHOW shared_preload_libraries\"

If the output does not contain \"pgaudit\", this is a finding.

Next, verify that role, read, write, and ddl auditing are enabled:

$ psql -c \"SHOW pgaudit.log\"

If the output does not contain role, read, write, and ddl, this is a finding."
	desc	'fix', "Note: The following instructions use the PGDATA and PGVER environment variables. See 
	supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

All errors and denials are logged if logging is enabled. To ensure logging is enabled, review supplementary content 
APPENDIX-C for instructions on enabling logging.

Using pgaudit PostgreSQL can be configured to audit these requests. See supplementary content APPENDIX-B for 
documentation on installing pgaudit.

With pgaudit installed the following configurations can be made:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.log='ddl, role, read, write'

Now, as the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}"
	impact 0.5
	tag severity: 'medium'
  tag gtitle: 'SRG-APP-000502-DB-000349'
  tag gid: 'V-233557'
  tag rid: 'SV-233557r617333_rule'
  tag stig_id: 'CD12-00-005000'
  tag fix_id: 'F-36716r606895_fix'
  tag cci: ["CCI-000172"]
  tag nist: ["AU-12 c"]

	sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

	describe sql.query('SHOW shared_preload_libraries;', [input('pg_db')]) do
	  its('output') { should include 'pgaudit' }
	end
  
	pgaudit_types = %w(ddl read role write)
  
	pgaudit_types.each do |type|
	  describe sql.query('SHOW pgaudit.log;', [input('pg_db')]) do
		its('output') { should include type }
	  end
	end
  end

