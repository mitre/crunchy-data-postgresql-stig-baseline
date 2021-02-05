# encoding: UTF-8

pg_ver = input('pg_version')

pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

control	'V-233566' do
	title	"PostgreSQL must generate audit records when unsuccessful attempts to access categorized information 
	(e.g., classification levels/security levels) occur."
	desc	"Changes in categories of information must be tracked. Without an audit trail, unauthorized access to 
	protected data could go undetected.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.

For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security 
Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security 
Requirements for Federal Information and Information Systems."
	desc	'rationale', ''
	desc	'check', "As the database administrator (shown here as \"postgres\"), run the following SQL:

$ sudo su - postgres
$ psql -c \"SHOW pgaudit.log\"

If pgaudit.log does not contain, \"ddl, write, role\", this is a finding."
	desc	'fix', "Note: The following instructions use the PGDATA and PGVER environment variables. See 
	supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Configure PostgreSQL to produce audit records when unsuccessful attempts to access categories of information occur.

All denials are logged if logging is enabled. To ensure that logging is enabled, review supplementary content 
APPENDIX-C for instructions on enabling logging.

With pgaudit installed the following configurations can be made:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.log = 'ddl, write, role'

Next, as the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}"
	impact 0.5
	tag severity: 'medium'
	tag gtitle: nil
	tag gid: nil
	tag rid: nil
	tag stig_id: nil
	tag fix_id: nil
	tag cci: nil
	tag nist: nil

	sql = postgres_session(pg_dba, pg_dba_password, pg_host, input('pg_port'))

	pgaudit_types = %w(ddl role write)
  
	pgaudit_types.each do |type|
	  describe sql.query('SHOW pgaudit.log;', [pg_db]) do
		its('output') { should include type }
	  end
	end
  end

