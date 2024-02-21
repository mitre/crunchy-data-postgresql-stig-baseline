control 'V-233551' do
  title 'PostgreSQL must generate audit records when categorized information (e.g., classification
	levels/security levels) is accessed.'
  desc 'Changes in categories of information must be tracked. Without an audit trail, unauthorized access to
	protected data could go undetected.

For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security
Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security
Requirements for Federal Information and Information Systems.'
  desc 'check', 'As the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -c "SHOW pgaudit.log"

If pgaudit.log does not contain, "ddl, write, role", this is a finding.'
  desc 'fix', "Note: The following instructions use the PGDATA and PGVER environment variables. See
	supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Using pgaudit, the DBMS (PostgreSQL) can be configured to audit these requests. See supplementary content
APPENDIX-B for documentation on installing pgaudit.

With pgaudit installed the following configurations can be made:

$ sudo su - postgres

$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.log = 'ddl, write, role'

Next, as the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql- ${PGVER?}"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000494-DB-000344'
  tag gid: 'V-233551'
  tag rid: 'SV-233551r879865_rule'
  tag stig_id: 'CD12-00-004400'
  tag fix_id: 'F-36710r606877_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  pgaudit_types = %w(ddl role write)

  pgaudit_types.each do |type|
    describe sql.query('SHOW pgaudit.log;', [input('pg_db')]) do
      its('output') { should include type }
    end
  end
end
