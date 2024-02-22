control 'V-233570' do
  title 'PostgreSQL must generate audit records when unsuccessful attempts to delete security objects occur.'
  desc "The removal of security objects from the database/PostgreSQL would seriously degrade a system's
	information assurance posture. If such an action is attempted, it must be logged.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones."
  desc 'check', 'First, as the database administrator, verify pgaudit is enabled by running the following SQL:

$ sudo su - postgres
$ psql -c "SHOW shared_preload_libraries"

If the output does not contain pgaudit, this is a finding.

Next, verify that role, read, write, and ddl auditing are enabled:

$ psql -c "SHOW pgaudit.log"

If the output does not contain role, read, write, and ddl, this is a finding.'
  desc 'fix', "Note: The following instructions use the PGDATA and PGVER environment variables. See
	supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Configure PostgreSQL to produce audit records when unsuccessful attempts to delete security objects occur.

All errors and denials are logged if logging is enabled. To ensure that logging is enabled, review supplementary
content APPENDIX-C for instructions on enabling logging.

With pgaudit installed the following configurations can be made:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.log='ddl, role, read, write'

Now, as the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000501-DB-000337'
  tag gid: 'V-233570'
  tag rid: 'SV-233570r879872_rule'
  tag stig_id: 'CD12-00-006300'
  tag fix_id: 'F-36729r606934_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  if input('aws_rds')
    describe 'Requires manual review of the RDS audit log system.' do
      skip 'Requires manual review of the RDS audit log system.'
    end
  else
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
end
