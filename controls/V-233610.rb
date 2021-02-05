# encoding: UTF-8

pg_ver = input('pg_version')

pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

control	'V-233610' do
	title	"PostgreSQL must off-load audit data to a separate log management facility; this must be continuous 
	and in near real time for systems with a network connection to the storage facility and weekly or more often 
	for stand-alone systems."
	desc	"Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity. 

PostgreSQL may write audit records to database tables, to files in the file system, to other kinds of local 
repository, or directly to a centralized log management system. Whatever the method used, it must be compatible 
with off-loading the records to the centralized system."
	desc	'rationale', ''
	desc	'check', "First, as the database administrator (shown here as \"postgres\"), ensure PostgreSQL uses 
	syslog by running the following SQL:

$ sudo su - postgres
$ psql -c \"SHOW log_destination\"

If log_destination is not syslog, this is a finding.

Next, as the database administrator, check which log facility is configured by running the following SQL:

$ psql -c \"SHOW syslog_facility\" 

Check with the organization to see how syslog facilities are defined in their organization.

If the wrong facility is configured, this is a finding.

If PostgreSQL does not have a continuous network connection to the centralized log management system, and 
PostgreSQL audit records are not transferred to the centralized log management system weekly or more often, this is 
a finding."
	desc	'fix', "Note: The following instructions use the PGDATA and PGVER environment variables. See 
	supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Configure PostgreSQL or deploy and configure software tools to transfer audit records to a centralized log management 
system, continuously and in near-real time where a continuous network connection to the log management system exists, 
or at least weekly in the absence of such a connection.

To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

With logging enabled, as the database administrator (shown here as \"postgres\"), configure the following parameters 
in postgresql.conf (the example uses the default values - tailor for environment):

Note: Consult the organization on how syslog facilities are defined in the syslog daemon configuration.

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf
log_destination = 'syslog'
syslog_facility = 'LOCAL0'
syslog_ident = 'postgres'

Now, as the system administrator, reload the server with the new configuration:

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

  describe sql.query('SHOW log_destination;', [pg_db]) do
    its('output') { should cmp 'csvlog,syslog'}
  end

  
  #Change comparison value based on organizational syslog defintions
  describe sql.query('SHOW syslog_facility;', [pg_db]) do
    its('output') { should cmp 'local0'}
  end  

  describe "Configure PostgreSQL or deploy and configure software tools to transfer audit records to a centralized log management system" do
    skip "If continuous network connection to the log management system does not exist, or at least weekly in the absence of such a connection. This is a finding"
  end
end

