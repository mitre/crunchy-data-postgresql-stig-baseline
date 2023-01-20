# encoding: UTF-8

control	'V-233618' do
	title	"PostgreSQL must protect its audit configuration from unauthorized modification."
	desc	"Protecting audit data also includes identifying and protecting the tools used to view and manipulate 
	log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the 
user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the 
modification of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view 
and manipulate audit information system activity and records. Audit tools include custom queries and report generators."
	desc	'rationale', ''
	desc	'check', "All configurations for auditing and logging can be found in the postgresql.conf configuration 
	file. By default, this file is owned by the database administrator account. 

To check that the permissions of the postgresql.conf are owned by the database administrator with permissions of 
0600, run the following as the database administrator (shown here as \"postgres\"):

$ sudo su - postgres
$ ls -la ${PGDATA?}

If postgresql.conf is not owned by the database administrator or does not have 0600 permissions, this is a finding.

#### stderr Logging

To check that logs are created with 0600 permissions, check the following setting:

$ sudo su - postgres
$ psql -c \"SHOW log_file_mode\"

If permissions are not 0600, this is a finding.

#### syslog Logging

If PostgreSQL is configured to use syslog, verify that the logs are owned by root and have 0600 permissions. If they 
are not, this is a finding."
	desc	'fix', "Apply or modify access controls and permissions (both within PostgreSQL and in the file 
	system/operating system) to tools used to view or modify audit log data. Tools must be configurable by authorized 
	personnel only.

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf
log_file_mode = 0600

Next, as the database administrator (shown here as \"postgres\"), change the ownership and permissions of 
configuration files in PGDATA:

$ sudo su - postgres
$ chown postgres:postgres ${PGDATA?}/*.conf
$ chmod 0600 ${PGDATA?}/*.conf"
	impact 0.5
	tag severity: 'medium'
  tag gtitle: 'SRG-APP-000122-DB-000203'
  tag gid: 'V-233618'
  tag rid: 'SV-233618r617333_rule'
  tag stig_id: 'CD12-00-012200'
  tag fix_id: 'F-36777r607078_fix'
  tag cci: ["CCI-001494"]
  tag nist: ["AU-9"]

pg_data_dir = input('pg_data_dir') #not in use

	describe file(input('pg_conf_file')) do
		it { should be_file }
		its('mode') { should cmp '0600' }
	  end
	
	  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))
	
	  log_destination_query = sql.query('SHOW log_destination;', [input('pg_db')])
	  log_destination = log_destination_query.output
	
	  if log_destination =~ /stderr/i
		describe sql.query('SHOW log_file_mode;', [input('pg_db')]) do
		  its('output') { should cmp '0600' }
		end
	  end
	end

