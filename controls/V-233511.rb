control 'V-233511' do
  title 'PostgreSQL must be configured to prohibit or restrict the use of organization-defined functions, ports,
	protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized
	tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or
	unnecessary physical and logical ports/protocols/services on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services
provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes
convenient to provide multiple services from a single component (e.g., email and web services); however, doing so
increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the application must support the organizational
requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only
those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

Database Management Systems using ports, protocols, and services deemed unsafe are open to attack through those ports,
protocols, and services. This can allow unauthorized access to the database and through the database to other
components of the information system.'
  desc 'check', 'As the database administrator, run the following SQL:

$ psql -c "SHOW port"
$ psql -c "SHOW listen_addresses"

If the currently defined address:port configuration is deemed prohibited, this is a finding.'
  desc 'fix', 'Note: The following instructions use the PGDATA and PGVER environment variables. See supplementary
	content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To change the listening port of the database, as the database administrator, change the following setting in
postgresql.conf:

$ sudo su - postgres
$ vi $PGDATA/postgresql.conf

Change the port parameter to the desired port.

Next, restart the database:

# SYSTEMD SERVER ONLY
$ sudo systemctl restart postgresql-${PGVER?}

Note: psql uses the port 5432 by default. This can be changed by specifying the port with psql or by setting the
PGPORT environment variable:

$ psql -p 5432 -c "SHOW port"
$ export PGPORT=5432'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag gid: 'V-233511'
  tag rid: 'SV-233511r879588_rule'
  tag stig_id: 'CD12-00-000100'
  tag fix_id: 'F-36670r617419_fix'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  describe sql.query('SHOW port;', [input('pg_db')]) do
    its('output') { should eq input('pg_port') }
  end

  if !input('aws_rds')

	  if virtualization.system == 'docker'
	    describe 'The docker container must have networking tools to check its ports and their processes' do
	      skip 'If the currently defined port configuration is deemed prohibited, this is a finding.'
	    end
	
	  else
	    describe port(input('pg_port')) do
	      it { should be_listening }
	      its('processes') { should match ['postmaster'] }
	    end
	  end
  end
end
