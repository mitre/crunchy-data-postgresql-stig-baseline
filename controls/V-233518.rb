<<<<<<< HEAD
control	'V-233518' do
  title	"PostgreSQL must limit privileges to change functions and triggers, and links to software external to
	PostgreSQL."
  desc	"If the system were to allow any user to make changes to software libraries, those changes might be
	implemented without undergoing the appropriate testing and approvals that are part of a robust change management
	process.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system
components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database code can lead to unauthorized or compromised installations."
  desc	'rationale', ''
  desc	'check', "Only owners of objects can change them. To view all functions, triggers, and trigger
	procedures, their ownership and source, as the database administrator (shown here as \"postgres\") run the
	following SQL:

$ sudo su - postgres
$ psql -x -c \"\df+\"

Only the OS database owner user (shown here as \"postgres\") or a PostgreSQL superuser can change links to external
software. As the database administrator (shown here as \"postgres\"), check the permissions of configuration files
for the database:

$ sudo su - postgres
$ ls -la ${PGDATA?}

If any files are not owned by the database owner or have permissions allowing others to modify (write) configuration
files, this is a finding."
  desc	'fix', "Note: The following instructions use the PGDATA environment variable. See supplementary content
	APPENDIX-F for instructions on configuring PGDATA.

To change ownership of an object, as the database administrator (shown here as \"postgres\"), run the following SQL:

$ sudo su - postgres
$ psql -c \"ALTER FUNCTION function_name OWNER TO new_role_name\"

To change ownership of postgresql.conf, as the database administrator (shown here as \"postgres\"), run the
following commands:

$ sudo su - postgres
$ chown postgres:postgres ${PGDATA?}/postgresql.conf
$ chmod 0600 ${PGDATA?}/postgresql.conf

To remove superuser from a role, as the database administrator (shown here as \"postgres\"), run the following SQL:

$ sudo su - postgres
$ psql -c \"ALTER ROLE rolename WITH NOSUPERUSER\""
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag gid: 'V-233518'
  tag rid: 'SV-233518r617333_rule'
  tag stig_id: 'CD12-00-000710'
  tag fix_id: 'F-36677r606778_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  pg_owner = input('pg_owner')

  describe file(input('pg_conf_file')) do
    it { should be_owned_by pg_owner }
    its('mode') { should cmp '0600' }
  end

  describe file(input('pg_hba_conf_file')) do
    it { should be_owned_by pg_owner }
    its('mode') { should cmp '0600' }
  end

  describe file(input('pg_ident_conf_file')) do
    it { should be_owned_by pg_owner }
    its('mode') { should cmp '0600' }
  end
end
=======
# encoding: UTF-8

control	'V-233518' do
	title	"PostgreSQL must limit privileges to change functions and triggers, and links to software external to 
	PostgreSQL."
	desc	"If the system were to allow any user to make changes to software libraries, those changes might be 
	implemented without undergoing the appropriate testing and approvals that are part of a robust change management 
	process.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system 
components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database code can lead to unauthorized or compromised installations."
	desc	'rationale', ''
	desc	'check', "Only owners of objects can change them. To view all functions, triggers, and trigger 
	procedures, their ownership and source, as the database administrator (shown here as \"postgres\") run the 
	following SQL:

$ sudo su - postgres
$ psql -x -c \"\df+\"

Only the OS database owner user (shown here as \"postgres\") or a PostgreSQL superuser can change links to external 
software. As the database administrator (shown here as \"postgres\"), check the permissions of configuration files 
for the database:

$ sudo su - postgres
$ ls -la ${PGDATA?}

If any files are not owned by the database owner or have permissions allowing others to modify (write) configuration 
files, this is a finding."
	desc	'fix', "Note: The following instructions use the PGDATA environment variable. See supplementary content 
	APPENDIX-F for instructions on configuring PGDATA.

To change ownership of an object, as the database administrator (shown here as \"postgres\"), run the following SQL:

$ sudo su - postgres
$ psql -c \"ALTER FUNCTION function_name OWNER TO new_role_name\"

To change ownership of postgresql.conf, as the database administrator (shown here as \"postgres\"), run the 
following commands:

$ sudo su - postgres
$ chown postgres:postgres ${PGDATA?}/postgresql.conf
$ chmod 0600 ${PGDATA?}/postgresql.conf

To remove superuser from a role, as the database administrator (shown here as \"postgres\"), run the following SQL:

$ sudo su - postgres
$ psql -c \"ALTER ROLE rolename WITH NOSUPERUSER\""
	impact 0.5
	tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag gid: 'V-233518'
  tag rid: 'SV-233518r617333_rule'
  tag stig_id: 'CD12-00-000710'
  tag fix_id: 'F-36677r606778_fix'
  tag cci: ["CCI-001499"]
  tag nist: ["CM-5 (6)"]

	describe file(input('pg_conf_file')) do
		it { should be_owned_by input('pg_owner') }
		its('mode') { should cmp '0600' }
	  end
	
	  describe file(input('pg_hba_conf_file')) do
		it { should be_owned_by input('pg_owner') }
		its('mode') { should cmp '0600' }
	  end
	
	  describe file(input('pg_ident_conf_file')) do
		it { should be_owned_by input('pg_owner') }
		its('mode') { should cmp '0600' }
	  end  
	end

>>>>>>> c8099699c8781ddc2c93c9e881ef02f71486898f
