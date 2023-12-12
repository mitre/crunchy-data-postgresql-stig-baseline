control	'V-233609' do
  title	'PostgreSQL must protect its audit features from unauthorized removal.'
  desc	"Protecting audit data also includes identifying and protecting the tools used to view and manipulate
	log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the
user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the
deletion of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view
and manipulate audit information system activity and records. Audit tools include custom queries and report generators."
  desc	'rationale', ''
  desc	'check', "Note: The following instructions use the PGDATA and PGVER environment variables. See
	supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

As the database administrator (shown here as \"postgres\"), verify the permissions of PGDATA:

$ sudo su - postgres
$ ls -la ${PGDATA?}

If PGDATA is not owned by postgres:postgres or if files can be accessed by others, this is a finding.

As the system administrator, verify the permissions of pgsql shared objects and compiled binaries:

$ ls -la /usr/pgsql-${PGVER?}/bin
$ ls -la /usr/pgsql-${PGVER?}/include
$ ls -la /usr/pgsql-${PGVER?}/lib
$ ls -la /usr/pgsql-${PGVER?}/share

If any of these are not owned by root:root, this is a finding."
  desc	'fix', "Note: The following instructions use the PGDATA and PGVER environment variables. See
	supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

As the system administrator, change the permissions of PGDATA:

$ sudo chown -R postgres:postgres ${PGDATA?}
$ sudo chmod 700 ${PGDATA?}

As the system administrator, change the permissions of pgsql:

$ sudo chown -R root:root /usr/pgsql-${PGVER?}"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000123-DB-000204'
  tag gid: 'V-233609'
  tag rid: 'SV-233609r617333_rule'
  tag stig_id: 'CD12-00-011200'
  tag fix_id: 'F-36768r607051_fix'
  tag cci: ['CCI-001495']
  tag nist: ['AU-9']

  describe file(input('pg_hba_conf_file')) do
    it { should be_owned_by input('pg_owner') }
    its('mode') { should cmp '0600' }
  end

  describe file(input('pg_ident_conf_file')) do
    it { should be_owned_by input('pg_owner') }
    its('mode') { should cmp '0600' }
  end

  describe file(input('pg_user_defined_conf')) do
    it { should be_owned_by input('pg_owner') }
    its('mode') { should cmp '0600' }
  end

  describe directory(input('pg_data_dir')) do
    it { should be_owned_by input('pg_owner') }
    it { should be_grouped_into input('pg_group') }
  end

  describe command("find #{input('pg_data_dir')} ! -user #{input('pg_owner')} | wc -l") do
    its('stdout') { should cmp 0 }
  end

  describe command("find #{input('pg_data_dir')} ! -group #{input('pg_group')} | wc -l") do
    its('stdout') { should cmp 0 }
  end

  # NOTE: this accounts for stig-postgresql.conf, hba_conf, pg_ident
  describe command('find /var/lib/pgsql/9.5/data/ ! -perm 600 -type f | wc -l') do
    its('stdout.strip') { should be <= '3' }
  end

  describe command('find /var/lib/pgsql/9.5/data/ ! -perm 700 -type d | wc -l') do
    its('stdout.strip') { should cmp '0' }
  end

  input('pg_shared_dirs').each do |dir|
    next unless directory(dir).exist?
    describe directory(dir) do
      it { should be_owned_by 'root' }
      it { should be_grouped_into 'root' }
    end
  end
end
