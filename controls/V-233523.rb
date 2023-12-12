<<<<<<< HEAD
control	'V-233523' do
  title	"The role(s)/group(s) used to modify database structure (including but not necessarily limited to
	tables, indexes, storage, etc.) and logic modules (functions, trigger procedures, links to software external to
		PostgreSQL, etc.) must be restricted to authorized users."
  desc	"If PostgreSQL were to allow any user to make changes to database structure or logic, those changes might
	be implemented without undergoing the appropriate testing and approvals that are part of a robust change
	management process.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system
components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or
compromised installations."
  desc	'rationale', ''
  desc	'check', "Note: The following instructions use the PGDATA environment variable. See supplementary content
	APPENDIX-F for instructions on configuring PGDATA.

As the database administrator (shown here as \"postgres\"), list all users and their permissions by running the
following SQL:

$ sudo su - postgres
$ psql -c \"\dp *.*\"

Verify that all objects have the correct privileges. If they do not, this is a finding.

Next, as the database administrator (shown here as \"postgres\"), verify the permissions of the database directory
on the filesystem:

$ ls -la ${PGDATA?}

If permissions of the database directory are not limited to an authorized user account, this is a finding."
  desc	'fix', "As the database administrator, revoke any permissions from a role that are deemed unnecessary
	by running the following SQL:

ALTER ROLE bob NOCREATEDB;
ALTER ROLE bob NOCREATEROLE;
ALTER ROLE bob NOSUPERUSER;
ALTER ROLE bob NOINHERIT;
REVOKE SELECT ON some_function FROM bob;"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-DB-000362'
  tag gid: 'V-233523'
  tag rid: 'SV-233523r617333_rule'
  tag stig_id: 'CD12-00-001300'
  tag fix_id: 'F-36682r606793_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  pg_owner = input('pg_owner')

  pg_group = input('pg_group')

  if !input('windows_runner')
    sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

    authorized_owners = input('pg_superusers')
    owners = authorized_owners.join('|')

    object_granted_privileges = 'arwdDxtU'
    object_public_privileges = 'r'
    object_acl = "^((((#{owners})=[#{object_granted_privileges}]+|"\
      "=[#{object_public_privileges}]+)\/\\w+,?)+|)\\|"
    object_acl_regex = Regexp.new(object_acl)

    pg_settings_acl = "^((((#{owners})=[#{object_granted_privileges}]+|"\
      "=rw)\/\\w+,?)+)\\|pg_catalog\\|pg_settings\\|v"
    pg_settings_acl_regex = Regexp.new(pg_settings_acl)

    tested = []
    objects_sql = 'SELECT n.nspname, c.relname, c.relkind '\
      'FROM pg_catalog.pg_class c '\
      'LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace '\
      "WHERE c.relkind IN ('r', 'v', 'm', 'S', 'f');"

    databases_sql = 'SELECT datname FROM pg_catalog.pg_database where not datistemplate;'
    databases_query = sql.query(databases_sql, [input('pg_db')])
    databases = databases_query.lines

    databases.each do |database|
      rows = sql.query(objects_sql, [database])
      next unless rows.methods.include?(:output) # Handle connection disabled on database
      objects = rows.lines

      objects.each do |obj|
        next if tested.include?(obj)
        schema, object, type = obj.split('|')
        relacl_sql = "SELECT pg_catalog.array_to_string(c.relacl, E','), "\
          'n.nspname, c.relname, c.relkind FROM pg_catalog.pg_class c '\
          'LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace '\
          "WHERE n.nspname = '#{schema}' AND c.relname = '#{object}' "\
          "AND c.relkind = '#{type}';"

        sql_result = sql.query(relacl_sql, [database])

        describe.one do
          describe sql_result do
            its('output') { should match object_acl_regex }
          end

          describe sql_result do
            its('output') { should match pg_settings_acl_regex }
          end
        end
        tested.push(obj)
      end
    end

    describe 'Column acl check' do
      skip "Review all access privileges and column access privileges list.
		  If any roles' privileges exceed those documented, this is a finding."
    end

    describe directory(input('pg_data_dir')) do
      it { should be_directory }
      it { should be_owned_by pg_owner }
      its('mode') { should cmp '0700' }
    end
  else
    describe 'This must be manually reviewed at this time' do
      skip 'This must be manually reveiwed at this time'
    end
  end
end
=======
# encoding: UTF-8

control	'V-233523' do
	title	"The role(s)/group(s) used to modify database structure (including but not necessarily limited to 
	tables, indexes, storage, etc.) and logic modules (functions, trigger procedures, links to software external to 
		PostgreSQL, etc.) must be restricted to authorized users."
	desc	"If PostgreSQL were to allow any user to make changes to database structure or logic, those changes might 
	be implemented without undergoing the appropriate testing and approvals that are part of a robust change 
	management process.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system 
components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or 
compromised installations."
	desc	'rationale', ''
	desc	'check', "Note: The following instructions use the PGDATA environment variable. See supplementary content 
	APPENDIX-F for instructions on configuring PGDATA.

As the database administrator (shown here as \"postgres\"), list all users and their permissions by running the 
following SQL:

$ sudo su - postgres
$ psql -c \"\dp *.*\"

Verify that all objects have the correct privileges. If they do not, this is a finding.

Next, as the database administrator (shown here as \"postgres\"), verify the permissions of the database directory 
on the filesystem:

$ ls -la ${PGDATA?}

If permissions of the database directory are not limited to an authorized user account, this is a finding."
	desc	'fix', "As the database administrator, revoke any permissions from a role that are deemed unnecessary 
	by running the following SQL:

ALTER ROLE bob NOCREATEDB;
ALTER ROLE bob NOCREATEROLE;
ALTER ROLE bob NOSUPERUSER;
ALTER ROLE bob NOINHERIT;
REVOKE SELECT ON some_function FROM bob;"
	impact 0.5
	tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-DB-000362'
  tag gid: 'V-233523'
  tag rid: 'SV-233523r617333_rule'
  tag stig_id: 'CD12-00-001300'
  tag fix_id: 'F-36682r606793_fix'
  tag cci: ["CCI-001499"]
  tag nist: ["CM-5 (6)"]

	if !input('windows_runner')
		sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))
	
		object_granted_privileges = 'arwdDxtU'
		object_public_privileges = 'r'
		object_acl = "^((((#{input('pg_superusers').join('|')})=[#{object_granted_privileges}]+|"\
		  "=[#{object_public_privileges}]+)\/\\w+,?)+|)\\|"
		object_acl_regex = Regexp.new(object_acl)
	
		pg_settings_acl = "^((((#{input('pg_superusers').join('|')})=[#{object_granted_privileges}]+|"\
		  "=rw)\/\\w+,?)+)\\|pg_catalog\\|pg_settings\\|v"
		pg_settings_acl_regex = Regexp.new(pg_settings_acl)
	
		tested = []
		objects_sql = "SELECT n.nspname, c.relname, c.relkind "\
		  "FROM pg_catalog.pg_class c "\
		  "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "\
		  "WHERE c.relkind IN ('r', 'v', 'm', 'S', 'f');"
	
		databases_sql = 'SELECT datname FROM pg_catalog.pg_database where not datistemplate;'
		databases_query = sql.query(databases_sql, [input('pg_db')])
		databases = databases_query.lines
	
		databases.each do |database|
		  rows = sql.query(objects_sql, [database])
		  if rows.methods.include?(:output) # Handle connection disabled on database
			objects = rows.lines
	
			objects.each do |obj|
			  unless tested.include?(obj)
				schema, object, type = obj.split('|')
				relacl_sql = "SELECT pg_catalog.array_to_string(c.relacl, E','), "\
				  "n.nspname, c.relname, c.relkind FROM pg_catalog.pg_class c "\
				  "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "\
				  "WHERE n.nspname = '#{schema}' AND c.relname = '#{object}' "\
				  "AND c.relkind = '#{type}';"
	
				sql_result=sql.query(relacl_sql, [database])
	
				describe.one do
				  describe sql_result do
					its('output') { should match object_acl_regex }
				  end
	
				  describe sql_result do
					its('output') { should match pg_settings_acl_regex }
				  end
				end
				tested.push(obj)
			  end
			end
		  end
		end
	
		describe "Column acl check" do
		  skip "Review all access privileges and column access privileges list. 
		  If any roles' privileges exceed those documented, this is a finding."
		end
	
		describe directory(input('pg_data_dir')) do
		  it { should be_directory }
		  it { should be_owned_by input('pg_owner') }
		  its('mode') { should cmp '0700' }
		end
	  else
		describe 'This must be manually reviewed at this time' do
		  skip 'This must be manually reveiwed at this time'
		end
	  end
	end

>>>>>>> c8099699c8781ddc2c93c9e881ef02f71486898f
