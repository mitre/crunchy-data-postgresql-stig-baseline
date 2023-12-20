control 'V-233588' do
  title 'PostgreSQL must separate user functionality (including user interface services) from database
	management functionality.'
  desc 'Information system management functionality includes functions necessary to administer databases,
	network components, workstations, or servers and typically requires privileged user access.

The separation of user functionality from information system management functionality is either physical or logical
and is accomplished by using different computers, different central processing units, different instances of the
operating system, different network addresses, combinations of these methods, or other methods, as appropriate.

An example of this type of separation is observed in web administrative interfaces that use separate authentication
methods for users of any other information system resources.

This may include isolating the administrative interface on a different domain and with additional access controls.

If administrative functionality or information regarding PostgreSQL management is presented on an interface available
for users, information on DBMS settings may be inadvertently made available to the user.'
  desc 'check', 'Check PostgreSQL settings and vendor documentation to verify that administrative functionality is separate from user functionality.

As the database administrator (shown here as "postgres"), list all roles and permissions for the database:

$ sudo su - postgres
$ psql -c "\du"

If any non-administrative role has the attribute "Superuser", "Create role", "Create DB" or "Bypass RLS", this is a finding.

If administrator and general user functionality are not separated either physically or logically, this is a finding.'
  desc 'fix', 'Configure PostgreSQL to separate database administration and general user functionality.

Do not grant superuser, create role, create db, or bypass rls role attributes to users that do not require it.

To remove privileges, see the following example:

ALTER ROLE <username> NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000211-DB-000122'
  tag gid: 'V-233588'
  tag rid: 'SV-233588r606989_rule'
  tag stig_id: 'CD12-00-008500'
  tag fix_id: 'F-36747r606988_fix'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']

  privileges = %w(rolcreatedb rolcreaterole rolsuper)
  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  roles_sql = 'SELECT r.rolname FROM pg_catalog.pg_roles r;'
  roles_query = sql.query(roles_sql, [input('pg_db')])
  roles = roles_query.lines

  roles.each do |role|
    next if input('pg_superusers').include?(role)
    privileges.each do |privilege|
      privilege_sql = "SELECT r.#{privilege} FROM pg_catalog.pg_roles r "\
      "WHERE r.rolname = '#{role}';"

      describe sql.query(privilege_sql, [input('pg_db')]) do
        its('output') { should_not eq 't' }
      end
    end
  end
end
