# encoding: UTF-8

pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

pg_superusers = input('pg_superusers')

control	'V-233524' do
	title	"PostgreSQL must uniquely identify and authenticate non-organizational users (or processes acting on 
	behalf of non-organizational users)."
	desc	"Non-organizational users include all information system users other than organizational users, which 
	includes organizational employees or individuals the organization deems to have equivalent status of employees 
	(e.g., contractors, guest researchers, individuals from allied nations). 

Non-organizational users must be uniquely identified and authenticated for all accesses other than those accesses 
explicitly identified and documented by the organization when related to the use of anonymous access, such as 
accessing a web server. 

Accordingly, a risk assessment is used in determining the authentication needs of the organization. 

Scalability, practicality, and security are simultaneously considered in balancing the need to ensure ease of use 
for access to federal information and information systems with the need to protect and adequately mitigate risk to 
	organizational operations, organizational assets, individuals, other organizations, and the Nation."
	desc	'rationale', ''
	desc	'check', "PostgreSQL uniquely identifies and authenticates PostgreSQL users through the use of DBMS roles. 

To list all roles in the database, as the database administrator (shown here as \"postgres\"), run the following SQL:

$ sudo su - postgres
$ psql -c \"\du\"

If users are not uniquely identified per organizational documentation, this is a finding."
	desc	'fix', "To drop a role, as the database administrator (shown here as \"postgres\"), run the following SQL:

$ sudo su - postgres
$ psql -c \"DROP ROLE <role_to_drop>\"

To create a role, as the database administrator, run the following SQL:

$ sudo su - postgres
$ psql -c \"CREATE ROLE <role name> LOGIN\"

For the complete list of permissions allowed by roles, see the official documentation: 
https://www.postgresql.org/docs/current/static/sql-createrole.html"
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

	authorized_roles = pg_superusers
  
	roles_sql = 'SELECT r.rolname FROM pg_catalog.pg_roles r where r.rolsuper;'
	describe sql.query(roles_sql, [pg_db]) do
	  its('lines.sort') { should cmp authorized_roles.sort }
	end
  end

