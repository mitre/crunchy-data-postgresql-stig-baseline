<<<<<<< HEAD
control	'V-233556' do
  title	'PostgreSQL must generate audit records when privileges/permissions are added.'
  desc	"Changes in the permissions, privileges, and roles granted to users and roles must be tracked. Without
	an audit trail, unauthorized elevation or restriction of privileges could go undetected. Elevated privileges
	give users access to information and functionality that they should not have; restricted privileges wrongly deny
	access to authorized users.

In a SQL environment, adding permissions is typically done via the GRANT command, or, in the negative, the REVOKE
command."
  desc	'rationale', ''
  desc	'check', "Note: The following instructions use the PGDATA and PGLOG environment variables. See
	supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for PGLOG.

First, as the database administrator (shown here as \"postgres\"), create a role by running the following SQL:

Change the privileges of another user:

$ sudo su - postgres
$ psql -c \"CREATE ROLE bob\"

Next, GRANT then REVOKE privileges from the role:

$ psql -c \"GRANT CONNECT ON DATABASE postgres TO bob\"
$ psql -c \"REVOKE CONNECT ON DATABASE postgres FROM bob\"

postgres=# REVOKE CONNECT ON DATABASE postgres FROM bob;
REVOKE

postgres=# GRANT CONNECT ON DATABASE postgres TO bob;
GRANT

Next, as the database administrator (shown here as \"postgres\"), verify the events were logged:

$ sudo su - postgres
$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
< 2016-07-13 16:25:21.103 EDT postgres postgres LOG: > AUDIT: SESSION,1,1,ROLE,GRANT,,,GRANT CONNECT ON DATABASE
postgres TO bob,<none>
< 2016-07-13 16:25:25.520 EDT postgres postgres LOG: > AUDIT: SESSION,1,1,ROLE,REVOKE,,,REVOKE CONNECT ON DATABASE
postgres FROM bob,<none>

If the above steps cannot verify that audit records are produced when privileges/permissions/role memberships are
added, this is a finding."
  desc	'fix', "Note: The following instructions use the PGDATA and PGVER environment variables. See
	supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Using pgaudit, PostgreSQL can be configured to audit these requests. See supplementary content APPENDIX-B for
documentation on installing pgaudit.

With pgaudit installed, the following configurations can be made:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.log = 'role'

Now, as the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000495-DB-000326'
  tag gid: 'V-233556'
  tag rid: 'SV-233556r617333_rule'
  tag stig_id: 'CD12-00-004900'
  tag fix_id: 'F-36715r606892_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  pg_ver = input('pg_version') # not in use

  pg_log_dir = input('pg_log_dir') # not in use

  sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

  if file(input('pg_audit_log_dir')).exist?
    describe sql.query('CREATE ROLE fooaudit; GRANT CONNECT ON DATABASE postgres TO fooaudit; REVOKE CONNECT ON DATABASE postgres FROM fooaudit;', [input('pg_db')]) do
      its('output') { should match // }
    end

    describe command("grep -r \"GRANT CONNECT ON DATABASE postgres TO\" #{input('pg_audit_log_dir')}") do
      its('stdout') { should match /^.*fooaudit.*$/ }
    end

    describe command("grep -r \"REVOKE CONNECT ON DATABASE postgres FROM\" #{input('pg_audit_log_dir')}") do
      its('stdout') { should match /^.*fooaudit.*$/ }
    end
  else
    describe "The #{input('pg_audit_log_dir')} directory was not found. Check path for this postgres version/install to define the value for the 'input('pg_audit_log_dir')' inspec input parameter." do
      skip "The #{input('pg_audit_log_dir')} directory was not found. Check path for this postgres version/install to define the value for the 'input('pg_audit_log_dir')' inspec input parameter."
    end
  end
end
=======
# encoding: UTF-8

control	'V-233556' do
	title	"PostgreSQL must generate audit records when privileges/permissions are added."
	desc	"Changes in the permissions, privileges, and roles granted to users and roles must be tracked. Without 
	an audit trail, unauthorized elevation or restriction of privileges could go undetected. Elevated privileges 
	give users access to information and functionality that they should not have; restricted privileges wrongly deny 
	access to authorized users.

In a SQL environment, adding permissions is typically done via the GRANT command, or, in the negative, the REVOKE 
command."
	desc	'rationale', ''
	desc	'check', "Note: The following instructions use the PGDATA and PGLOG environment variables. See 
	supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for PGLOG.

First, as the database administrator (shown here as \"postgres\"), create a role by running the following SQL:

Change the privileges of another user:

$ sudo su - postgres
$ psql -c \"CREATE ROLE bob\"

Next, GRANT then REVOKE privileges from the role:

$ psql -c \"GRANT CONNECT ON DATABASE postgres TO bob\"
$ psql -c \"REVOKE CONNECT ON DATABASE postgres FROM bob\"

postgres=# REVOKE CONNECT ON DATABASE postgres FROM bob;
REVOKE

postgres=# GRANT CONNECT ON DATABASE postgres TO bob;
GRANT

Next, as the database administrator (shown here as \"postgres\"), verify the events were logged:

$ sudo su - postgres
$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
< 2016-07-13 16:25:21.103 EDT postgres postgres LOG: > AUDIT: SESSION,1,1,ROLE,GRANT,,,GRANT CONNECT ON DATABASE 
postgres TO bob,<none>
< 2016-07-13 16:25:25.520 EDT postgres postgres LOG: > AUDIT: SESSION,1,1,ROLE,REVOKE,,,REVOKE CONNECT ON DATABASE 
postgres FROM bob,<none>

If the above steps cannot verify that audit records are produced when privileges/permissions/role memberships are 
added, this is a finding."
	desc	'fix', "Note: The following instructions use the PGDATA and PGVER environment variables. See 
	supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Using pgaudit, PostgreSQL can be configured to audit these requests. See supplementary content APPENDIX-B for 
documentation on installing pgaudit.

With pgaudit installed, the following configurations can be made:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.log = 'role'

Now, as the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}"
	impact 0.5
	tag severity: 'medium'
  tag gtitle: 'SRG-APP-000495-DB-000326'
  tag gid: 'V-233556'
  tag rid: 'SV-233556r617333_rule'
  tag stig_id: 'CD12-00-004900'
  tag fix_id: 'F-36715r606892_fix'
  tag cci: ["CCI-000172"]
  tag nist: ["AU-12 c"]

sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

	if file(input('pg_audit_log_dir')).exist?
		describe sql.query('CREATE ROLE fooaudit; GRANT CONNECT ON DATABASE postgres TO fooaudit; REVOKE CONNECT ON DATABASE postgres FROM fooaudit;', [input('pg_db')]) do
		  its('output') { should match // }
		end
	  
		describe command("grep -r \"GRANT CONNECT ON DATABASE postgres TO\" #{input('pg_audit_log_dir')}") do
		  its('stdout') { should match /^.*fooaudit.*$/ }
		end 
		
		describe command("grep -r \"REVOKE CONNECT ON DATABASE postgres FROM\" #{input('pg_audit_log_dir')}") do
		  its('stdout') { should match /^.*fooaudit.*$/ }
		end
	  else
		describe "The #{input('pg_audit_log_dir')} directory was not found. Check path for this postgres version/install to define the value for the 'input('pg_audit_log_dir')' inspec input parameter." do
		  skip "The #{input('pg_audit_log_dir')} directory was not found. Check path for this postgres version/install to define the value for the 'input('pg_audit_log_dir')' inspec input parameter."
		end 
	  end
	  
	  end

>>>>>>> c8099699c8781ddc2c93c9e881ef02f71486898f
