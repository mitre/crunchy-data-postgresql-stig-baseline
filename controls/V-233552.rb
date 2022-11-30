# encoding: UTF-8

control	'V-233552' do
	title	"PostgreSQL must generate audit records when unsuccessful attempts to access security objects occur."
	desc	"Changes to the security configuration must be tracked.

This requirement applies to situations where security data is retrieved or modified via data manipulation 
operations, as opposed to via specialized security functionality.

In an SQL environment, types of access include, but are not necessarily limited to:

SELECT
INSERT
UPDATE
DELETE
EXECUTE

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones."
	desc	'rationale', ''
	desc	'check', "Note: The following instructions use the PGDATA and PGLOG environment variables. See 
	supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for PGLOG.

First, as the database administrator (shown here as \"postgres\"), setup a test schema and revoke users privileges 
from using it by running the following SQL:

$ sudo su - postgres
$ psql -c \"CREATE SCHEMA stig_test_schema AUTHORIZATION postgres\"
$ psql -c \"REVOKE ALL ON SCHEMA stig_test_schema FROM public\"
$ psql -c \"GRANT ALL ON SCHEMA stig_test_schema TO postgres\"

Next, create a test table, insert a value into that table for the following checks by running the following SQL:

$ psql -c \"CREATE TABLE stig_test_schema.stig_test_table(id INT)\"
$ psql -c \"INSERT INTO stig_test_schema.stig_test_table(id) VALUES (0)\"

#### CREATE
Attempt to CREATE a table in the stig_test_schema schema with a role that does not have privileges by running the 
following SQL:

psql -c \"CREATE ROLE bob; SET ROLE bob; CREATE TABLE stig_test_schema.test_table(id INT);\"
ERROR: permission denied for schema stig_test_schema

Next, as a database administrator (shown here as \"postgres\"), verify that the denial was logged:

$ sudo su - postgres
$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
< 2016-03-09 09:55:19.423 EST postgres 56e0393f.186b postgres: >ERROR: permission denied for schema stig_test_schema 
at character 14
< 2016-03-09 09:55:19.423 EST postgres 56e0393f.186b postgres: >STATEMENT: CREATE TABLE 
stig_test_schema.test_table(id INT);

If the denial is not logged, this is a finding.

#### INSERT
As role bob, attempt to INSERT into the table created earlier, stig_test_table by running the following SQL:

$ sudo su - postgres
$ psql -c \"SET ROLE bob; INSERT INTO stig_test_schema.stig_test_table(id) VALUES (0);\"

Next, as a database administrator (shown here as \"postgres\"), verify that the denial was logged:

$ sudo su - postgres
$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
< 2016-03-09 09:58:30.709 EST postgres 56e0393f.186b postgres: >ERROR: permission denied for schema 
stig_test_schema at character 13
< 2016-03-09 09:58:30.709 EST postgres 56e0393f.186b postgres: >STATEMENT: INSERT INTO 
stig_test_schema.stig_test_table(id) VALUES (0);

If the denial is not logged, this is a finding.

#### SELECT
As role bob, attempt to SELECT from the table created earlier, stig_test_table by running the following SQL:

$ sudo su - postgres
$ psql -c \"SET ROLE bob; SELECT * FROM stig_test_schema.stig_test_table;\"

Next, as a database administrator (shown here as \"postgres\"), verify that the denial was logged:

$ sudo su - postgres
$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
< 2016-03-09 09:57:58.327 EST postgres 56e0393f.186b postgres: >ERROR: permission denied for schema 
stig_test_schema at character 15
< 2016-03-09 09:57:58.327 EST postgres 56e0393f.186b postgres: >STATEMENT: SELECT * FROM 
stig_test_schema.stig_test_table;

If the denial is not logged, this is a finding.

#### ALTER
As role bob, attempt to ALTER the table created earlier, stig_test_table by running the following SQL:

$ sudo su - postgres
$ psql -c \"SET ROLE bob; ALTER TABLE stig_test_schema.stig_test_table ADD COLUMN name TEXT;\"

Next, as a database administrator (shown here as \"postgres\"), verify that the denial was logged:

$ sudo su - postgres
$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
< 2016-03-09 10:03:43.765 EST postgres 56e0393f.186b postgres: >STATEMENT: ALTER TABLE 
stig_test_schema.stig_test_table ADD COLUMN name TEXT;

If the denial is not logged, this is a finding.

#### UPDATE
As role bob, attempt to UPDATE a row created earlier, stig_test_table by running the following SQL:

$ sudo su - postgres
$ psql -c \"SET ROLE bob; UPDATE stig_test_schema.stig_test_table SET id=1 WHERE id=0;\"

Next, as a database administrator (shown here as \"postgres\"), verify that the denial was logged:

$ sudo su - postgres
$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
< 2016-03-09 10:08:27.696 EST postgres 56e0393f.186b postgres: >ERROR: permission denied for schema 
stig_test_schema at character 8
< 2016-03-09 10:08:27.696 EST postgres 56e0393f.186b postgres: >STATEMENT: UPDATE 
stig_test_schema.stig_test_table SET id=1 WHERE id=0;

If the denial is not logged, this is a finding.

#### DELETE
As role bob, attempt to DELETE a row created earlier, stig_test_table by running the following SQL:

$ sudo su - postgres
$ psql -c \"SET ROLE bob; DELETE FROM stig_test_schema.stig_test_table WHERE id=0;\"

Next, as a database administrator (shown here as \"postgres\"), verify that the denial was logged:

$ sudo su - postgres
$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
< 2016-03-09 10:09:29.607 EST postgres 56e0393f.186b postgres: >ERROR: permission denied for schema 
stig_test_schema at character 13
< 2016-03-09 10:09:29.607 EST postgres 56e0393f.186b postgres: >STATEMENT: DELETE FROM 
stig_test_schema.stig_test_table WHERE id=0;

If the denial is not logged, this is a finding.

#### PREPARE 
As role bob, attempt to execute a prepared system using PREPARE by running the following SQL:

$ sudo su - postgres
$ psql -c \"SET ROLE bob; PREPARE stig_test_plan(int) AS SELECT id FROM stig_test_schema.stig_test_table 
WHERE id=$1;\"

Next, as a database administrator (shown here as \"postgres\"), verify that the denial was logged:

$ sudo su - postgres
$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
< 2016-03-09 10:16:22.628 EST postgres 56e03e02.18e4 postgres: >ERROR: permission denied for schema 
stig_test_schema at character 46
< 2016-03-09 10:16:22.628 EST postgres 56e03e02.18e4 postgres: >STATEMENT: PREPARE stig_test_plan(int) AS 
SELECT id FROM stig_test_schema.stig_test_table WHERE id=$1;

If the denial is not logged, this is a finding.

#### DROP
As role bob, attempt to DROP the table created earlier stig_test_table by running the following SQL:

$ sudo su - postgres
$ psql -c \"SET ROLE bob; DROP TABLE stig_test_schema.stig_test_table;\"

Next, as a database administrator (shown here as \"postgres\"), verify that the denial was logged:

$ sudo su - postgres
$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
< 2016-03-09 10:18:55.255 EST postgres 56e03e02.18e4 postgres: >ERROR: permission denied for schema 
stig_test_schema
< 2016-03-09 10:18:55.255 EST postgres 56e03e02.18e4 postgres: >STATEMENT: DROP TABLE 
stig_test_schema.stig_test_table;

If the denial is not logged, this is a finding."
	desc	'fix', "Configure PostgreSQL to produce audit records when unsuccessful attempts to access security 
	objects occur.

All denials are logged if logging is enabled. To ensure that logging is enabled, review supplementary content 
APPENDIX-C for instructions on enabling logging."
	impact 0.5
	tag severity: 'medium'
  tag gtitle: 'SRG-APP-000492-DB-000333'
  tag gid: 'V-233552'
  tag rid: 'SV-233552r617333_rule'
  tag stig_id: 'CD12-00-004500'
  tag fix_id: 'F-36711r606880_fix'
  tag cci: ["CCI-000172"]
  tag nist: ["AU-12 c"]

pg_ver = input('pg_version')

pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

pg_log_dir = input('pg_log_dir')

pg_audit_log_dir = input('pg_audit_log_dir')

sql = postgres_session(pg_dba, pg_dba_password, pg_host, input('pg_port'))

	if file(pg_audit_log_dir).exist?
		describe sql.query('CREATE ROLE permdeniedtest; CREATE SCHEMA permdeniedschema; SET ROLE permdeniedtest; CREATE TABLE permdeniedschema.usertable(index int);', [pg_db]) do
		 its('stdout') { should match // }
		end
	  
		#Find the most recently modified log file in the pg_audit_log_dir, grep for the syntax error statement, and then
		#test to validate the output matches the regex.
	  
		describe command("grep -r \"permission denied for schema\" #{pg_audit_log_dir}") do
		  its('stdout') { should match /^.*permission denied for schema permdeniedschema..*$/ }
		end 
		describe sql.query('SET ROLE postgres; DROP SCHEMA IF EXISTS permdeniedschema; DROP ROLE IF EXISTS permdeniedtest;', [pg_db]) do
		 its('stdout') { should match // }
		end
	  else
		describe "The #{pg_audit_log_dir} directory was not found. Check path for this postgres version/install to define the value for the 'pg_audit_log_dir' inspec input parameter." do
		  skip "The #{pg_audit_log_dir} directory was not found. Check path for this postgres version/install to define the value for the 'pg_audit_log_dir' inspec input parameter."
		end
	  end
	  
	  end

