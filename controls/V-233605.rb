# encoding: UTF-8

control	'V-233605' do
	title	"PostgreSQL must implement cryptographic mechanisms preventing the unauthorized disclosure of 
	organization-defined information at rest on organization-defined information system components."
	desc	"PostgreSQLs handling data requiring data-at-rest protections must employ cryptographic mechanisms to 
	prevent unauthorized disclosure and modification of the information at rest. These cryptographic mechanisms may 
	be native to PostgreSQL or implemented via additional software or operating system/file system settings, as 
	appropriate to the situation.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. 
The strength of the mechanism is commensurate with the security category and/or classification of the information. 
Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) 
or encrypt specific data structures (e.g., files, records, or fields). 

The decision whether and what to encrypt rests with the data owner and is also influenced by the physical measures 
taken to secure the equipment and media on which the information resides."
	desc	'rationale', ''
	desc	'check', "To check if pgcrypto is installed on PostgreSQL, as a database administrator (shown here as 
	\"postgres\"), run the following command:

$ sudo su - postgres
$ psql -c \"SELECT * FROM pg_available_extensions where name='pgcrypto'\"

If data in the database requires encryption and pgcrypto is not available, this is a finding.

If a disk or filesystem requires encryption, ask the system owner, DBA, and SA to demonstrate the use of filesystem 
and/or disk-level encryption. If this is required and is not found, this is a finding."
	desc	'fix', "Configure PostgreSQL, operating system/file system, and additional software as relevant, to 
	provide the required level of cryptographic protection for information requiring cryptographic protection 
	against disclosure.

Secure the premises, equipment, and media to provide the required level of physical protection.

The pgcrypto module provides cryptographic functions for PostgreSQL. See supplementary content APPENDIX-E for 
documentation on installing pgcrypto.

With pgcrypto installed, it is possible to insert encrypted data into the database:

INSERT INTO accounts(username, password) VALUES ('bob', crypt('mypass', gen_salt('bf', 4));"
	impact 0.5
	tag severity: 'medium'
  tag gtitle: 'SRG-APP-000429-DB-000387'
  tag gid: 'V-233605'
  tag rid: 'SV-233605r617333_rule'
  tag stig_id: 'CD12-00-010500'
  tag fix_id: 'F-36764r607039_fix'
  tag cci: ["CCI-002476"]
  tag nist: ["SC-28 (1)"]

	sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

	pgcrypto_sql = "SELECT * FROM pg_available_extensions where name='pgcrypto'"
  
	describe sql.query(pgcrypto_sql, [input('pg_db')]) do
	  its('output') { should_not eq '' }
	end
  end

