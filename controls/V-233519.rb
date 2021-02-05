# encoding: UTF-8

pg_data_dir = input('pg_data_dir')

pg_hba_conf_file = input('pg_hba_conf_file')

control	'V-233519' do
	title	"If passwords are used for authentication, PostgreSQL must transmit only encrypted representations of 
	passwords."
	desc	"The DoD standard for authentication is DoD-approved PKI certificates.

Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, 
and requires Authorizing Official (AO) approval.

In such cases, passwords need to be protected at all times, and encryption is the standard method for protecting 
passwords during transmission.

PostgreSQL passwords sent in clear text format across the network are vulnerable to discovery by unauthorized users. 
Disclosure of passwords may easily lead to unauthorized access to the database."
	desc	'rationale', ''
	desc	'check', "Note: The following instructions use the PGDATA environment variable. See supplementary 
	content APPENDIX-F for instructions on configuring PGDATA.

As the database administrator (shown here as \"postgres\"), review the authentication entries in pg_hba.conf:

$ sudo su - postgres
$ cat ${PGDATA?}/pg_hba.conf

If any entries use the auth_method (last column in records) \"password\" or \"md5\", this is a finding."
	desc	'fix', "Note: The following instructions use the PGDATA environment variable. See supplementary 
	content APPENDIX-F for instructions on configuring PGDATA.

As the database administrator (shown here as \"postgres\"), edit pg_hba.conf authentication file and change all 
entries of \"password\" to \"scram-sha-256\":

$ sudo su - postgres
$ vi ${PGDATA?}/pg_hba.conf
host all all .example.com scram-sha-256"
	impact 0.5
	tag severity: 'medium'
	tag gtitle: nil
	tag gid: nil
	tag rid: nil
	tag stig_id: nil
	tag fix_id: nil
	tag cci: nil
	tag nist: nil

	describe postgres_hba_conf(pg_hba_conf_file) do
		its('auth_method') { should_not include 'password' }
	  end
	end

