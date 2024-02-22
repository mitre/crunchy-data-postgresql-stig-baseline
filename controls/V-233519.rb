control 'V-233519' do
  title 'If passwords are used for authentication, PostgreSQL must transmit only encrypted representations of
  passwords.'
  desc "The #{input('org_name')[:acronym]} standard for authentication is #{input('org_name')[:acronym]}-approved PKI certificates.

  Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate,
  and requires Authorizing Official (AO) approval.

  In such cases, passwords need to be protected at all times, and encryption is the standard method for protecting
  passwords during transmission.

  PostgreSQL passwords sent in clear text format across the network are vulnerable to discovery by unauthorized users.
  Disclosure of passwords may easily lead to unauthorized access to the database."
  desc 'check', 'Note: The following instructions use the PGDATA environment variable. See supplementary
	content APPENDIX-F for instructions on configuring PGDATA.

  As the database administrator (shown here as "postgres"), review the authentication entries in pg_hba.conf:

  $ sudo su - postgres
  $ cat ${PGDATA?}/pg_hba.conf

  If any entries use the auth_method (last column in records) "password" or "md5", this is a finding.'
  desc 'fix', 'Note: The following instructions use the PGDATA environment variable. See supplementary
	content APPENDIX-F for instructions on configuring PGDATA.

  As the database administrator (shown here as "postgres"), edit pg_hba.conf authentication file and change all
  entries of "password" to "scram-sha-256":

  $ sudo su - postgres
  $ vi ${PGDATA?}/pg_hba.conf
  host all all .example.com scram-sha-256'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000172-DB-000075'
  tag gid: 'V-233519'
  tag rid: 'SV-233519r836817_rule'
  tag stig_id: 'CD12-00-000800'
  tag fix_id: 'F-36678r606781_fix'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']

  if input('aws_rds')
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system on which the postgres database is running' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system on which the postgres database is running'
    end
  else	
	
	  describe postgres_hba_conf("#{input('pg_hba_conf_file')}") do
	    its('auth_method') { should_not include 'password' }
	    its('auth_method') { should_not include 'md5' }
	  end
		
  end
end
