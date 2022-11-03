# encoding: UTF-8

control	'V-233615' do
	title	"PostgreSQL must map the PKI-authenticated identity to an associated user account."
	desc	"The #{input('org_name')[:acronym]} standard for authentication is #{input('org_name')[:acronym]}-approved PKI certificates. Once a PKI certificate has been 
	validated, it must be mapped to PostgreSQL user account for the authenticated identity to be meaningful to 
	PostgreSQL and useful for authorization decisions."
	desc	'rationale', ''
	desc	'check', "The Common Name (cn) attribute of the certificate will be compared to the requested database 
	user name and, if they match, the login will be allowed. 

To check the cn of the certificate, using openssl, do the following:

$ openssl x509 -noout -subject -in client_cert

If the cn does not match the users listed in PostgreSQL and no user mapping is used, this is a finding.

User name mapping can be used to allow cn to be different from the database user name. If User Name Maps are used, 
run the following as the database administrator (shown here as \"postgres\"), to get a list of maps used for 
authentication:

$ sudo su - postgres
$ grep \"map\" ${PGDATA?}/pg_hba.conf

With the names of the maps used, check those maps against the user name mappings in pg_ident.conf:

$ sudo su - postgres
$ cat ${PGDATA?}/pg_ident.conf

If user accounts are not being mapped to authenticated identities, this is a finding.

If the cn and the username mapping do not match, this is a finding."
	desc	'fix', "Configure PostgreSQL to map authenticated identities directly to PostgreSQL user accounts.

For information on configuring PostgreSQL to use SSL, see supplementary content APPENDIX-G."
	impact 0.5
	tag severity: 'medium'
  tag gtitle: 'SRG-APP-000177-DB-000069'
  tag gid: 'V-233615'
  tag rid: 'SV-233615r617333_rule'
  tag stig_id: 'CD12-00-011800'
  tag fix_id: 'F-36774r607069_fix'
  tag cci: ["CCI-000187"]
  tag nist: ["IA-5 (2) (c)"]

	describe "The cn  attribute of the certificate will be compared to the requested database user name, and if they match the login will be allowed." do
		skip "If the cn and the username mapping do not match, this is a finding."
		skip "If the cn does not match the users listed in PostgreSQL and no user mapping is used, this is a finding."
	  end
	end

