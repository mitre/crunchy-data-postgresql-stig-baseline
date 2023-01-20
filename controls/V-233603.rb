# encoding: UTF-8

control	'V-233603' do
	title	"PostgreSQL must only accept end entity certificates issued by #{input('org_name')[:acronym]} PKI or #{input('org_name')[:acronym]}-approved PKI 
	Certification Authorities (CAs) for the establishment of all encrypted sessions."
	desc	"Only #{input('org_name')[:acronym]}-approved external PKIs have been evaluated to ensure security controls and identity vetting 
	procedures are in place that are sufficient for #{input('org_name')[:acronym]} systems to rely on the identity asserted in the certificate. 
	PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing 
	certificates that enable adversaries to impersonate legitimate users. 

The authoritative list of #{input('org_name')[:acronym]}-approved PKIs is published at https://cyber.mil/pki-pke/interoperability

This requirement focuses on communications protection for PostgreSQL session rather than for the network packet."
	desc	'rationale', ''
	desc	'check', "As the database administrator (shown here as \"postgres\"), verify the following setting in 
	postgresql.conf:

$ sudo su - postgres
$ psql -c \"SHOW ssl_ca_file\"
$ psql -c \"SHOW ssl_cert_file\"

If the database is not configured to use only #{input('org_name')[:acronym]}-approved certificates, this is a finding."
	desc	'fix', "Revoke trust in any certificates not issued by a #{input('org_name')[:acronym]}-approved certificate authority.

Configure PostgreSQL to accept only #{input('org_name')[:acronym]} and #{input('org_name')[:acronym]}-approved PKI end-entity certificates.

To configure PostgreSQL to accept approved CAs, see the official PostgreSQL documentation: 
http://www.postgresql.org/docs/current/static/ssl-tcp.html

For more information on configuring PostgreSQL to use SSL, see supplementary content APPENDIX-G."
	impact 0.5
	tag severity: 'medium'
  tag gtitle: 'SRG-APP-000427-DB-000385'
  tag gid: 'V-233603'
  tag rid: 'SV-233603r617340_rule'
  tag stig_id: 'CD12-00-010300'
  tag fix_id: 'F-36762r607033_fix'
  tag cci: ["CCI-002470"]
  tag nist: ["SC-23 (5)"]

	sql = postgres_session(input('pg_dba'), input('pg_dba_password'), input('pg_host'), input('pg_port'))

	describe sql.query('SHOW ssl_ca_file;', [input('pg_db')]) do
	  its('output') { should_not eq '' }
	end
  
	describe sql.query('SHOW ssl_cert_file;', [input('pg_db')]) do
	  its('output') { should_not eq '' }
	end
  end

