control 'V-233585' do
  title 'PostgreSQL must implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to protect unclassified information requiring confidentiality and cryptographic protection, in accordance with the data owner’s requirements.'
  desc "Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

It is the responsibility of the data owner to assess the cryptography requirements in light of applicable federal laws, Executive Orders, directives, policies, regulations, and standards.

For detailed information, refer to NIST FIPS Publication 140-2 or Publication 140-3, Security Requirements For Cryptographic Modules. Note that the product's cryptographic modules must be validated and certified by NIST as FIPS-compliant."
  desc 'check', 'First, as the system administrator, run the following to see if FIPS is enabled:

$ cat /proc/sys/crypto/fips_enabled

If fips_enabled is not "1", this is a finding.'
  desc 'fix', 'If fips_enabled = 0, configure OpenSSL to be FIPS compliant.

Configure per operating system documentation:
RedHat: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-federal_standards_and_regulations
Ubuntu: https://security-certs.docs.ubuntu.com/en/fips

For information on configuring PostgreSQL to use SSL, see supplementary content APPENDIX-G.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000514-DB-000383'
  tag gid: 'V-233585'
  tag rid: 'SV-233585r836824_rule'
  tag stig_id: 'CD12-00-008200'
  tag fix_id: 'F-36744r836823_fix'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13', 'SC-13 b']

  if input('aws_rds')
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system on which the postgres database is running' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system on which the postgres database is running'
    end
  else	  
    describe kernel_parameter('crypto.fips_enabled') do
      its('value') { should cmp 1 }
    end
  end
end
