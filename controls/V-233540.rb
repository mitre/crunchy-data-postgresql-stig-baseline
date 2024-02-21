control 'V-233540' do
  title 'The PostgreSQL software installation account must be restricted to authorized users.'
  desc 'When dealing with change control issues, it should be noted any changes to the hardware, software,
	and/or firmware components of the information system and/or application can have significant effects on the
	overall security of the system.

If the system were to allow any user to make changes to software libraries, those changes might be implemented
without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals must be allowed access to information system components
for purposes of initiating changes, including upgrades and modifications.

DBA and other privileged administrative or application owner accounts are granted privileges that allow actions
that can have a great impact on database security and operation. It is especially important to grant privileged
access to only those persons who are qualified and authorized to use them.'
  desc 'check', 'Review procedures for controlling, granting access to, and tracking use of the PostgreSQL
	software installation account(s).

If access or use of this account is not restricted to the minimum number of personnel required or if unauthorized
access to the account has been granted, this is a finding.'
  desc 'fix', 'Develop, document, and implement procedures to restrict and track use of the PostgreSQL
	software installation account.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000133-DB-000198'
  tag gid: 'V-233540'
  tag rid: 'SV-233540r879586_rule'
  tag stig_id: 'CD12-00-003200'
  tag fix_id: 'F-36699r606844_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  if input('aws_rds')
    impact 0.0
    describe 'This control is not applicable on postgres within aws rds, as aws manages the operating system on which the postgres database is running' do
      skip 'This control is not applicable on postgres within aws rds, as aws manages the operating system on which the postgres database is running'
    end
  else	
	
	  describe 'Review procedures for controlling, granting access to, and tracking use of the PostgreSQL software installation account(s).' do
	    skip 'If account(s) are not restricted to the minimum personnel required or if unauthorized access to the account has been granted, this is a finding'
	  end
  end
end
