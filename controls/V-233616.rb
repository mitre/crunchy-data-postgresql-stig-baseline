# encoding: UTF-8

control	'V-233616' do
	title	"Database contents must be protected from unauthorized and unintended information transfer by enforcement 
	of a data-transfer policy."
	desc	"Applications, including PostgreSQL, must prevent unauthorized and unintended information transfer via 
	shared system resources.

Data used for the development and testing of applications often involves copying data from production. It is 
important that specific procedures exist for this process, to include the conditions under which such transfer may 
take place, where the copies may reside, and the rules for ensuring sensitive data are not exposed.

Copies of sensitive data must not be misplaced or left in a temporary location without the proper controls."
	desc	'rationale', ''
	desc	'check', "Review the procedures for the refreshing of development/test data from production.

Review any scripts or code that exists for the movement of production data to development/test systems, or to any 
other location or for any other purpose.

Verify that copies of production data are not left in unprotected locations. 

If the code that exists for data movement does not comply with the organization-defined data transfer policy and/or 
fails to remove any copies of production data from unprotected locations, this is a finding."
	desc	'fix', "Modify any code used for moving data from production to development/test systems to comply with 
	the organization-defined data transfer policy, and to ensure copies of production data are not left in unsecured 
	locations."
	impact 0.5
	tag severity: 'medium'
	tag gtitle: nil
	tag gid: nil
	tag rid: nil
	tag stig_id: nil
	tag fix_id: nil
	tag cci: nil
	tag nist: nil

	describe "Review the procedures for the refreshing of development/test data from production." do
		skip "If code for data movement does not comply with the organization-defined data transfer policy and/or fails to remove any copies of production data from unprotected locations, this is a finding."
	  end
	end

