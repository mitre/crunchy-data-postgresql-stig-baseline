# encoding: UTF-8

control	'V-233537' do
	title	"PostgreSQL must by default shut down upon audit failure, to include the unavailability of space for 
	more audit log records; or must be configurable to shut down upon audit failure."
	desc	"It is critical that when PostgreSQL is at risk of failing to process audit logs as required, it take 
	action to mitigate the failure. Audit processing failures include software/hardware errors; failures in the 
	audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure 
	depend upon the nature of the failure mode. 

When the need for system availability does not outweigh the need for a complete audit trail, PostgreSQL should shut 
down immediately, rolling back all in-flight transactions.

Systems where audit trail completeness is paramount will most likely be at a lower MAC level than MAC I; the final 
determination being the prerogative of the application owner, subject to Authorizing Official concurrence. 
Sufficient auditing resources must be allocated to avoid a shutdown in all but the most extreme situations."
	desc	'rationale', ''
	desc	'check', "If the application owner has determined that the need for system availability outweighs the 
	need for a complete audit trail, this is not applicable (NA). 

Otherwise, review the procedures, manual and/or automated, for monitoring the space used by audit trail(s) and for 
off-loading audit records to a centralized log management system.

If the procedures do not exist, this is a finding.

If the procedures exist, request evidence that they are followed. If the evidence indicates that the procedures are 
not followed, this is a finding.

If the procedures exist, inquire if the system has ever run out of audit trail space in the last two years or since 
the last system upgrade, whichever is more recent. If it has run out of space in this period, and the procedures 
have not been updated to compensate, this is a finding."
	desc	'fix', "Modify DBMS, OS, or third-party logging application settings to alert appropriate personnel 
when a specific percentage of log storage capacity is reached."
	impact 0.5
	tag severity: 'medium'
	tag gtitle: nil
	tag gid: nil
	tag rid: nil
	tag stig_id: nil
	tag fix_id: nil
	tag cci: nil
	tag nist: nil

	describe "Check that PostgreSQL will shutdown upon audit failure." do
		skip "If PostgreSQL does not shut down upon audit failure or is not configurable to, this is a finding."
	  end
	end

