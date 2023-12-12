control	'V-233536' do
  title	"PostgreSQL must be configurable to overwrite audit log records, oldest first (First-In-First-Out [FIFO]),
	in the event of unavailability of space for more audit log records."
  desc	"It is critical that when PostgreSQL is at risk of failing to process audit logs as required, it take
	action to mitigate the failure. Audit processing failures include software/hardware errors; failures in the
	audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure
	depend upon the nature of the failure mode.

When availability is an overriding concern, approved actions in response to an audit failure are as follows:

(i) If the failure was caused by the lack of audit record storage capacity, PostgreSQL must continue generating
audit records, and if possible (automatically restarting the audit service if necessary), overwriting the oldest
audit records in a first-in-first-out manner.
(ii) If audit records are sent to a centralized collection server and communication with this server is lost or
the server fails, PostgreSQL must queue audit records locally until communication is restored or until the audit
records are retrieved manually. Upon restoration of the connection to the centralized collection server, action
should be taken to synchronize the local audit data with the collection server.

Systems where availability is paramount will most likely be MAC I; the final determination is the prerogative of
the application owner, subject to Authorizing Official concurrence. Sufficient auditing resources must be allocated
to avoid audit data loss in all but the most extreme situations."
  desc	'rationale', ''
  desc	'check', "If the AO approved system documentation states that system availability takes precedence, this
	requirement is not applicable (NA).

If an externally managed and monitored partition or logical volume that can be grown dynamically is being used for
logging, this is not a finding.

If PostgreSQL is auditing to a directory that is not being actively checked for availability of disk space, and if
a tool, utility, script, or other mechanism is not being used to ensure sufficient disk space is available for the
creation of new audit logs, this is a finding.

If a tool, utility, script, or other mechanism is being used to rotate audit logs, and oldest logs are not being
removed to ensure sufficient space for newest logs, or oldest logs are not being replaced by newest logs, this is a
finding."
  desc	'fix', "Establish a process with accompanying tools for monitoring available disk space and ensuring
	that sufficient disk space is maintained in order to continue generating audit logs, overwriting the oldest
	existing records if necessary."
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000109-DB-000321'
  tag gid: 'V-233536'
  tag rid: 'SV-233536r617333_rule'
  tag stig_id: 'CD12-00-002800'
  tag fix_id: 'F-36695r606832_fix'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']

  describe 'Check that audit logs are overwritten in a FIFO manner.' do
    skip 'If audit logs are not overwritten in a FIFO manner, this is a finding.'
  end
end
