control 'V-233535' do
  title 'PostgreSQL must provide an immediate alert to appropriate support staff of all audit log failures.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process
	audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of
	the audit capability, and system operation may be adversely affected.

The appropriate support staff include, at a minimum, the Information System Security Officer (ISSO) and the database
administrator (DBA)/systems administrator (SA).

A failure of database auditing will result in either the database continuing to function without auditing or in a
complete halt to database operations. When audit processing fails, appropriate personnel must be alerted immediately
to avoid further downtime or unaudited transactions.

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the
	time from event detection to alert occurs in seconds or less).

The necessary monitoring and alerts may be implemented using features of PostgreSQL, the OS, third-party software,
custom code, or a combination of these. The term "the system" is used to encompass all of these.'
  desc 'check', 'Review DBMS, OS, or third-party logging software settings to determine whether a real-time
	alert will be sent to the appropriate personnel when auditing fails for any reason.

If real-time alerts are not sent upon auditing failure, this is a finding.'
  desc 'fix', 'Configure the system to provide an immediate real-time alert to appropriate support staff when
	an audit log failure occurs.

It is possible to create scripts or implement third-party tools to enable real-time alerting for audit failures in
PostgreSQL.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000360-DB-000320'
  tag gid: 'V-233535'
  tag rid: 'SV-233535r622558_rule'
  tag stig_id: 'CD12-00-002700'
  tag fix_id: 'F-36694r606829_fix'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']

    describe 'A manual review is required to ensure PostgreSQL provides an immediate real-time alert to appropriate
      support staff of all audit failure events requiring real-time alerts' do
      skip 'A manual review is required to ensure PostgreSQL provides an immediate real-time alert to appropriate
      support staff of all audit failure events requiring real-time alerts'
    end
end
