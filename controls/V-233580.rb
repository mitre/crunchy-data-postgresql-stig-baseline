# encoding: UTF-8

control	'V-233580' do
	title	"PostgreSQL must be configured to provide audit record generation for #{input('org_name')[:acronym]}-defined auditable events 
	within all DBMS/database components."
	desc	"Without the capability to generate audit records, it would be difficult to establish, correlate, and 
	investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within PostgreSQL (e.g., process, module). Certain specific 
application functionalities may be audited as well. The list of audited events is the set of events for which audits 
are to be generated. This set of events is typically a subset of the list of all events for which the system is 
capable of generating audit records.

#{input('org_name')[:acronym]} has defined the list of events for which PostgreSQL will provide an audit record generation capability as the 
following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, 
or categories of information (e.g., classification levels);
(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities, or other 
system-level access, starting and ending time for user access to the system, concurrent logons from different 
workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the 
information system; and
(iii) All account creation, modification, disabling, and termination actions.

Organizations may define additional events requiring continuous or ad hoc auditing."
	desc	'rationale', ''
	desc	'check', "Note: The following instructions use the PGLOG environment variables. See supplementary 
	content APPENDIX-I for instructions on configuring PGVER.

Check PostgreSQL audit logs to determine whether organization-defined auditable events are being audited by the system.

For example, if the organization defines 'CREATE TABLE' as an auditable event, issuing the following command should 
return a result:

$ sudo su - postgres
$ psql -c \"CREATE TABLE example (id int)\"
$ grep 'AUDIT:.*,CREATE TABLE.*example' ${PGLOG?}/<latest_log>
$ psql -c 'DROP TABLE example;'

If organization-defined auditable events are not being audited, this is a finding."
	desc	'fix', "Configure PostgreSQL to generate audit records for at least the #{input('org_name')[:acronym]} minimum set of events.

Using \"pgaudit\", PostgreSQL can be configured to audit these requests. See supplementary content APPENDIX-B for 
documentation on installing pgaudit.

To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging."
	impact 0.5
	tag severity: 'medium'
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag gid: 'V-233580'
  tag rid: 'SV-233580r617333_rule'
  tag stig_id: 'CD12-00-007400'
  tag fix_id: 'F-36739r606964_fix'
  tag cci: ["CCI-000169"]
  tag nist: ["AU-12 a"]

	describe "Check PostgreSQL auditing to determine whether organization-defined auditable events are being audited by the system" do
		skip "If organization-defined auditable events are not being audited, this is a finding."
	  end
	end

