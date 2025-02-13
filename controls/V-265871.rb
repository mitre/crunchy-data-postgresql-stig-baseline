control 'V-265871' do
  title 'PostgreSQL products must be a version supported by the vendor.'
  desc 'Unsupported commercial and database systems should not be used because fixes to newly identified bugs will not be implemented by the vendor. The lack of support can result in potential vulnerabilities.

Systems at unsupported servicing levels or releases will not receive security updates for new vulnerabilities, which leaves them subject to exploitation.

When maintenance updates and patches are no longer available, the database software is no longer considered supported and should be upgraded or decommissioned.'
  desc 'check', 'If new packages are available for PostgreSQL, they can be reviewed in the package manager appropriate for the server operating system:

To list the version of installed PostgreSQL using psql:

$ sudo su - postgres
$ psql --version

To list the current version of software for RPM:

$ rpm -qa | grep postgres

To list the current version of software for APT:

$ apt-cache policy postgres

All versions of PostgreSQL will be listed here:
http://www.postgresql.org/support/versioning/

All security-relevant software updates for PostgreSQL will be listed here:
http://www.postgresql.org/support/security/

If PostgreSQL is not at the latest version, this is a finding.'
  desc 'fix', 'Remove or decommission all unsupported software products.

Upgrade unsupported DBMS or unsupported components to a supported version of the product.'
  impact 0.7
  tag check_id: 'C-69790r999517_chk'
  tag severity: 'high'
  tag gid: 'V-265871'
  tag rid: 'SV-265871r999519_rule'
  tag stig_id: 'CD12-00-012900'
  tag gtitle: 'SRG-APP-000456-DB-000400'
  tag fix_id: 'F-69694r999518_fix'
  tag 'documentable'
  tag cci: ['CCI-003376']
  tag nist: ['SA-22 a']

  min_org_allowed_postgres_version = input('min_org_allowed_postgres_version')
  installed_postgres_version = command('psql --version').stdout.split[2]

  # If no organization specified postgres version was given, check the internet for major and minor release versions
  if (min_org_allowed_postgres_version.nil? || min_org_allowed_postgres_version.empty?)
    describe "Your installed Postgres version is: #{installed_postgres_version}. You must review this control manually or set / pass the 'min_org_allowed_postgres_version' to the profile. The latest supported releases can be found at http://www.postgresql.org/support/versioning/" do
      skip "Your installed Postgres version is: #{installed_postgres_version}. You must review this control manually or set / pass the 'min_org_allowed_postgres_version' to the profile. The latest supported releases can be found at http://www.postgresql.org/support/versioning/"
    end
  else
    describe 'PostgreSQL installed version' do
      subject { installed_postgres_version }
      it { should cmp >= min_org_allowed_postgres_version }
    end
  end
end
