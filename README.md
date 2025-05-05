# Crunchy Data PostgreSQL Security Technical Implementation Guide
This InSpec Profile was created to facilitate testing and auditing of `Crunchy Data PostgreSQL`
infrastructure and applications when validating compliancy with [Department of Defense (DoD) STIG](https://public.cyber.mil/stigs/)
requirements.

- Profile Version: **3.1.0**
- Benchmark Date: **24 Jul 2024**
- Benchmark Version: **Version 3 Release 1 (V3R1)**

> [!Note]
> This Profile applies to database versions 10, 11, 12, 13, 14, 15

This profile was developed to reduce the time it takes to perform a security checks based upon the
STIG Guidance from the Defense Information Systems Agency (DISA) in partnership between the DISA Services Directorate (SD) and the DISA Risk Management Executive (RME) office.

The results of a profile run will provide information needed to support an Authority to Operate (ATO)
decision for the applicable technology.

The Crunchy Data PostgreSQL STIG Profile uses the [InSpec](https://github.com/inspec/inspec)
open-source compliance validation language to support automation of the required compliance, security
and policy testing for Assessment and Authorization (A&A) and Authority to Operate (ATO) decisions
and Continuous Authority to Operate (cATO) processes.

Table of Contents
=================
* [STIG Benchmark  Information](#benchmark-information)
* [Getting Started](#getting-started)
    * [Intended Usage](#intended-usage)
    * [Tailoring to Your Environment](#tailoring-to-your-environment)
    * [Testing the Profile Controls](#testing-the-profile-controls)
* [Running the Profile](#running-the-profile)
    * [Directly from Github](#directly-from-github) 
    * [Using a local Archive copy](#using-a-local-archive-copy)
    * [Different Run Options](#different-run-options)
* [Using Heimdall for Viewing Test Results](#using-heimdall-for-viewing-test-results)

## Benchmark Information
The DISA RME and DISA SD Office, along with their vendor partners, create and maintain a set of Security Technical Implementation Guides for applications, computer systems and networks
connected to the Department of Defense (DoD). These guidelines are the primary security standards
used by the DoD agencies. In addition to defining security guidelines, the STIGs also stipulate
how security training should proceed and when security checks should occur. Organizations must
stay compliant with these guidelines or they risk having their access to the DoD terminated.

Requirements associated with the Crunchy Data PostgreSQL STIG are derived from the
[Security Requirements Guides](https://csrc.nist.gov/glossary/term/security_requirements_guide)
and align to the [National Institute of Standards and Technology](https://www.nist.gov/) (NIST)
[Special Publication (SP) 800-53](https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/800-53)
Security Controls, [DoD Control Correlation Identifier](https://public.cyber.mil/stigs/cci/) and related standards.

The Crunchy Data PostgreSQL STIG profile checks were developed to provide technical implementation
validation to the defined DoD requirements, the guidance can provide insight for any organizations wishing
to enhance their security posture and can be tailored easily for use in your organization.

[top](#table-of-contents)
## Getting Started  
### InSpec (CINC-auditor) setup
For maximum flexibility/accessibility `cinc-auditor`, the open-source packaged binary version of Chef InSpec should be used,
compiled by the CINC (CINC Is Not Chef) project in coordination with Chef using Chef's always-open-source InSpec source code.
For more information see [CINC Home](https://cinc.sh/)

It is intended and recommended that CINC-auditor and this profile executed from a __"runner"__ host
(such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop)
against the target. This can be any Unix/Linux/MacOS or Windows runner host, with access to the Internet.

> [!TIP]
> **For the best security of the runner, always install on the runner the latest version of CINC-auditor and any other supporting language components.**

To install CINC-auditor on a UNIX/Linux/MacOS platform use the following command:
```bash
curl -L https://omnitruck.cinc.sh/install.sh | sudo bash -s -- -P cinc-auditor
```

To install CINC-auditor on a Windows platform (Powershell) use the following command:
```powershell
. { iwr -useb https://omnitruck.cinc.sh/install.ps1 } | iex; install -project cinc-auditor
```

To confirm successful install of cinc-auditor:
```
cinc-auditor -v
```

Latest versions and other installation options are available at [CINC Auditor](https://cinc.sh/start/auditor/) site.

[top](#table-of-contents)
### Intended Usage
1. The latest `released` version of the profile is intended for use in A&A testing, as well as
    providing formal results to Authorizing Officials and Identity and Access Management (IAM)s.
    Please use the `released` versions of the profile in these types of workflows. 

2. The `main` branch is a development branch that will become the next release of the profile.
    The `main` branch is intended for use in _developing and testing_ merge requests for the next
    release of the profile, and _is not intended_ be used for formal and ongoing testing on systems.

[top](#table-of-contents)
### Tailoring to Your Environment
This profile uses InSpec Inputs to provide flexibility during testing. Inputs allow for
customizing the behavior of Chef InSpec profiles.

InSpec Inputs are defined in the `inspec.yml` file. The `inputs` configured in this
file are **profile definitions and defaults for the profile** extracted from the profile
guidances and contain metadata that describe the profile, and shouldn't be modified.

InSpec provides several methods for customizing profile behaviors at run-time that does not require
modifying the `inspec.yml` file itself (see [Using Customized Inputs](#using-customized-inputs)).

The following inputs are permitted to be configured in an inputs `.yml` file (often named inputs.yml)
for the profile to run correctly on a specific environment, while still complying with the security
guidance document intent. This is important to prevent confusion when test results are passed downstream
to different stakeholders under the *security guidance name used by this profile repository*

For changes beyond the inputs cited in this section, users can create an *organizationally-named overlay repository*.
For more information on developing overlays, reference the [MITRE SAF Training](https://mitre-saf-training.netlify.app/courses/beginner/10.html)

#### Example Inputs You Can Use

```yaml
# Changes checks depending on if using a Windows or Linux-based InSpec Runner (default value = false)
windows_runner: false

# These five inputs are used by any tests needing to query the database:
# Description: 'Postgres database admin user (e.g., 'postgres').'
pg_dba: 'postgres'

# Description: 'Postgres database admin password.'
pg_dba_password: ''

# Description: 'Postgres database hostname'
pg_host: ''

# Description: 'Postgres database name (e.g., 'postgres')'
pg_db: 'postgres'

# Description: 'Postgres database port (e.g., '5432')
pg_port: '5432'

# Description: 'Postgres OS user (e.g., 'postgres').'
pg_owner: 'postgres'

# Description: 'Postgres OS group (e.g., 'postgres').'
pg_group: 'postgres'

# Description: 'Database version'
# Change "12.x" to your version (This STIG applies to versions 10.x, 11.x, 12.x, and 13.x)
pg_version: '12.9'

# Description: 'Data directory for database'
# e.g., Default for version 12: '/var/lib/pgsql/12/data'
pg_data_dir: ''

# Description: 'Configuration file for the database' 
# e.g., Default for version 12: '/var/lib/pgsql/12/data/postgresql.conf'
pg_conf_file: ''

# Description: 'User defined configuration file for the database'
# e.g., Default for version 12: '/var/lib/pgsql/12/data/stig-postgresql.conf'
pg_user_defined_conf: ''

# Description: 'Configuration file to enable client authentication'
# e.g., Default for version 12: '/var/lib/pgsql/12/data/pg_hba.conf'
pg_hba_conf_file: ''

# Description: 'Configuration file that maps operating system usernames and database usernames'
# e.g., Default for version 12: '/var/lib/pgsql/12/data/pg_ident.conf'
pg_ident_conf_file: ''

# Description: 'V-233517 uses this input to check permissions of shared directories'
# e.g., Default for version 12: ['/usr/pgsql-12', '/usr/pgsql-12/bin', '/usr/pgsql-12/include', '/usr/pgsql-12/lib', '/usr/pgsql-12/share']
# Change "12" to your version (This STIG applies to versions 10, 11, 12, and 13)
pg_shared_dirs: ['/usr/pgsql-12', '/usr/pgsql-12/bin', '/usr/pgsql-12/include', '/usr/pgsql-12/lib', '/usr/pgsql-12/share']

# Description: 'V-233514, V-233533, V-233607 use this input for the location of the postgres log files on the system'
# e.g., Default for version 12: '/var/lib/pgsql/12/data/log'
# Change "12" to your version (This STIG applies to versions 10, 11, 12, and 13)
pg_log_dir: '/var/lib/pgsql/12/data/log'

# Description: 'V-233544, V-233547, V-233549, V-233552, V-233553, V-233554, V-233555, V-233556, V-233558, V-233559, V-233560, V-233561, V-233562, V-233564, V-233572, V-233575, V-233576 use this input for the location of the postgres audit log files on the system'
# e.g., Default for version 12: '/var/lib/pgsql/12/data/log'
# Change "12" to your version (This STIG applies to versions 10, 11, 12, and 13)
pg_audit_log_dir: '/var/lib/pgsql/12/data/log'

# Description: 'V-233607 uses this input for the location of the pgaudit installation directory on the system'
# e.g., Default for version 12: '/usr/pgsql-12/share/contrib/pgaudit'
# Change "12" to your version (This STIG applies to versions 10, 11, 12, and 13)
pgaudit_installation: '/usr/pgsql-12/share/contrib/pgaudit'

# Description: 'Postgres super users (e.g., ['postgres']).'
pg_superusers: ['postgres']

# Description: 'Postgres users'
pg_users: []

# Description: 'V-233520, V-233612 use this list of Postgres replicas from pg_hba.conf settings (e.g. ['127.0.0.1/32']).'
pg_replicas: []

# Description: 'Postgres max number of connections allowed (e.g., 100).'
pg_max_connections: 100

# Description: 'Postgres timezone (e.g., 'UTC').'
pg_timezone: 'UTC'

# Description: 'V-233515, V-233520, V-233612 use this list of approved authentication methods (e.g., per STIG: ['gss', 'sspi', 'ldap'] ).'
approved_auth_methods: []

# Description: 'V-233594 uses this list of approved postgres-related packages (e.g., postgresql-server.x86_64, postgresql-odbc.x86_64).'
approved_packages: []

# Description: 'V-233592, V-233593 use this list of approved database extensions (e.g., ['plpgsql']).'
approved_ext: []

# Description: 'Privileges that should be granted to a role for a database object (e.g., arwdDxt).'
pg_object_granted_privileges:

# Description: 'Privileges that should be granted to public for a database object (e.g. 'rw')'
pg_object_public_privileges: 

# Description: 'List of database objects that should be returned from tests'
pg_object_exceptions: ['pg_setting']

# Description: 'The minimum Postgres version allowed by the organization'
min_org_allowed_postgres_version: '16.2'

```


> [!NOTE]
>Inputs are variables that are referenced by control(s) in the profile that implement them.
 They are declared (defined) and given a default value in the `inspec.yml` file. 

#### Using Customized Inputs
Customized inputs may be used at the CLI by providing an input file or a flag at execution time.

1. Using the `--input` flag
  
    Example: `[inspec or cinc-auditor] exec <my-profile.tar.gz> --input disable_slow_controls=true`

2. Using the `--input-file` flag.
    
    Example: `[inspec or cinc-auditor] exec <my-profile.tar.gz> --input-file=<my_inputs_file.yml>`

>[!TIP]
> For additional information about `input` file examples reference the [MITRE SAF Training](https://mitre.github.io/saf-training/courses/beginner/06.html#input-file-example)

Chef InSpec Resources:
- [InSpec Profile Documentation](https://docs.chef.io/inspec/profiles/).
- [InSpec Inputs](https://docs.chef.io/inspec/profiles/inputs/).
- [inspec.yml](https://docs.chef.io/inspec/profiles/inspec_yml/).


[top](#table-of-contents)
### Testing the Profile Controls
The Gemfile provided contains all the necessary ruby dependencies for checking the profile controls.
#### Requirements
All action are conducted using `ruby` (gemstone/programming language). Currently `inspec` 
commands have been tested with ruby version 3.1.2. A higher version of ruby is not guaranteed to
provide the expected results. Any modern distribution of Ruby comes with Bundler preinstalled by default.

Install ruby based on the OS being used, see [Installing Ruby](https://www.ruby-lang.org/en/documentation/installation/)

After installing `ruby` install the necessary dependencies by invoking the bundler command
(must be in the same directory where the Gemfile is located):
```bash
bundle install
```

[top](#table-of-contents)

#### Testing against a Local Postgres Container
As a developer or someone wanting to test the profile without an existing database target, there are files available to start up a docker container with a test PostgreSQL 2016 database instance. Starting this requires the runner to have InSpec or CINC Auditor installed, psql, and docker.
To pull the container image, run:
```bash
docker pull
```

To start the container, run:
```bash
docker compose up -D
```

To run the InSpec profile against the test database, run:
```bash
inspec exec ./ --input-file ./inputs_postgres16_example.yml --reporter cli json:./results/file.json
```

#### Testing Commands

Linting and validating controls:
```bash
  bundle exec rake [inspec or cinc-auditor]:check # Validate the InSpec Profile
  bundle exec rake lint                           # Run RuboCop Linter
  bundle exec rake lint:auto_correct              # Autocorrect RuboCop offenses (only when it's safe)
  bundle exec rake pre_commit_checks              # Pre-commit checks
```

Ensure the controls are ready to be committed into the repo:
```bash
  bundle exec rake pre_commit_checks
```


[top](#table-of-contents)
## Running the Profile
### Directly from Github
This option is best used when network connectivity is available and policies permit
access to the hosting repository.

```bash
# Using `ssh` transport
bundle exec [inspec or cinc-auditor] exec https://github.com/mitre/crunchy-data-postgresql-stig-baseline/archive/main.tar.gz --input-file=<your_inputs_file.yml> -t ssh://<hostname>:<port> --sudo --reporter=cli json:<your_results_file.json>

# Using `winrm` transport
bundle exec [inspec or cinc-auditor] exec https://github.com/mitre/crunchy-data-postgresql-stig-baseline/archive/master.tar.gz --target winrm://<hostip> --user '<admin-account>' --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

[top](#table-of-contents)
### Using a local Archive copy
If your runner is not always expected to have direct access to the profile's hosted location,
use the following steps to create an archive bundle of this overlay and all of its dependent tests:

Git is required to clone the InSpec profile using the instructions below.
Git can be downloaded from the [Git Web Site](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git).

When the **"runner"** host uses this profile overlay for the first time, follow these steps:

```bash
mkdir profiles
cd profiles
git clone https://github.com/mitre/crunchy-data-postgresql-stig-baseline.git
bundle exec [inspec or cinc-auditor] archive crunchy-data-postgresql-stig-baseline

# Using `ssh` transport
bundle exec [inspec or cinc-auditor] exec <name of generated archive> --input-file=<your_inputs_file.yml> -t ssh://<hostname>:<port> --sudo --reporter=cli json:<your_results_file.json>

# Using `winrm` transport
bundle exec [inspec or cinc-auditor] exec <name of generated archive> --target winrm://<hostip> --user '<admin-account>' --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>    
```

For every successive run, follow these steps to always have the latest version of this profile baseline:

```bash
cd crunchy-data-postgresql-stig-baseline
git pull
cd ..
bundle exec [inspec or cinc-auditor] archive crunchy-data-postgresql-stig-baseline --overwrite

# Using `ssh` transport
bundle exec [inspec or cinc-auditor] exec <name of generated archive> --input-file=<your_inputs_file.yml> -t ssh://<hostname>:<port> --sudo --reporter=cli json:<your_results_file.json>

# Using `winrm` transport
bundle exec [inspec or cinc-auditor] exec <name of generated archive> --target winrm://<hostip> --user '<admin-account>' --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>    
```

[top](#table-of-contents)
## Different Run Options

[Full exec options](https://docs.chef.io/inspec/cli/#options-3)

[top](#table-of-contents)
## Using Heimdall for Viewing Test Results
The JSON results output file can be loaded into **[Heimdall-Lite](https://heimdall-lite.mitre.org/)**
or **[Heimdall-Server](https://github.com/mitre/heimdall2)** for a user-interactive, graphical view of the profile scan results.

Heimdall-Lite is a `browser only` viewer that allows you to easily view your results directly and locally rendered in your browser.
Heimdall-Server is configured with a `data-services backend` allowing for data persistency to a database (PostgreSQL).
For more detail on feature capabilities see [Heimdall Features](https://github.com/mitre/heimdall2?tab=readme-ov-file#features)

Heimdall can **_export your results into a DISA Checklist (CKL) file_** for easily uploading into eMass using the `Heimdall Export` function.

Depending on your environment restrictions, the [SAF CLI](https://saf-cli.mitre.org) can be used to run a local docker instance
of Heimdall-Lite via the `saf view:heimdall` command.

Additionally both Heimdall applications can be deployed via docker, kubernetes, or the installation packages.

[top](#table-of-contents)
## Authors
[Defense Information Systems Agency (DISA)](https://www.disa.mil/)

[STIG support by DISA Risk Management Team and Cyber Exchange](https://public.cyber.mil/)

[MITRE Security Automation Framework Team](https://saf.mitre.org)

## NOTICE

© 2018-2025 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

## NOTICE 

MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

## NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.

## NOTICE
[DISA STIGs are published by DISA IASE](https://public.cyber.mil/stigs/)
