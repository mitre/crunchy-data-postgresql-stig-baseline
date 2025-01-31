# crunchy-data-postgresql-stig-baseline

InSpec profile to validate the secure configuration of Crunchy Data PostgreSQL against [DISA's](https://public.cyber.mil/stigs/downloads/) Crunchy Data PostgreSQL Security Technical Implementation Guide (STIG) Version 3, Release 1. (Applies to database versions 10, 11, 12, 13, 14, 15)

#### Container-Ready: Profile updated to adapt checks when the running against a containerized instance of PostgreSQL

## Getting Started

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

Latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

## Inputs: Tailoring your scan to Your Environment

The following inputs must be configured in an inputs ".yml" file for the profile to run correctly for your specific environment. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

#### *Note* Windows and Linux InSpec Runner

There are current issues with how the profiles run when using a windows or linux runner. We have accounted for this in the profile with the `windows_runner` input - which we *default* to `false` assuming a Linux based InSpec runner.

If you are using a *Windows* based inspec installation, please set the `windows_runner` input to `true` either via your `inspec.yml` file or via the cli flag via, `--input windows_runner=true`

### Example Inputs You Can Use

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

## Running This Overlay Directly from Github

Against a remote target using ssh as the *postgres* user (i.e., InSpec installed on a separate runner host)
```bash
inspec exec https://github.com/mitre/crunchy-data-postgresql-stig-baseline/archive/main.tar.gz -t ssh://postgres:TARGET_PASSWORD@TARGET_IP:TARGET_PORT --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json> 
```

Against a remote target using a pem key as the *postgres* user (i.e., InSpec installed on a separate runner host)
```bash
inspec exec https://github.com/mitre/crunchy-data-postgresql-stig-baseline/archive/main.tar.gz -t ssh://postgres@TARGET_IP:TARGET_PORT -i <postgres_PEM_KEY> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>  
```

Against a _**locally-hosted**_ instance logged in as the *postgres* user (i.e., InSpec installed on the target hosting the postgresql database)

```bash
inspec exec https://github.com/mitre/crunchy-data-postgresql-stig-baseline/archive/main.tar.gz --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

Against a _**docker-containerized**_ instance (i.e., InSpec installed on the node hosting the postgresql container):
```
inspec exec https://github.com/mitre/crunchy-data-postgresql-stig-baseliney/archive/main.tar.gz -t docker://<instance_id> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

### Different Run Options

  [Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## Running This Overlay from a local Archive copy 

If your runner is not always expected to have direct access to GitHub, use the following steps to create an archive bundle of this overlay and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.)

When the __"runner"__ host uses this profile overlay for the first time, follow these steps: 

```
mkdir profiles
cd profiles
git clone https://github.com/mitre/crunchy-data-postgresql-stig-baseline.git
inspec archive crunchy-data-postgresql-stig-baseline
inspec exec <name of generated archive> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

For every successive run, follow these steps to always have the latest version of this overlay and dependent profiles:

```
cd crunchy-data-postgresql-stig-baseline
git pull
cd ..
inspec archive crunchy-data-postgresql-stig-baseline --overwrite
inspec exec <name of generated archive> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

## Using Heimdall for Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors
* Eugene Aronne - [ejaronne](https://github.com/ejaronne)

## Special Thanks
* Aaron Lippold - [aaronlippold](https://github.com/aaronlippold)
* Will Dower - [wdower](https://github.com/wdower)
* Shivani Karikar - [karikarshivani](https://github.com/karikarshivani)
* 

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/mitre/crunchy-data-postgresql-stig-baseline/issues/new).

### NOTICE

© 2018-2025 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

### NOTICE 

MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.

### NOTICE 

DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx

