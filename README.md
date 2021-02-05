# InSpec Profile
An InSpec Compliance Profile
---
Name: PostgreSQL STIG
Author: The Authors
Status: 
Copyright: The Authors
Copyright Email: you@example.com
Version: 0.1.0

Reference: 
Reference by: 
Reference source: 

`inspec exec controls/ -t ssh://[user]@[ip] --password=[password] --sudo --sudo-password=[password] --sudo-options="-u postgres" --input-file inputs.mysystem.yml --reporter cli json:results/myresults.json`
