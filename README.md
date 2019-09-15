# dnssec-bind-zone-configurator
Utility to generate BIND DNS zone configuration files for OpenDNSSEC

# Install
From cloned git directory:
`pip3 install .`

# Usage
Execute `dnssec-zone-configurator.py` with required argument of YAML-file containing the zones.

## Example:
`dnssec-zone-configurator.py zones.yaml`

Will generate includable BIND configuration file listing all zones.
Subdirectories `zones.public` and `zones.internal` will contain the actual zone configuration files.

# Zone-configuration
There are two types of zones:
* _regular_: the ones not having any DNSSEC-magic
* _dnssec_: the ones having OpenDNSSEC signing applied to them


## Example YAML
Define two zones: _example.org_ and _example.com_.
_example.com_ will have OpenDNSSEC signing in it, _example.org_ will not.
```yaml

---
zones:
  dnssec:
    - example.com: named-example.com
  regular:
    - example.org: named-zone.example.org.txt
```
