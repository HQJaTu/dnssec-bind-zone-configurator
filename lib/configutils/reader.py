# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

import yaml


class ConfigReader:

    @staticmethod
    def read_zone_list(configuration_file_name, master_ip_addr):
        zones = {}
        with open(configuration_file_name, "r") as stream:
            zone_config = yaml.safe_load(stream)
        if not zone_config['zones']:
            raise ValueError("Invalid zone-YAML! No 'zones' in it.")
        zone_config = zone_config['zones']
        zone_count = 0

        if 'dnssec' in zone_config:
            for zone_item in zone_config['dnssec']:
                zone_name = next(iter(zone_item))
                zone_file = zone_item[zone_name]
                zone_does_slave = False
                if not isinstance(zone_file, str):
                    if 'slave' in zone_file and isinstance(zone_file['slave'], bool):
                        zone_does_slave = zone_file['slave']
                    zone_file = zone_file['file']
                if master_ip_addr and not zone_does_slave:
                    # Skip non-slave zones on a slave DNS
                    continue
                zones[zone_name] = [True, zone_file]
                zone_count += 1

        if 'regular' in zone_config:
            for zone_item in zone_config['regular']:
                zone_name = next(iter(zone_item))
                zone_file = zone_item[zone_name]
                zone_does_slave = False
                if not isinstance(zone_file, str):
                    if 'slave' in zone_file and isinstance(zone_file['slave'], bool):
                        zone_does_slave = zone_file['slave']
                    zone_file = zone_file['file']
                if master_ip_addr and not zone_does_slave:
                    # Skip non-slave zones on a slave DNS
                    continue
                zones[zone_name] = [False, zone_file]
                zone_count += 1

        if zone_count == 0:
            raise ValueError("Invalid zone-YAML! No zones found from it.")

        return zones
