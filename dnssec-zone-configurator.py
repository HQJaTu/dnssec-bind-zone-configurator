#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

import argparse
import os
import platform
import yaml
from appdirs import AppDirs
from jinja2 import Environment, FileSystemLoader

if platform.system() == 'Windows':
    import getpass
    DO_CHMOD = False
else:
    import pwd
    import grp
    DO_CHMOD = True

OWNER_NAME = 'root'
GROUP_NAME = 'named'
DNS_IP = "::1"
DNS_PORT = 54
TEMPLATE_DNSSEC_UNSIGNED = 'zone-template-dnssec-unsigned.j2'
TEMPLATE_DNSSEC_SIGNED = 'zone-template-dnssec-signed.j2'
TEMPLATE_UNSIGNED_MASTER = 'zone-template-unsigned-master.j2'
TEMPLATE_UNSIGNED_SLAVE = 'zone-template-unsigned-slave.j2'
OUT_KEY = 'opendnssec-out'
INTERNAL_DIR = 'zones.internal'
PUBLIC_DIR = 'zones.public'
BIND_CONF_FILENAME = 'dnssec.conf'

BIND_CONF_TEMPLATE = """
include "named/{{ directory_name }}/{{ zone }}.conf";
"""


def create_bind_conf(j2_env, zones, master_ip_addr):
    if DO_CHMOD:
        uid = pwd.getpwnam(OWNER_NAME).pw_uid
        gid = grp.getgrnam(GROUP_NAME).gr_gid

    conf_data = ""
    template = j2_env.from_string(BIND_CONF_TEMPLATE)
    for zone in zones:
        zone_item = zones[zone]
        conf_data += template.render(zone=zone, directory_name=PUBLIC_DIR)
        if zone_item[0] and not master_ip_addr:
            conf_data += template.render(zone=zone, directory_name=INTERNAL_DIR)

    print("Writing %s:" % BIND_CONF_FILENAME)
    with open(BIND_CONF_FILENAME, "w") as conf_handle:
        print(conf_data, file=conf_handle)
    if DO_CHMOD:
        os.chmod(BIND_CONF_FILENAME, 0o640)
        os.chown(BIND_CONF_FILENAME, uid, gid)

    return BIND_CONF_FILENAME


def create_zone_files(j2_env, zones, master_ip_addr):
    if DO_CHMOD:
        uid = pwd.getpwnam(OWNER_NAME).pw_uid
        gid = grp.getgrnam(GROUP_NAME).gr_gid
    if not master_ip_addr:
        if not os.path.isdir(INTERNAL_DIR):
            os.mkdir(INTERNAL_DIR, 0o750)
    if not os.path.isdir(PUBLIC_DIR):
        os.mkdir(PUBLIC_DIR, 0o750)
    if DO_CHMOD:
        if not master_ip_addr:
            os.chown(INTERNAL_DIR, uid, gid)
        os.chown(PUBLIC_DIR, uid, gid)

    if master_ip_addr:
        unsigned_template = j2_env.get_template(TEMPLATE_UNSIGNED_SLAVE)
    else:
        dnssec_unsigned_template = j2_env.get_template(TEMPLATE_DNSSEC_UNSIGNED)
        dnssec_signed_template = j2_env.get_template(TEMPLATE_DNSSEC_SIGNED)
        unsigned_template = j2_env.get_template(TEMPLATE_UNSIGNED_MASTER)

    if master_ip_addr:
        master_ip = master_ip_addr
    else:
        master_ip = DNS_IP
    for zone in zones:
        zone_item = zones[zone]
        zone_file = zone_item[1]
        internal_filename = "%s/%s.conf" % (INTERNAL_DIR, zone)
        public_filename: str = "%s/%s.conf" % (PUBLIC_DIR, zone)
        if zone_item[0] and not master_ip_addr:
            print("DNSSEC zone %s, files %s and %s:" % (zone, public_filename, internal_filename))
            create_zone_file(dnssec_unsigned_template, zone, internal_filename, zone_file, master_ip)
            create_zone_file(dnssec_signed_template, zone, public_filename, zone_file, master_ip)
        else:
            if master_ip_addr:
                print("DNSSEC zone %s, file %s:" % (zone, public_filename))
            else:
                print("Non-DNSSEC zone %s, file %s:" % (zone, public_filename))
            create_zone_file(unsigned_template, zone, public_filename, zone_file, master_ip)


def create_zone_file(template, zone, conf_filename, zone_file, master_ip):
    if DO_CHMOD:
        uid = pwd.getpwnam(OWNER_NAME).pw_uid
        gid = grp.getgrnam(GROUP_NAME).gr_gid
    conf_file = template.render(zone=zone, zone_file=zone_file,
                                dns_ip=master_ip, dns_port=DNS_PORT,
                                out_key=OUT_KEY)

    with open(conf_filename, "w") as zone_handle:
        print(conf_file, file=zone_handle)
    if DO_CHMOD:
        os.chmod(conf_filename, 0o640)
        os.chown(conf_filename, uid, gid)


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


def main():
    parser = argparse.ArgumentParser(description='OpenDNSSEC BIND zone configurator')
    parser.add_argument('--dest-dir', '-d', metavar='DIRECTORY',
                        help='Destination directory to write to')
    parser.add_argument('--master-for-slave', '-m', metavar='MASTER-IP',
                        help='Instead of a master DNS, do a slave DNS config')
    parser.add_argument('zone_configuration', metavar='ZONES-YAML-file',
                        help='The YAML-file containing DNS zones')
    args = parser.parse_args()

    app_dirs = AppDirs("dnssec-bind-zone-configurator")
    j2_template_directories = ['%s/templates' % app_dirs.site_data_dir,
                               '%s/dnssec-bind-zone-configurator/templates' % app_dirs.site_data_dir]
    j2_template_loader = FileSystemLoader(searchpath=j2_template_directories)
    j2_env = Environment(loader=j2_template_loader, trim_blocks=True)

    zones = read_zone_list(args.zone_configuration, args.master_for_slave)
    create_bind_conf(j2_env, zones, args.master_for_slave)
    create_zone_files(j2_env, zones, args.master_for_slave)

    print("All done.")


if __name__ == '__main__':
    main()
