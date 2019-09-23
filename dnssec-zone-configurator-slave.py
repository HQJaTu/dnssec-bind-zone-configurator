#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

import argparse
from lib.configutils import *
from lib.bindutils import *


def main():
    parser = argparse.ArgumentParser(description='OpenDNSSEC BIND slave zone configurator')
    parser.add_argument('--bind-dir', metavar='BIND-DIRECTORY', default='/etc/bind',
                        help='Destination directory to write to')
    parser.add_argument('--dest-dir', '-d', metavar='DESTINATION-DIRECTORY',
                        help='Destination directory to write to')
    parser.add_argument('zone_configuration', metavar='ZONES-YAML-file',
                        help='The YAML-file containing DNS zones')
    parser.add_argument('master_ip', metavar='DNS-MASTER-IP',
                        help='IP-address of the master DNS of this slave DNS')
    args = parser.parse_args()

    bind_writer = BindConfigWriter(BindDir=args.bind_dir, DestDir=args.dest_dir)
    zones = ConfigReader.read_zone_list(args.zone_configuration, args.master_ip)
    bind_writer.create_slave_bind_conf(zones)
    bind_writer.create_zone_files(zones, args.master_ip)

    print("All done.")


if __name__ == '__main__':
    main()
