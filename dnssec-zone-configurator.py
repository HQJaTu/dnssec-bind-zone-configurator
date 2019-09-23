#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

import argparse
from lib.configutils import *
from lib.bindutils import *


def main():
    parser = argparse.ArgumentParser(description='OpenDNSSEC BIND zone configurator')
    parser.add_argument('--bind-dir', metavar='BIND-DIRECTORY', default='/etc/bind',
                        help='Destination directory to write to')
    parser.add_argument('--dest-dir', '-d', metavar='DESTINATION-DIRECTORY',
                        help='Destination directory to write to')
    parser.add_argument('zone_configuration', metavar='ZONES-YAML-file',
                        help='The YAML-file containing DNS zones')
    parser.add_argument('tsig-key', metavar='TSIG-PRIVATE-KEY-FILE',
                        help='TSIG private key to access OpenDNSSEC signerd')
    parser.add_argument('--tsig-key-name', metavar='TSIG-KEY-NAME', default='opendnssec-out',
                        help='TSIG key name')
    parser.add_argument('--signer-ip', metavar='SIGNERD-IP', default="::1",
                        help='OpenDNSSEC signerd IP-address')
    parser.add_argument('--signer-port', metavar='SIGNERD-PORT', default="53",
                        help='OpenDNSSEC signerd port. Default TCP/53')
    args = parser.parse_args()

    bind_writer = BindConfigWriter(BindDir=args.bind_dir, DestDir=args.dest_dir)
    zones = ConfigReader.read_zone_list(args.zone_configuration, False)
    bind_writer.create_dnssec_bind_conf(zones)
    bind_writer.create_zone_files(zones, False)

    print("All done.")


if __name__ == '__main__':
    main()
