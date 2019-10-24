#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

import argparse
from lib.configutils import *
from lib.bindutils import *


def main():
    orig_args = args_as_string()
    parser = argparse.ArgumentParser(description='OpenDNSSEC BIND zone configurator')
    parser.add_argument('--bind-dir', metavar='BIND-DIRECTORY', default='/etc/bind',
                        help='Destination directory to write to')
    parser.add_argument('--dest-dir', '-d', metavar='DESTINATION-DIRECTORY',
                        help='Destination directory to write to')
    parser.add_argument('--bind-conf-file-name', metavar='BIND-ZONES-INCLUDE-CONFIG-FILE',
                        default="zones-include.conf",
                        help='Bind configuration file to be included for all zones.')
    parser.add_argument('zone_configuration', metavar='ZONES-YAML-file',
                        help='The YAML-file containing DNS zones')
    parser.add_argument('tsig_key_file', metavar='TSIG-IN-PRIVATE-KEY-FILE',
                        help='TSIG private key to access OpenDNSSEC signerd for signed zones')
    parser.add_argument('--tsig-key-name', metavar='TSIG-IN-KEY-NAME',
                        help='TSIG key name for reading signed zones from OpenDNSSEC signerd')
    parser.add_argument('--signer-ip', metavar='SIGNERD-IP', default="::1",
                        help='OpenDNSSEC signerd IP-address')
    parser.add_argument('--signer-port', metavar='SIGNERD-PORT', default="53",
                        help='OpenDNSSEC signerd port. Default AXFR from TCP/53.')
    parser.add_argument('--tsig-out-key-file', metavar='TSIG-OUT-PRIVATE-KEY-FILE',
                        help='TSIG private key to allow access for OpenDNSSEC signerd into this DNS')
    parser.add_argument('--tsig-out-key-name', metavar='TSIG-OUT-KEY-NAME', default='opendnssec-out',
                        help='TSIG key name for OpenDNSSEC signerd to read unsigned zones from this DNS')
    args = parser.parse_args()

    bind_writer = BindConfigWriter(BindDir=args.bind_dir,
                                   DestDir=args.dest_dir, MainConfFileName=args.bind_conf_file_name,
                                   OrigArgv=orig_args)
    zones = ConfigReader.read_zone_list(args.zone_configuration, False)
    out_key_name_used = None
    if args.tsig_out_key_file:
        (key_file_name, out_key_name_used) = bind_writer.create_dnssec_bind_key_conf(args.tsig_out_key_file, args.tsig_out_key_name,
                                                BindConfigWriter.DEFAULT_BIND_KEY_OUT_CONF_FILENAME)
    bind_writer.create_dnssec_bind_conf(zones, args.tsig_out_key_file, out_key_name_used)

    (key_file_name, in_key_name_used) = bind_writer.create_dnssec_bind_key_conf(args.tsig_key_file, args.tsig_key_name,
                                            BindConfigWriter.DEFAULT_BIND_KEY_IN_CONF_FILENAME)
    bind_writer.create_zone_files(zones, args.tsig_out_key_file is None, args.signer_ip, in_key_name_used)

    print("All done.")


if __name__ == '__main__':
    main()
