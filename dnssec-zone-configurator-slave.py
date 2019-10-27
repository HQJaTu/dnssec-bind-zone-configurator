#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

import argparse
import subprocess
from lib.configutils import *
from lib.bindutils import *


def main():
    orig_args = args_as_string()
    parser = argparse.ArgumentParser(description='OpenDNSSEC BIND slave zone configurator')
    parser.add_argument('--bind-dir', metavar='BIND-DIRECTORY', default='/etc/bind',
                        help='Destination directory to write to')
    parser.add_argument('--dest-dir', '-d', metavar='DESTINATION-DIRECTORY',
                        help='Destination directory to write to')
    parser.add_argument('--bind-conf-file-name', metavar='BIND-ZONES-INCLUDE-CONFIG-FILE',
                        default="zones-include.conf",
                        help='Bind configuration file to be included for all zones.')
    parser.add_argument('--rndc-reload', '-r', action="store_true",
                        help='After all is done ok, run rndc reload to update Bind')
    parser.add_argument('zone_configuration', metavar='ZONES-YAML-file',
                        help='The YAML-file containing DNS zones')
    parser.add_argument('master_ip', metavar='DNS-MASTER-IP',
                        help='IP-address of the master DNS of this slave DNS')
    args = parser.parse_args()

    bind_writer = BindConfigWriter(BindDir=args.bind_dir,
                                   DestDir=args.dest_dir, MainConfFileName=args.bind_conf_file_name,
                                   OrigArgv=orig_args)
    zones = ConfigReader.read_zone_list(args.zone_configuration, args.master_ip)
    bind_writer.create_slave_bind_conf(zones)
    bind_writer.create_zone_files_for_slave(zones, args.master_ip)

    if args.rndc_reload:
        subprocess.run(['rndc', 'reload'], stdout=subprocess.PIPE)

    print("All done.")


if __name__ == '__main__':
    main()
