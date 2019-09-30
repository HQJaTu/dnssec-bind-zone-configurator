# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

import os
import platform
from jinja2 import Environment, FileSystemLoader
from appdirs import AppDirs
import re


class BindConfigWriter:
    PUBLIC_DIR: str
    # See: https://www.iana.org/assignments/tsig-algorithm-names/tsig-algorithm-names.xhtml
    # for list of TSIG algorithms.
    TSIG_ALGORITHMS = {
        'HMAC_SHA1': 'hmac-sha1',
        'HMAC_SHA224': 'hmac-sha224',
        'HMAC_SHA256': 'hmac-sha256',
        'HMAC_SHA384': 'hmac-sha384',
        'HMAC_SHA512': 'hmac-sha512'
    }
    DO_CHOWN = None

    DEFAULT_BIND_KEY_IN_CONF_FILENAME = 'dnssec-reader-key.conf'
    DEFAULT_BIND_KEY_OUT_CONF_FILENAME = 'dnssec-master-key.conf'
    DEFAULT_SIGNERD_IP = "::1"
    DEFAULT_SIGNERD_PORT = 54

    def __init__(self, BindDir=None, DestDir=None, MasterForSlave=None):
        self.master_ip = MasterForSlave

        self.OWNER_NAME = 'root'
        self.GROUP_NAME = 'named'
        self.template_config_plain = 'bind-include-plain-view.j2'
        self.template_config_dual_view = 'bind-include-internal-view.j2'
        self.template_config_key = 'bind-key-include.j2'
        self.TEMPLATE_DNSSEC_UNSIGNED = 'zone-template-dnssec-unsigned.j2'
        self.TEMPLATE_DNSSEC_SIGNED = 'zone-template-dnssec-signed.j2'
        self.TEMPLATE_UNSIGNED_MASTER = 'zone-template-unsigned-master.j2'
        self.TEMPLATE_UNSIGNED_SLAVE = 'zone-template-unsigned-slave.j2'

        self.bind_dir = BindDir
        self.destination_dir = DestDir
        self.INTERNAL_DIR = 'zones.internal'
        self.PUBLIC_DIR = 'zones.public'
        self.BIND_CONF_FILENAME = 'dnssec.conf'
        self.OUT_KEY = 'opendnssec-out'

        # Initialize Jinja2
        app_dirs = AppDirs("dnssec-bind-zone-configurator")
        j2_template_directories = [
            '%s/templates' % os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            '%s/templates' % app_dirs.site_data_dir]
        j2_template_loader = FileSystemLoader(searchpath=j2_template_directories)
        self.j2_env = Environment(loader=j2_template_loader, trim_blocks=True)

    def create_dnssec_bind_conf(self, zones, out_key_file, out_key_name):
        """
        Create the "main" include to manage all DNS zones
        :param zones: dict of zones to create includes for
        :param out_key_file: Do configuration for additional key.
        If exists, indicates that this DNS is serving zones for OpenDNSSEC signerd.
        :param out_key_name: Key name to use in Bind configuration
        :return:
        """
        if BindConfigWriter.DO_CHOWN:
            uid = pwd.getpwnam(self.OWNER_NAME).pw_uid
            gid = grp.getgrnam(self.GROUP_NAME).gr_gid

        if not self.destination_dir:
            bind_conf_file = self.BIND_CONF_FILENAME
        else:
            bind_conf_file = '%s/%s' % (self.destination_dir, self.BIND_CONF_FILENAME)

        if out_key_file:
            template = self.j2_env.get_template(self.template_config_dual_view)
        else:
            template = self.j2_env.get_template(self.template_config_plain)
        zone_info = []
        zone_info_private = []
        for zone in zones:
            zone_item = zones[zone]
            this_zone_info = {
                "zone": zone,
                "directory_name": self.PUBLIC_DIR
            }
            zone_info.append(this_zone_info)
            if zone_item[0]:
                this_zone_info = {
                    "zone": zone,
                    "directory_name": self.INTERNAL_DIR
                }
                zone_info_private.append(this_zone_info)
        conf_data = template.render(bind_dir=self.bind_dir,
                                    zones=zone_info, zones_private=zone_info_private,
                                    key_conf_name='dnssec-reader-key.conf',
                                    key_out_conf_name='dnssec-master-key.conf',
                                    out_key=out_key_name)

        print("Writing %s:" % bind_conf_file)
        with open(bind_conf_file, "w") as conf_handle:
            print(conf_data, file=conf_handle)
        os.chmod(bind_conf_file, 0o640)
        if BindConfigWriter.DO_CHOWN:
            os.chown(bind_conf_file, uid, gid)

        return bind_conf_file

    def create_dnssec_bind_key_conf(self, key_file, key_name, conf_out_filename=DEFAULT_BIND_KEY_IN_CONF_FILENAME):
        if BindConfigWriter.DO_CHOWN:
            uid = pwd.getpwnam(self.OWNER_NAME).pw_uid
            gid = grp.getgrnam(self.GROUP_NAME).gr_gid

        if not self.destination_dir:
            bind_conf_file = conf_out_filename
        else:
            bind_conf_file = '%s/%s' % (self.destination_dir, conf_out_filename)

        # Read given TSIG private key file and parse needed information for Bind configuration.
        key_algorithm = None
        key_secret = None
        with open(key_file, encoding='utf-8') as key_handle:
            for line in key_handle:
                match = re.search(r'^Algorithm:\s+(\d+)\s+\((.+)\)', line)
                if match:
                    if match.group(2) not in BindConfigWriter.TSIG_ALGORITHMS:
                        raise ValueError(
                            "Cannot use TSIG key in file %s. Unsupported algorithm %s, need one of HMAC-SHA<bits>." % (
                                key_file, match.group(2)))
                    key_algorithm = BindConfigWriter.TSIG_ALGORITHMS[match.group(2)]
                    continue

                match = re.search(r'^Key:\s+(.+)$', line)
                if match:
                    key_secret = match.group(1)
                    continue

        if not key_algorithm or not key_secret:
            raise ValueError(
                "Cannot use TSIG key in file %s. Cannot parse TSIG key-file." % (key_file))

        template = self.j2_env.get_template(self.template_config_key)
        conf_data = template.render(key_name=key_name, key_algorithm=key_algorithm, key_secret=key_secret)

        print("Writing %s:" % bind_conf_file)
        with open(bind_conf_file, "w") as conf_handle:
            print(conf_data, file=conf_handle)
        os.chmod(bind_conf_file, 0o640)
        if BindConfigWriter.DO_CHOWN:
            os.chown(bind_conf_file, uid, gid)

        return bind_conf_file

    def create_slave_bind_conf(self, zones):
        if BindConfigWriter.DO_CHOWN:
            uid = pwd.getpwnam(self.OWNER_NAME).pw_uid
            gid = grp.getgrnam(self.GROUP_NAME).gr_gid

        if not self.destination_dir:
            internal_dir = self.INTERNAL_DIR
            public_dir = self.PUBLIC_DIR
            bind_conf_file = self.BIND_CONF_FILENAME
        else:
            internal_dir = '%s/%s' % (self.destination_dir, self.INTERNAL_DIR)
            public_dir = '%s/%s' % (self.destination_dir, self.PUBLIC_DIR)
            bind_conf_file = '%s/%s' % (self.destination_dir, self.BIND_CONF_FILENAME)

        template = self.j2_env.get_template(self.template_config_plain)
        templ_zones = []
        for zone in zones:
            zone_item = zones[zone]
            templ_zone = {
                "zone": zone,
                "directory_name": self.PUBLIC_DIR
            }
            templ_zones.append(templ_zone)
        conf_data = template.render(bind_dir=self.bind_dir, zones=templ_zones)

        print("Writing %s:" % bind_conf_file)
        with open(bind_conf_file, "w") as conf_handle:
            print(conf_data, file=conf_handle)
        os.chmod(bind_conf_file, 0o640)
        if BindConfigWriter.DO_CHOWN:
            os.chown(bind_conf_file, uid, gid)

        return bind_conf_file

    def create_zone_files(self, zones, dont_serve_signerd_out, master_ip_in, key_name):
        """
        Create Bind configuration files for all zones
        :param zones: dict of zones to do
        :param dont_serve_signerd_out: Create internal zones for serving zones from this Bind
        This is not applicable for slave zones.
        :param master_ip_in: IP-address of OpenDNSSEC signerd master OR
        master DNS of a slave.
        :param key_name: TSIG key name in Bind configuration to read data from OpenDNSSEC signerd
        :return:
        """
        if BindConfigWriter.DO_CHOWN:
            uid = pwd.getpwnam(self.OWNER_NAME).pw_uid
            gid = grp.getgrnam(self.GROUP_NAME).gr_gid
        if not self.destination_dir:
            internal_dir = self.INTERNAL_DIR
            public_dir = self.PUBLIC_DIR
        else:
            internal_dir = "%s/%s" % (self.destination_dir, self.INTERNAL_DIR)
            public_dir: str = "%s/%s" % (self.destination_dir, self.PUBLIC_DIR)
        if not dont_serve_signerd_out:
            if not os.path.isdir(internal_dir):
                os.mkdir(internal_dir, 0o750)
        if not os.path.isdir(public_dir):
            os.mkdir(public_dir, 0o750)
        if BindConfigWriter.DO_CHOWN:
            if not dont_serve_signerd_out:
                os.chown(internal_dir, uid, gid)
            os.chown(public_dir, uid, gid)

        if dont_serve_signerd_out:
            unsigned_template = self.j2_env.get_template(self.TEMPLATE_UNSIGNED_SLAVE)
            dnssec_unsigned_template = None
            dnssec_signed_template = None
        else:
            dnssec_unsigned_template = self.j2_env.get_template(self.TEMPLATE_DNSSEC_UNSIGNED)
            dnssec_signed_template = self.j2_env.get_template(self.TEMPLATE_DNSSEC_SIGNED)
            unsigned_template = self.j2_env.get_template(self.TEMPLATE_UNSIGNED_MASTER)

        if master_ip_in:
            master_ip = master_ip_in
        else:
            master_ip = BindConfigWriter.DEFAULT_SIGNERD_IP
        for zone in zones:
            zone_item = zones[zone]
            zone_file = zone_item[1]
            if not self.destination_dir:
                internal_filename = "%s/%s.conf" % (self.INTERNAL_DIR, zone)
                public_filename: str = "%s/%s.conf" % (self.PUBLIC_DIR, zone)
            else:
                internal_filename = "%s/%s/%s.conf" % (self.destination_dir, self.INTERNAL_DIR, zone)
                public_filename: str = "%s/%s/%s.conf" % (self.destination_dir, self.PUBLIC_DIR, zone)
            if zone_item[0] and not dont_serve_signerd_out:
                print("DNSSEC zone %s, files %s and %s:" % (zone, public_filename, internal_filename))
                self.create_zone_file(dnssec_unsigned_template, zone, internal_filename, zone_file,
                                      master_ip, BindConfigWriter.DEFAULT_SIGNERD_PORT, key_name)
                self.create_zone_file(dnssec_signed_template, zone, public_filename, zone_file,
                                      master_ip, BindConfigWriter.DEFAULT_SIGNERD_PORT, key_name)
            else:
                if dont_serve_signerd_out:
                    print("DNSSEC zone %s, file %s:" % (zone, public_filename))
                else:
                    print("Non-DNSSEC zone %s, file %s:" % (zone, public_filename))
                self.create_zone_file(unsigned_template, zone, public_filename, zone_file,
                                      master_ip, BindConfigWriter.DEFAULT_SIGNERD_PORT, key_name)

    def create_zone_file(self, template, zone, conf_filename, zone_file, master_ip, master_port, key_name):
        if BindConfigWriter.DO_CHOWN:
            uid = pwd.getpwnam(self.OWNER_NAME).pw_uid
            gid = grp.getgrnam(self.GROUP_NAME).gr_gid
        conf_file = template.render(zone=zone, zone_file=zone_file,
                                    dns_ip=master_ip, dns_port=master_port,
                                    signerd_in_key=key_name)

        with open(conf_filename, "w") as zone_handle:
            print(conf_file, file=zone_handle)
        os.chmod(conf_filename, 0o640)
        if BindConfigWriter.DO_CHOWN:
            os.chown(conf_filename, uid, gid)


if platform.system() == 'Windows':
    import getpass

    BindConfigWriter.DO_CHOWN = False
else:
    if os.geteuid() == 0:
        import pwd
        import grp

        BindConfigWriter.DO_CHOWN = True
    else:
        BindConfigWriter.DO_CHOWN = False
