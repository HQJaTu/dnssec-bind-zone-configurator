# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

import os
import platform
from jinja2 import Environment, FileSystemLoader
from appdirs import AppDirs


class BindConfigWriter:

    PUBLIC_DIR: str
    DO_CHMOD = None

    def __init__(self, BindDir=None, DestDir=None, MasterForSlave=None):
        self.master_ip = MasterForSlave

        self.OWNER_NAME = 'root'
        self.GROUP_NAME = 'named'
        self.template_config = 'bind-include.j2'
        self.TEMPLATE_DNSSEC_UNSIGNED = 'zone-template-dnssec-unsigned.j2'
        self.TEMPLATE_DNSSEC_SIGNED = 'zone-template-dnssec-signed.j2'
        self.TEMPLATE_UNSIGNED_MASTER = 'zone-template-unsigned-master.j2'
        self.TEMPLATE_UNSIGNED_SLAVE = 'zone-template-unsigned-slave.j2'

        self.bind_dir = BindDir
        self.destination_dir = DestDir
        self.INTERNAL_DIR = 'zones.internal'
        self.PUBLIC_DIR = 'zones.public'
        self.BIND_CONF_FILENAME = 'dnssec.conf'
        self.BIND_KEY_CONF_FILENAME = 'dnssec-key.conf'
        self.DNS_IP = "::1"
        self.ODS_SIGNER_DNS_PORT = 54
        self.OUT_KEY = 'opendnssec-out'

        # Initialize Jinja2
        app_dirs = AppDirs("dnssec-bind-zone-configurator")
        j2_template_directories = ['%s/templates' % os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                                   '%s/templates' % app_dirs.site_data_dir]
        j2_template_loader = FileSystemLoader(searchpath=j2_template_directories)
        self.j2_env = Environment(loader=j2_template_loader, trim_blocks=True)

    def create_dnssec_bind_conf(self, zones):
        if BindConfigWriter.DO_CHMOD:
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

        template = self.j2_env.get_template(self.template_config)
        templ_zones = []
        for zone in zones:
            zone_item = zones[zone]
            templ_zone = {
                "zone": zone,
                "directory_name": self.PUBLIC_DIR
            }
            templ_zones.append(templ_zone)
            if zone_item[0]:
                templ_zone = {
                    "zone": zone,
                    "directory_name": self.INTERNAL_DIR
                }
                templ_zones.append(templ_zone)
        conf_data = template.render(bind_dir=self.bind_dir, zones=templ_zones)

        print("Writing %s:" % bind_conf_file)
        with open(bind_conf_file, "w") as conf_handle:
            print(conf_data, file=conf_handle)
        if BindConfigWriter.DO_CHMOD:
            os.chmod(bind_conf_file, 0o640)
            os.chown(bind_conf_file, uid, gid)
    
        return bind_conf_file

    def create_slave_bind_conf(self, zones):
        if BindConfigWriter.DO_CHMOD:
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

        template = self.j2_env.get_template(self.template_config)
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
        if BindConfigWriter.DO_CHMOD:
            os.chmod(bind_conf_file, 0o640)
            os.chown(bind_conf_file, uid, gid)

        return bind_conf_file

    def create_zone_files(self, zones, master_ip_addr):
        if BindConfigWriter.DO_CHMOD:
            uid = pwd.getpwnam(self.OWNER_NAME).pw_uid
            gid = grp.getgrnam(self.GROUP_NAME).gr_gid
        if not self.destination_dir:
            internal_dir = self.INTERNAL_DIR
            public_dir = self.PUBLIC_DIR
        else:
            internal_dir = "%s/%s" % (self.destination_dir, self.INTERNAL_DIR)
            public_dir: str = "%s/%s" % (self.destination_dir, self.PUBLIC_DIR)
        if not master_ip_addr:
            if not os.path.isdir(internal_dir):
                os.mkdir(internal_dir, 0o750)
        if not os.path.isdir(public_dir):
            os.mkdir(public_dir, 0o750)
        if BindConfigWriter.DO_CHMOD:
            if not master_ip_addr:
                os.chown(internal_dir, uid, gid)
            os.chown(public_dir, uid, gid)
    
        if master_ip_addr:
            unsigned_template = self.j2_env.get_template(self.TEMPLATE_UNSIGNED_SLAVE)
        else:
            dnssec_unsigned_template = self.j2_env.get_template(self.TEMPLATE_DNSSEC_UNSIGNED)
            dnssec_signed_template = self.j2_env.get_template(self.TEMPLATE_DNSSEC_SIGNED)
            unsigned_template = self.j2_env.get_template(self.TEMPLATE_UNSIGNED_MASTER)
    
        if master_ip_addr:
            master_ip = master_ip_addr
        else:
            master_ip = self.DNS_IP
        for zone in zones:
            zone_item = zones[zone]
            zone_file = zone_item[1]
            if not self.destination_dir:
                internal_filename = "%s/%s.conf" % (self.INTERNAL_DIR, zone)
                public_filename: str = "%s/%s.conf" % (self.PUBLIC_DIR, zone)
            else:
                internal_filename = "%s/%s/%s.conf" % (self.destination_dir, self.INTERNAL_DIR, zone)
                public_filename: str = "%s/%s/%s.conf" % (self.destination_dir, self.PUBLIC_DIR, zone)
            if zone_item[0] and not master_ip_addr:
                print("DNSSEC zone %s, files %s and %s:" % (zone, public_filename, internal_filename))
                self.create_zone_file(dnssec_unsigned_template, zone, internal_filename, zone_file, master_ip)
                self.create_zone_file(dnssec_signed_template, zone, public_filename, zone_file, master_ip)
            else:
                if master_ip_addr:
                    print("DNSSEC zone %s, file %s:" % (zone, public_filename))
                else:
                    print("Non-DNSSEC zone %s, file %s:" % (zone, public_filename))
                self.create_zone_file(unsigned_template, zone, public_filename, zone_file, master_ip)

    def create_zone_file(self, template, zone, conf_filename, zone_file, master_ip):
        if BindConfigWriter.DO_CHMOD:
            uid = pwd.getpwnam(self.OWNER_NAME).pw_uid
            gid = grp.getgrnam(self.GROUP_NAME).gr_gid
        conf_file = template.render(zone=zone, zone_file=zone_file,
                                    dns_ip=master_ip, dns_port=self.ODS_SIGNER_DNS_PORT,
                                    out_key=self.OUT_KEY)
    
        with open(conf_filename, "w") as zone_handle:
            print(conf_file, file=zone_handle)
        if BindConfigWriter.DO_CHMOD:
            os.chmod(conf_filename, 0o640)
            os.chown(conf_filename, uid, gid)


if platform.system() == 'Windows':
    import getpass
    BindConfigWriter.DO_CHMOD = False
else:
    if os.geteuid() == 0:
        import pwd
        import grp
        BindConfigWriter.DO_CHMOD = True
    else:
        BindConfigWriter.DO_CHMOD = False
