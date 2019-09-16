#!/usr/bin/env python3

from distutils.core import setup
import pathlib

try:
    from appdirs import AppDirs
except ImportError:
    raise ImportError('this package requires "appdirs" to be installed. '
                      'Install it first: "pip3 install appdirs".')
APP_DIRS = AppDirs("dnssec-bind-zone-configurator")

# Sample from: https://github.com/pypa/sampleproject/blob/master/setup.py
setup(name='dnssec-bind-zone-configurator',
      version='0.0.2',
      description='Utility to generate BIND DNS zone configuration files for OpenDNSSEC',
      author='Jari Turkia',
      author_email='jatu@hqcodeshop.fi',
      url='https://github.com/HQJaTu/dnssec-bind-zone-configurator',
      classifiers=[
          # How mature is this project? Common values are
          #   3 - Alpha
          #   4 - Beta
          #   5 - Production/Stable
          'Development Status :: 4 - Beta',

          # Indicate who your project is intended for
          'Intended Audience :: System Administrators',
          'Topic :: Software Development :: Build Tools',

          # Specify the Python versions you support here.
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: 3.6',
          'Programming Language :: Python :: 3.7',
      ],
      python_requires='>=3.5, <4',
      install_requires=['jinja2', 'appdirs', 'pyaml'],
      scripts=['dnssec-zone-configurator.py'],
      include_package_data=True,
      data_files=[
          ('%s/templates' % APP_DIRS.site_data_dir, [str(x) for x in pathlib.Path('.').glob('templates/*')])
      ],
      packages=[],
      )
