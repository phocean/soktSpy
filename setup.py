from distutils.core import setup
import py2exe, sys, os

sys.argv.append('py2exe')

setup(zipfile = None, options = {'py2exe': {'bundle_files': 1}}, console=['soktSpy.py'])