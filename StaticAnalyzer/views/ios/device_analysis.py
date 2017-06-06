# -*- coding: utf_8 -*-
"""Module for iOS APp Analysis in device."""


import re
import os

from django.http import HttpResponse
from django.conf import settings
from MobSF.iosdevice.device import Device
from MobSF.iosdevice.utils.constants import Constants
from MobSF.iosdevice.utils.local_operations import LocalOperations
from MobSF.iosdevice.utils.printer import Printer


local_op = LocalOperations()
printer = Printer()

def install_uninstall_app(request):
   try:
        device = Device()
        bundle_id = request.GET['identifier']
        if bundle_id != "":
            output = device.uninstall_app(bundle_id)
        else:
            app_file = request.GET['file']
            md5_hash = request.GET['md5']
            app_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/' + app_file) #APP DIRECTORY
            output = device.install_ipa(app_dir)
        device.cleanup()
        device.disconnect()
        print "[INFO] output's value is %s" % output
        if output == None:
            return HttpResponse("Success")
        else:
            return HttpResponse("Failed,Please Re-try")
   except Exception,e:
        return HttpResponse(e)

def get_metadata(bundle_id):
    """Install APP to device"""
    app_metadata_dict = {}
    device = Device()
    app_metadata_dict = device.app.get_metadata(bundle_id)
    return app_metadata_dict

def install_app(ipa_file, bundle_id, ver):
    """Install APP to device"""
    device = Device()
    if device.have_installed(bundle_id):
        app_metadata_dict = device.app.get_metadata(bundle_id)
        if ver != app_metadata_dict["app_version"]:
            device.uninstall_app(bundle_id)
            device.install_ipa(ipa_file)
    else:
        device.install_ipa(ipa_file)

def get_app_data_cache(app_data,local_dir):
    device = Device()
    device.remote_op.download(app_data+"/.",local_dir,recursive=True)
    device.get_keyboard_cache(local_dir)
    device.get_cookies(local_dir)

def keychain_data():
    device = Device()
    keychaindata = device.dump_keychain()
    device.cleanup()
    device.disconnect()
    return keychaindata

def read_cookies(fname):
    cmd = 'python {bin} {temp_file}'.format(bin=Constants.PATH_TOOLS_LOCAL['BINARYCOOKIEREADER'], temp_file=fname)
    out = local_op.command_interactive(cmd)
    printer.verbose("COOKIES's value %s" % out)
    return out
