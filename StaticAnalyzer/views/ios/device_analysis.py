# -*- coding: utf_8 -*-
"""Module for iOS APp Analysis in device."""


import re
import os
import subprocess

from django.http import HttpResponse
from django.conf import settings
from MobSF.iosdevice.device import Device

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
    app_metadata_dict = {}
    device = Device()
    app_metadata_dict = device.app.get_metadata(bundle_id)
    return app_metadata_dict

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
