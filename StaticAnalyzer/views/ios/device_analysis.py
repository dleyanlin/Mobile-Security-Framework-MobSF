# -*- coding: utf_8 -*-
"""Module for iOS APp Analysis in device."""


import re
import os
import subprocess

from MobSF.iosdevice.device import Device

def get_metadata(bundle_id):
    app_metadata_dict = {}
    device = Device()
    app_metadata_dict = device.app.get_metadata(bundle_id)
    return app_metadata_dict

def keychain_data():
    device = Device()
    keychaindata = device.dump_keychain()
    device.cleanup()
    device.disconnect()
    return keychaindata
