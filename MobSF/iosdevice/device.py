from __future__ import print_function
import paramiko
import os
import subprocess
import json
from sshtunnel import SSHTunnelForwarder

from app import App
from installer import Installer
from remote_operations import RemoteOperations
from utils.local_operations import LocalOperations
from utils.constants import Constants
#from ..utils.menu import choose_from_list
from utils.printer import Colors, Printer


# ======================================================================================================================
# DEVICE CLASS
# ======================================================================================================================
class Device(object):
    # ==================================================================================================================
    # FRAMEWORK ATTRIBUTES
    # ==================================================================================================================
    # Connection Parameters
    _ip = Constants.GLOBAL_IP
    _port = Constants.GLOBAL_PORT
    _username = Constants.GLOBAL_USERNAME
    _password = Constants.GLOBAL_PASSWORD
    _pub_key_auth=bool(Constants.GLOBAL_PUB_KEY_AUTH)
    _tools_local = Constants.PATH_TOOLS_LOCAL
    _portforward = None
    _frida_server = None
    _debug_server = None
    # App specific
    _is_iOS8 = False
    _is_iOS9 = False
    _is_iOS7_or_less = False
    _applist = None
    _device_not_ready = bool(Constants.GLOBAL_SETUP_DEVICE)
    # On-Device Paths
    TEMP_FOLDER = Constants.DEVICE_PATH_TEMP_FOLDER
    DEVICE_TOOLS = Constants.DEVICE_TOOLS
    # Reference to External Objects
    conn = None
    app = None
    installer = None
    local_op = None
    remote_op = None
    printer = None

    # ==================================================================================================================
    # INIT
    # ==================================================================================================================
    def __init__(self):
        # Init related objects
        self.app = App(self)
        self.installer = Installer(self)
        self.local_op = LocalOperations()
        self.remote_op = RemoteOperations(self)
        self.printer = Printer()
        self.connect()
        self.setup()

    # ==================================================================================================================
    # UTILS - USB
    # ==================================================================================================================
    def _portforward_usb_start(self):
        """Setup USB port forwarding with TCPRelay."""
        # Check if the user chose a valid port
        if str(self._port) == '22':
            raise Exception('Chosen port must be different from 22 in order to use USB over SSH')
        # Setup the forwarding
        self.printer.verbose('Setting up USB port forwarding on port %s' % self._port)
        cmd = '{app} -t 22:{port}'.format(app=self._tools_local['TCPRELAY'], port=self._port)
        self._portforward = self.local_op.command_subproc_start(cmd)

    def _portforward_usb_stop(self):
        """Stop USB port forwarding."""
        self.printer.verbose('Stopping USB port forwarding')
        self.local_op.command_subproc_stop(self._portforward)

    # ==================================================================================================================
    # UTILS - SSH
    # ==================================================================================================================
    def _connect_ssh(self):
        """Open a new connection using Paramiko."""
        try:
            path = os.path.join(os.environ['HOME'], '.ssh', 'id_rsa')
            key = paramiko.RSAKey.from_private_key_file(path)
            self.printer.verbose('Setting up SSH connection...')
            self.conn = paramiko.SSHClient()
            self.conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.conn.connect(self._ip, port=self._port, username=self._username, password=self._password,
                              allow_agent=self._pub_key_auth, pkey=key)

        except paramiko.AuthenticationException as e:
            raise Exception('Authentication failed when connecting to %s. %s: %s' % (self._ip, type(e).__name__, e.message))
        except paramiko.SSHException as e:
            raise Exception('Connection dropped. Please check your connection with the device, '
                            'and reload the module. %s: %s' % (type(e).__name__, e.message))
        except Exception as e:
            raise Exception('Could not open a connection to %s. %s - %s' % (self._ip, type(e).__name__, e.message))

    def _disconnect_ssh(self):
        """Close the connection, if available."""
        if self.conn:
            self.conn.close()

    def _exec_command_ssh(self, cmd, internal):
        """Execute a shell command on the device, then parse/print output."""
        # Paramiko Exec Command
        stdin, stdout, stderr = self.conn.exec_command(cmd)
        # Parse STDOUT/ERR
        out = stdout.readlines()
        err = stderr.readlines()
        if internal:
            # For processing, don't display output
            if err:
                # Show error and abort run
                err_str = ''.join(err)
                raise Exception(err_str)
        else:
            # Display output
            if out: map(lambda x: print('\t%s' % x, end=''), out)
            if err: map(lambda x: print('\t%s%s%s' % (Colors.R, x, Colors.N), end=''), err)
        return out, err

    # ==================================================================================================================
    # FRIDA PORT FORWARDING
    # ==================================================================================================================
    def _portforward_frida_start(self):
        """Setup local port forward to enable communication with the Frida server running on the device"""
        localhost = '127.0.0.1'
        self._frida_server = SSHTunnelForwarder(
            (self._ip, int(self._port)),
            ssh_username=self._username,
            ssh_password=self._password,
            local_bind_address=(localhost, Constants.FRIDA_PORT),
            remote_bind_address=(localhost, Constants.FRIDA_PORT),
        )
        self._frida_server.start()

    def _portforward_frida_stop(self):
        """Stop local port forwarding"""
        if self._frida_server:
            self._frida_server.stop()

    # ==================================================================================================================
    # LLDB PORT FORWARDING
    # ==================================================================================================================
    def _portforward_debug_start(self):
        """Setup local port forward to enable communication with the debug server running on the device"""
        localhost = '127.0.0.1'
        self._debug_server = SSHTunnelForwarder(
            (self._ip, int(self._port)),
            ssh_username=self._username,
            ssh_password=self._password,
            local_bind_address=(localhost, Constants.DEBUG_PORT),
            remote_bind_address=(localhost, Constants.DEBUG_PORT),
        )
        self._debug_server.start()

    def _portforward_debug_stop(self):
        """Stop local port forwarding"""
        if self._debug_server:
            self._debug_server.stop()

    # ==================================================================================================================
    # UTILS - OS
    # ==================================================================================================================
    def _detect_ios_version(self):
        """Detect the iOS version running on the device."""
        if self.remote_op.file_exist(Constants.DEVICE_PATH_APPLIST_iOS8):
            self._is_iOS8 = True
        elif self.remote_op.file_exist(Constants.DEVICE_PATH_APPLIST_iOS9):
            self._is_iOS9 = True
        else: self._is_iOS7_or_less = True

    def _list_apps(self):
        """List all the 3rd party apps installed on the device."""

        def list_iOS_7():
            raise Exception('Support for iOS < 8 not yet implemented')

        def list_iOS_89(applist):
            # Refresh UICache in case an app was installed after the last reboot
            self.printer.verbose("Refreshing list of installed apps...")
            self.remote_op.command_blocking('/bin/su mobile -c /usr/bin/uicache', internal=True)
            # Parse plist file
            pl = self.remote_op.parse_plist(applist)
            self._applist = pl["User"]

        # Dispatch
        self._detect_ios_version()
        if self._is_iOS8: list_iOS_89(Constants.DEVICE_PATH_APPLIST_iOS8)
        elif self._is_iOS9: list_iOS_89(Constants.DEVICE_PATH_APPLIST_iOS9)
        else: list_iOS_7()
    # ==================================================================================================================
    # EXPOSED COMMANDS
    # ==================================================================================================================
    def is_usb(self):
        """Returns true if using SSH over USB."""
        return self._ip == '127.0.0.1' or self._ip == 'localhost'

    def connect(self):
        """Connect to the device."""
        if self.is_usb():
            # Using SSH over USB, setup port forwarding first
            self._portforward_usb_start()
        # Connect
        self._connect_ssh()

    def disconnect(self):
        """Disconnect from the device."""
        if self._portforward:
            # Using SSH over USB, stop port forwarding
            self._portforward_usb_stop()
        self._disconnect_ssh()

    def setup(self):
        """Create temp folder, and check if all tools are available"""
        # Setup temp folder
        self.printer.verbose("Creating temp folder: %s" % self.TEMP_FOLDER)
        self.remote_op.dir_create(self.TEMP_FOLDER)
        # Install tools
        if self._device_not_ready:
            self.printer.info("Configuring device...")
            self._device_not_ready = self.installer.configure()

    def cleanup(self):
        """Remove temp folder from device."""
        self.printer.verbose("Cleaning up temp folder: %s" % self.TEMP_FOLDER)
        self.remote_op.dir_delete(self.TEMP_FOLDER)

    def shell(self):
        """Spawn a system shell on the device."""
        cmd = 'sshpass -p "{password}" ssh {hostverification} -p {port} {username}@{ip}'.format(password=self._password,
                                                                                                hostverification=Constants.DISABLE_HOST_VERIFICATION,
                                                                                                port=self._port,
                                                                                                username=self._username,
                                                                                                ip=self._ip)
        self.local_op.command_interactive(cmd)

    def pull(self, src, dst):
        """Pull a file from the device."""
        self.printer.info("Pulling: %s -> %s" % (src, dst))
        self.remote_op.download(src, dst)

    def push(self, src, dst):
        """Push a file on the device."""
        self.printer.info("Pushing: %s -> %s" % (src, dst))
        self.remote_op.upload(src, dst)

    def sync_files(self,src,dst):
        """sync files with device."""
        device_ip = self.remote_op.get_ip()
        device_ip = str(device_ip[0].strip())
        self.printer.verbose("The Device IP address is: %s" % device_ip)
        remote_dir=self._username +"@" + device_ip + ":" + src
        self.printer.verbose("Start to sync data from %s >> %s" %(remote_dir,dst))
        subprocess.check_call(["rsync","-avz","--delete",remote_dir,dst])

    def install_ipa(self, src):
        """Install app with ipa file."""
        self.printer.verbose("Start to install %s to device" % src)
        dst = self.remote_op.build_temp_path_for_file("app.ipa")
          # Upload binary to device
        self.printer.verbose("Uploading binary: %s" % src)
        self.remote_op.upload(src, dst)
          # Install
        self.printer.verbose("Installing binary...")
        cmd = "{bin} {app}".format(bin=self.DEVICE_TOOLS['IPAINSTALLER'], app=dst)
        self.remote_op.command_interactive_tty(cmd)

    def uninstall_app(self,identifier):
        self.printer.verbose("Uninstall binary...")
        cmd = "{bin} -u {app}".format(bin=self.DEVICE_TOOLS['IPAINSTALLER'], app=identifier)
        self.remote_op.command_interactive_tty(cmd)

    def have_installed(self,app_name):
        self.printer.verbose("Start to check App whether have been installed")
        self._list_apps()
        if app_name in self._applist.keys():
            self.printer.verbose("The %s App have been installed" % app_name)
            return True
        else:
            self.printer.verbose("The %s App not been installed" % app_name)
            return False

    def get_app_info(self,app_name):
        self.printer.verbose("Start to get %s App base information..." % app_name)
        self._list_apps()
        #if app_name in self._applist.keys():
        metadata=self.app.get_metadata(app_name)
        app_ver = metadata["app_version"].split(' ')[0]
        uuid = metadata["uuid"]
        data_directory = metadata["data_directory"]
        self.printer.verbose("The %s App Version in device is %s" %(app_name,app_ver))
        return app_ver,uuid,data_directory

    def get_keyboard_cache(self,LOCAL_KeyboardCache_DIR):
        """get keyboard cache of device."""
        self.printer.verbose("Start to get Keyobard cache data from device.")
        try:
            self.sync_files(Constants.KEYBOARD_CACHE+"en-dynamic.lm/",LOCAL_KeyboardCache_DIR)
            self.sync_files(Constants.KEYBOARD_CACHE+"dynamic-text.dat",LOCAL_KeyboardCache_DIR+".")
        except:
            self.printer.error("Cannot sync the keyboard cache data.")

    def dump_keychain(self):
        self.printer.verbose("Start to dump keychain data from device.")
        keychaindata=''
        cmd = '{} --action dump'.format(self.DEVICE_TOOLS['KEYCHAIN_DUMP'])
        stdin,stdout,stderr=self.conn.exec_command(cmd)
        out=stdout.read()
        data = json.loads(out)
        for key in data:
            keychaindata+=","+(json.dumps(data[key]))
        return keychaindata[1:]

    def dump_head_memory(self,app_name,local_head_folder):
       try:
           self._list_apps()
           metadata=self.app.get_metadata(app_name)
           self.printer.info("Launching the app...")
           self.app.open(metadata['bundle_id'])
           pid = self.app.search_pid(metadata['name'])
           # Create temp files/folders
           dir_dumps = self.remote_op.build_temp_path_for_file("gdb_dumps")
           fname_mach = self.remote_op.build_temp_path_for_file("gdb_mach")
           fname_ranges = self.remote_op.build_temp_path_for_file("gdb_ranges")
           self.remote_op.write_file(fname_mach, "info mach-regions")
           if self.remote_op.dir_exist(dir_dumps): self.remote_op.dir_delete(dir_dumps)
           self.remote_op.dir_create(dir_dumps)
           # Enumerate Mach Regions
           self.printer.info("Enumerating mach regions...")
           cmd = '''\
             gdb --pid="%s" --batch --command=%s 2>/dev/null | grep sub-regions | awk '{print $3,$5}' | while read range; do
               echo "mach-regions: $range"
               cmd="dump binary memory %s/dump`echo $range| awk '{print $1}'`.dmp $range"
               echo "$cmd" >> %s
           done ''' % (pid, fname_mach, dir_dumps, fname_ranges)
           self.remote_op.command_blocking(cmd)

           # Dump memory
           self.printer.info("Dumping memory (it might take a while)...")
           cmd = 'gdb --pid="%s" --batch --command=%s &>>/dev/null' % (pid, fname_ranges)
           self.remote_op.command_blocking(cmd)
           self.printer.info("Dump memory done.be stored under %s" % dir_dumps)

           self.remote_op.download(dir_dumps,local_head_folder,True)
           #return dir_dumps
           '''
           # Check if we have dumps
           self.printer.verbose("Checking if we have dumps...")
           file_list = self.remote_op.dir_list(dir_dumps, recursive=True)
           failure = filter(lambda x: 'total 0' in x, file_list)
           if failure:
              self.printer.error('It was not possible to attach to the process (known issue in iOS9. A Fix is coming soon)')
              return
         '''
       except:
           self.printer.error("Can't dump head memory data, Plese retry!!! ")
