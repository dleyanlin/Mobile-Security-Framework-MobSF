import paramiko
import os
import json
import subprocess

class Device:
    ip=''
    username=''
    client=None

    def __init__(self,ip,username):
      self.ip = ip
      self.username = username

    def connect_ssh(self):
        print "[INFO] SSH the give server."+str(self.ip)
        try:
           path = os.path.join(os.environ['HOME'], '.ssh', 'id_rsa')
           key = paramiko.RSAKey.from_private_key_file(path)
           self.client = paramiko.SSHClient()
           self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
           print "[INFO] Start Connecting to server "+str(self.ip)
           self.client.connect(self.ip,username=self.username, pkey=key)
           print "[INFO] Connect done as "+str(self.username)
        except paramiko.AuthenticationException as e:
                raise Exception('Authentication failed when connecting to %s. %s: %s' % (self.ip, type(e).__name__, e.message))
        except paramiko.SSHException as e:
                raise Exception('Connection dropped. Please check your connection with the device, '
                                'and reload the module. %s: %s' % (type(e).__name__, e.message))
        except Exception as e:
                raise Exception('Could not open a connection to %s. %s - %s' % (self.ip, type(e).__name__, e.message))

    def exec_command(self, cmd):
        """Execute a shell command on the device, then parse/print output."""
        # Paramiko Exec Command
        self.connect_ssh()
        print "[INFO] Implement command of ."+str(cmd)
        stdin, stdout, stderr = self.client.exec_command(cmd)
        # Parse STDOUT/ERR
        out = stdout.readlines()
        err = stderr.readlines()
            # For processing, don't display output
        if err: # Show error and abort run
            err_str = ''.join(err)
            raise Exception(err_str)
        else:
          return out, err

    def Uicache(self):
        print "[INFO] Uicache the server."
        stdout,stderr=self.exec_command('/bin/su mobile -c /usr/bin/uicache')
        return stdout,stderr

    def DumpKeyChain(self):
        self.connect_ssh()
        keychaindata=''
        #client=SSH(hostname,username)
        print "[INFO] Dump keyChain from. "+str(self.ip)
        stdin,stdout,stderr=self.client.exec_command('/var/root/keychaineditor --action dump')
        output=stdout.read()
        data = json.loads(output)
        for key in data:
            keychaindata+=","+(json.dumps(data[key]))
        return keychaindata[1:]

    def install_ipa(self,src,dst):
        """sync the remote file to local."""
        dst=self.username +"@" + self.ip + ":" + dst
        print "[INFO] upload file to " +str(dst)
        subprocess.check_call(["scp","-r",src,dst])
        cmd="ipadinstaller -i" + dst
        self.connect_ssh()
        stdin,stdout,stderr=self.client.exec_command(cmd)
