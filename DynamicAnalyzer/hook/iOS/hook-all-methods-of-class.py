import frida
import sys


def on_message(message, data):
    try:
        if message:
            print("[*] {0}".format(message["payload"]))
    except Exception as e:
        print(message)
        print(e)

# $methods: array containing native method names exposed by this object
hook = '''
    console.log("[*] Started: Hook all methods of a specific class");
    if (ObjC.available){
        try{
            var className = "%s";
            console.log("[*] Target: The specific class is " + className);
            var methods = eval('ObjC.classes.' + className + '.$methods');
            for (var i = 0; i < methods.length; i++){
                try{
                    console.log("[-] "+methods[i]);
                    try{
                        console.log("\t[*] Hooking into implementation");
                        var className2 = className;
                        var funcName2 = methods[i];
                        var hook = eval('ObjC.classes.'+className2+'["'+funcName2+'"]');
                        Interceptor.attach(hook.implementation, {
                            onEnter: function(args) {
                                console.log("[*] Detected call to: " + className2 + " -> " + funcName2);
                            }
                        });
                        console.log("\t[*] Hooking successful");
                    }
                    catch(err){
                        console.log("\t[!] Hooking failed: " + err.message);
                    }
                }
                catch(err){
                    console.log("[!] Exception1: " + err.message);
                }
            }
        }
        catch(err){
            console.log("[!] Exception2: " + err.message);
        }
    }
    else{
        console.log("Objective-C Runtime is not available!");
    }
    console.log("[*] Completed: Hook all methods of a specific class");
'''

if __name__ == '__main__':
    try:
        device = frida.get_usb_device()
        app = device.get_frontmost_application()
        if app==None:
            print "No app in foreground"
        else:
            print "The %s application will be attached." % app.name
        payload = hook % sys.argv[1]
        session = device.attach(app.pid)
        script = session.create_script(payload)
        script.on('message', on_message)
        script.load()
    except Exception as e:
            print("Script terminated abruptly,Usage is ")
            print(e)
