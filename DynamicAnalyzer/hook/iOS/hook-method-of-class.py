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
    console.log("[*] Started: Hook spcific methods of a specific class");
    if(ObjC.available){
        try
            //Your class name here
            var className = "%s";
            //Your function name here
            var funcName = "%s";
            console.log("[*] Target: Will hook methods " + funcName + "in the class " + className);
            var hook = eval('ObjC.classes.' + className + '["' + funcName + '"]');
            Interceptor.attach(hook.implementation, {
                onEnter: function(args) {
                    // args[0] is self
                    // args[1] is selector (SEL "sendMessageWithText:")
                    // args[2] holds the first function argument, an NSString
                    console.log("[*] Detected call to: " + className + " -> " + funcName);
                    //For viewing and manipulating arguments
                    //console.log("\t[-] Value1: "+ObjC.Object(args[2]));
                    //console.log("\t[-] Value2: "+(ObjC.Object(args[2])).toString());
                    //console.log(args[2]);
                }
            });
        }
        catch(err){
           console.log("[!] Exception2: " + err.message);
        }
    }
    else{
       console.log("Objective-C Runtime is not available!");
    }
    console.log("[*] Completed: Hook specific methods of a specific class");
'''

if __name__ == '__main__':
    try:
        device = frida.get_usb_device()
        app = device.get_frontmost_application()
        if app==None:
            print "No app in foreground"
        else:
            print "The %s application will be attached." % app.name
        payload = hook % (sys.argv[1], sys.argv[2])
        print payload
        session = device.attach(app.pid)
        script = session.create_script(payload)
        script.on('message', on_message)
        script.load()
    except Exception as e:
            print("Script terminated abruptly,Usage is ")
            print(e)
