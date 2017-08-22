import frida
import sys


def on_message(message, data):
    try:
        if message:
            print("[*] {0}".format(message["payload"]))
            results.append(message["payload"])
    except Exception as e:
        print(message)
        print(e)

# $methods: array containing native method names exposed by this object
hook = '''
    if(ObjC.available) {
        ObjC.schedule(ObjC.mainQueue, function() {
            const window = ObjC.classes.UIWindow.keyWindow();
            const ui = window.recursiveDescription().toString();
            send(ui);
        });
    } else {
        console.log("Objective-C Runtime is not available!");
    }
'''

if __name__ == '__main__':
    try:
        print "Attach the Application is %s" % sys.argv[1]
        print hook
        session = frida.get_usb_device().attach(str(sys.argv[1]))
        script = session.create_script(hook)
        script.on('message', on_message)
        script.load()
    except Exception as e:
            print("Script terminated abruptly,Usage is ")
            print(e)
