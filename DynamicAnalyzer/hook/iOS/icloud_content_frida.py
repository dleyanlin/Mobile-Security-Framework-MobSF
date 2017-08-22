import frida
import sys


def on_message(message, data):
    try:
        if message:
            print("[*] {0}".format(message["payload"]))
    except Exception as e:
        print(message)
        print(e)


hook = '''
	   if (ObjC.available) {
            var NSHomeDirectory = new NativeFunction(ptr(Module.findExportByName("Foundation","NSHomeDirectory")),'pointer',[]);
            var NSFileManager = ObjC.classes.NSFileManager;
            var NSURL = ObjC.classes.NSURL;
            var documentsPath = (new ObjC.Object(NSHomeDirectory())).stringByAppendingPathComponent_("Documents");
            var enumerator = NSFileManager.defaultManager().enumeratorAtPath_(documentsPath);
            var filePath = null;
            var isDirPtr = Memory.alloc(Process.pointerSize);
            Memory.writePointer(isDirPtr,NULL);

            while ((filePath = enumerator.nextObject()) != null){
                NSFileManager.defaultManager().fileExistsAtPath_isDirectory_(documentsPath.stringByAppendingPathComponent_(filePath),isDirPtr);
                var url = NSURL.fileURLWithPath_(documentsPath.stringByAppendingPathComponent_(filePath));
                if (Memory.readPointer(isDirPtr) == 0) {
                    var resultPtr = Memory.alloc(Process.pointerSize);
                    var errorPtr = Memory.alloc(Process.pointerSize);
                    url.getResourceValue_forKey_error_(resultPtr,"NSURLIsExcludedFromBackupKey",errorPtr)
                    var result = new ObjC.Object(Memory.readPointer(resultPtr));
                    send(JSON.stringify({result:result.toString(), path:documentsPath.stringByAppendingPathComponent_(filePath).toString()}));
                }
          }
        } else {
            console.log("Objective-C Runtime is not available!");
        }
'''

if __name__ == '__main__':
    try:
        device = frida.get_usb_device()
        app = device.get_frontmost_application()
        if app==None:
            print "No app in foreground"
        else:
            print "The %s application will be attached." % app.name
        session = device.attach(app.pid)
        script = session.create_script(hook)
        script.on('message', on_message)
        script.load()
    except Exception as e:
            print("Script terminated abruptly,Usage is ")
            print(e)
