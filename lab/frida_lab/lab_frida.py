import frida
import time

device = frida.get_usb_device() # get device information
pid = device.spawn("com.hackerone.mobile.challenge2") # spawn app
device.resume(pid) # resumes it pid
time.sleep(1) # sleep 1 to avoid crash (sometime)
session=device.attach(pid)

hook_script="""
setTimeout(function()
{
    function rpad(width, string, padding) 
    { 
        return (width <= string.length) ? string : rpad(width, padding + string, padding)
    }

    function genPin(pin)
    {
        return rpad(6, pin.toString(), '0')        
    }
    Java.perform
    (   
        function ()
        {
            console.log("inside hook script");
            nonce = Java.array('byte',[ 97, 97, 98, 98, 99, 99, 100, 100, 101, 101, 102, 102, 103, 103, 104, 104, 97, 97, 98, 98, 99, 99, 100, 100]);
            cipherText = Java.array('byte',[ 150, 70, 209, 62, 200, 248, 97, 125, 28, 234, 28, 244, 51, 73, 64, 130, 76, 112, 10, 223, 106, 122, 50, 54, 22, 60, 162, 201, 96, 75, 155, 228, 189, 231, 112, 173, 105, 140, 2, 7, 15, 87, 26, 11, 97, 43, 189, 53, 114, 216, 31, 153]);
            
            flag = false;
            secretBoxClass = Java.use("org.libsodium.jni.crypto.SecretBox");
            Java.choose("com.hackerone.mobile.challenge2.MainActivity",{
                "onMatch":function(instance)
                {
                        console.log("[*] Instace found: "+instance);
                        counter = 0;
                        for(var i = 930000; i >= 0; i--)
                        {
                            pin = genPin(i.toString());
                            key = instance.getKey(pin);
                            console.log("Pin: " + pin + " - Key: " + instance.bytesToHex(key));

                            try
                            {
                                decrypt_result = secretBoxClass.$new(key).decrypt(nonce,cipherText);
                                flag = true;
                            }
                            catch(err)
                            {
                                //Do nothing
                            }
                            finally
                            {
                                if ( flag == true )
                                {
                                    console.log("Found");
                                    console.log("Pin: "+ pin );
                                    break;
                                }
                            }

                            counter++;
                            if(counter==50)
                                {
                                instance.resetCoolDown();
                                counter=0;
                                }
                        }
                },
                "onComplete":function()
                {
                    console.log("Done");
                }
            });
        }
    );
} , 0);
"""

script=session.create_script(hook_script) 
script.load()

input('...?') # prevent terminate

