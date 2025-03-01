Java.perform(function(){
    // Su Exists bypass
    const File = Java.use('java.io.File');
    File.exists.implementation = function () {
        const filePath = this.getPath();
       
        if (filePath.endsWith("su")){
            console.log(`Bypassing exists() call to: ${filePath}`);
            return false;
        }
        console.log(`Calling exists() on: ${filePath}`);
        return this.exists();
    };
 })