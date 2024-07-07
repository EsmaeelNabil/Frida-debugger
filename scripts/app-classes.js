Java.perform(function() {
    // Define the function to fetch classes and send them
    function fetchAndSendClasses() {
        try {
            var currentApplication = Java.use('android.app.ActivityThread').currentApplication();
            var packageName = currentApplication.getApplicationContext().getPackageName();

            var dexFiles = Java.enumerateLoadedClassesSync();
            var result = "";

            dexFiles.forEach(function(className) {
                if (className.startsWith(packageName)) {
                    result += className + '\n';
                }
            });

            send(result.trim()); // Send the result string without trailing newline
        } catch (error) {
            send('Error: ' + error.message);
        }
    }

    // Run the function in a separate thread using Frida's Thread API
    Java.scheduleOnMainThread(function() {
        fetchAndSendClasses();
    });
});
