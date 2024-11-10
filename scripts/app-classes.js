Java.perform(function() {
    // Define the function to fetch classes and send them
    function fetchAndSendClasses() {
        try {
            var currentApplication = Java.use('android.app.ActivityThread').currentApplication();
            var packageName = currentApplication.getApplicationContext().getPackageName();

            var dexFiles = Java.enumerateLoadedClassesSync();

            dexFiles.forEach(function(className) {
                if (className.startsWith(packageName)) {
                    send(className);
                }
            });

        } catch (error) {
            send('Error: ' + error.message);
        }
    }

    // Run the function in a separate thread using Frida's Thread API
    Java.scheduleOnMainThread(function() {
        fetchAndSendClasses();
    });
});
