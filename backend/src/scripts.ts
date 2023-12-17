export const load_stetho = `
Java.perform(function () {
    const stethoJarFilePath = "/data/local/tmp/stetho.jar";
    const stethoClassName = "com.facebook.stetho.Stetho";
    const javaFile = Java.use("java.io.File");
    const activityThread = Java.use("android.app.ActivityThread");
    const app = activityThread.currentApplication();
    const context = app.getApplicationContext();

    const stethoJarFile = javaFile.$new(stethoJarFilePath);

    // Define DynamicClassLoader using Java.registerClass
    const DynamicClassLoader = Java.registerClass({
        name: "org.update4j.DynamicClassLoader",
        implements: [Java.use("java.net.URLClassLoader").class],
        methods: {
            add: [{ returnType: 'void', argumentTypes: ['java.net.URL'] }]
        }
    });

    // Create a new instance of DynamicClassLoader
    const dynamicClassLoader = new DynamicClassLoader("classpath", Java.use("java.lang.ClassLoader").getSystemClassLoader());

    // Add the JAR file to the classpath
    dynamicClassLoader.add(Java.use("java.net.URL").$new(stethoJarFile.toURI().toURL()));

    try {
        // Load Stetho class using URLClassLoader
        const stethoClass = dynamicClassLoader.loadClass(stethoClassName);

        // Get the method and invoke it
        const initializeMethod = stethoClass.getDeclaredMethod("initializeWithDefaults", [Java.use("android.content.Context")]);
        initializeMethod.setAccessible(true); // Ensure we can access the method
        initializeMethod.invoke(null, context);

        send("Stetho successfully loaded!");
        send("Open Chrome at chrome://inspect/#devices");
    } catch (err) {
        send("Stetho NOT loaded!");
        send(err.toString());
    }
});



`;
export const AppInfoScript = `
Java.perform(function() {
    var context = null
    var ActivityThread = Java.use('android.app.ActivityThread');
    var targetApp = ActivityThread.currentApplication();
    if (targetApp != null) {
        context = targetApp.getApplicationContext();
        var env = {
            mainDirectory: context.getFilesDir().getParent(),
            filesDirectory: context.getFilesDir().getAbsolutePath().toString(),
            cacheDirectory: context.getCacheDir().getAbsolutePath().toString(),
            externalCacheDirectory: context.getExternalCacheDir().getAbsolutePath().toString(),
            codeCacheDirectory: 
                'getCodeCacheDir' in context ? 
                context.getCodeCacheDir().getAbsolutePath().toString() : 'N/A',
            obbDir: context.getObbDir().getAbsolutePath().toString(),
            packageCodePath: context.getPackageCodePath().toString(),
        };

        send("******************* App Environment Info *******************")
        send("mainDirectory: "+env.mainDirectory);
        send("filesDirectory: "+env.filesDirectory);
        send("cacheDirectory: "+env.cacheDirectory);
        send("externalCacheDirectory: "+env.externalCacheDirectory);
        send("codeCacheDirectory: "+env.codeCacheDirectory);
        send("obbDir: "+env.obbDir);
        send("packageCodePath: "+env.packageCodePath);
        send("************************************************************")

    } else console.log("Error: App Environment Info - N/A")

});
`;