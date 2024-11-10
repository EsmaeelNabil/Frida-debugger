/**
 * Configuration
 */
const debug = false; // Set to true to enable debug logging, false to disable

// List of function names to hook; leave empty to hook all functions
// If not empty, only functions whose names contain one of these strings will be hooked
const functionsToHook = ["save"]; // Add function names here

/**
 * Helper function: substringUntilDelimiterCount
 * Extracts a substring from the inputString until a specific delimiter is encountered
 * a certain number of times.
 *
 * @param {string} inputString - The input string to search within.
 * @param {string} delimiter - The delimiter to search for.
 * @param {number} count - The number of times the delimiter should be found.
 * @returns {string} - Substring of inputString up to the specified occurrence of delimiter.
 */
function substringUntilDelimiterCount(inputString, delimiter, count) {
  let currentIndex = 0;
  for (let i = 0; i < count; i++) {
    let delimiterIndex = inputString.indexOf(delimiter, currentIndex);
    if (delimiterIndex === -1) {
      return inputString; // If the delimiter is not found count times, return the whole string
    }
    currentIndex = delimiterIndex + 1;
  }
  return inputString.substring(0, currentIndex - 1);
}

/**
 * Function: debugSend
 * Conditionally sends a message if debugging is enabled.
 *
 * @param {string} message - The message to send.
 */
function debugSend(message) {
  if (debug) {
    send(message);
  }
}

/**
 * Helper function: shouldHookFunction
 * Determines if a function should be hooked based on the configured functionsToHook list.
 *
 * @param {string} methodName - The name of the method to check.
 * @returns {boolean} - True if the method should be hooked, false otherwise.
 */
function shouldHookFunction(methodName) {
  if (functionsToHook.length === 0) return true; // Hook all if list is empty
  return functionsToHook.some((name) =>
    methodName.toLowerCase().includes(name.toLowerCase()),
  );
}

/**
 * Main Frida script
 */
Java.perform(function () {
  debugSend("Script started");

  // Get the application context and package name
  var appContext = Java.use("android.app.ActivityThread")
    .currentApplication()
    .getApplicationContext();
  var packageName = appContext.getPackageName();
  debugSend("Current package name: " + packageName);
  debugSend("Enumerating loaded classes...");

  // Get all loaded classes
  var classes = Java.enumerateLoadedClassesSync();
  debugSend("Total loaded classes: " + classes.length);

  // Extract prefix from package name to limit hooked classes to the app’s package
  var appPrefix = substringUntilDelimiterCount(packageName, ".", 2);

  classes.forEach(function (className) {
    // Only process classes that belong to the application package
    if (className.startsWith(appPrefix)) {
      try {
        debugSend("Processing class: " + className);

        var clazz = Java.use(className);
        var methods = clazz.class.getDeclaredMethods();
        debugSend("Found " + methods.length + " methods in class " + className);

        // Iterate over each method in the class
        methods.forEach(function (method) {
          var methodName = method.getName();
          var paramTypeNames = method
            .getParameterTypes()
            .map((param) => param.getName());

          // Check if the method should be hooked based on the functionsToHook list
          if (shouldHookFunction(methodName)) {
            try {
              var overloadMethod = clazz[methodName].overload.apply(
                clazz[methodName],
                paramTypeNames,
              );

              (function (
                overloadMethod,
                className,
                methodName,
                paramTypeNames,
              ) {
                overloadMethod.implementation = function () {
                  let logMessage = `Called ${className}.${methodName}(${paramTypeNames.join(", ")})\n`;

                  // Log each argument's value and type
                  for (var k = 0; k < arguments.length; k++) {
                    let argValue = arguments[k];

                    // Handle specific Java types
                    if (
                      paramTypeNames[k] === "java.util.List" ||
                      paramTypeNames[k] === "kotlin.coroutines.Continuation"
                    ) {
                      argValue = JSON.stringify(argValue.toArray());
                    } else {
                      argValue = argValue.toString();
                    }

                    logMessage += `arg[${k}] (${paramTypeNames[k]}) = ${argValue}\n`;
                  }

                  // Call the original method and capture the return value
                  var ret = overloadMethod.apply(this, arguments);
                  logMessage += `Return value: ${JSON.stringify(ret)}`;
                  send(logMessage); // Send the log message

                  // Return the original result without modification
                  return ret;
                };
              })(overloadMethod, className, methodName, paramTypeNames);
            } catch (hookError) {
              debugSend(
                "Error hooking method " + methodName + ": " + hookError,
              );
            }
          }
        });
      } catch (e) {
        debugSend("Error processing class " + className + ": " + e);
      }
    }
  });

  debugSend("Script initialization complete");
});
