setImmediate(function() {
	Java.perform(function() {

		var bufferedReader = Java.use("java.io.BufferedReader");

		bufferedReader.readLine.overload().implementation = function () {
			var line = this.readLine();
			send("[*] BufferedReader.readLine called: " + line +"\n");
			return line;
		};

		bufferedReader.read.overload().implementation = function () {
			var intVal = this.read();
			send("[*] BufferedReader.read called: " + intVal +"\n");
			return intVal;
		};

		var writer = Java.use("java.io.Writer");

		writer.write.overload('java.lang.String').implementation = function (var0) {
			send("[*] Writer.write called: " + var0 +"\n");
			this.write(var0);
		};
	});
});