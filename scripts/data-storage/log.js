setImmediate(function() {
	Java.perform(function() {
		var log = Java.use("android.util.Log");
		log.d.overload('java.lang.String', 'java.lang.String').implementation = function (var0, var1) {
			send("[*] Debug log displayed with TAG: " + var0 + " and VALUE: " + var1 + "\n");
			this.d(var0, var1);
		};

		log.d.overload('java.lang.String', 'java.lang.String', 'java.lang.Throwable').implementation = function (var0, var1, var2) {
			send("[*] Debug log displayed with TAG: " + var0 + " and VALUE: " + var1 + "\n");
			this.d(var0, var1, var2);
		};

		log.e.overload('java.lang.String', 'java.lang.String').implementation = function (var0, var1) {
			send("[*] Error log displayed with TAG: " + var0 + " and VALUE: " + var1 + "\n");
			this.e(var0, var1);
		};

		log.e.overload('java.lang.String', 'java.lang.String', 'java.lang.Throwable').implementation = function (var0, var1, var2) {
			send("[*] Error log displayed with TAG: " + var0 + " and VALUE: " + var1 + "\n");
			this.e(var0, var1, var2);
		};		

		log.i.overload('java.lang.String', 'java.lang.String').implementation = function (var0, var1) {
			send("[*] Information log displayed with TAG: " + var0 + " and VALUE: " + var1 + "\n");
			this.i(var0, var1);
		};

		log.i.overload('java.lang.String', 'java.lang.String', 'java.lang.Throwable').implementation = function (var0, var1, var2) {
			send("[*] Information log displayed with TAG: " + var0 + " and VALUE: " + var1 + "\n");
			this.i(var0, var1, var2);
		};

		log.v.overload('java.lang.String', 'java.lang.String').implementation = function (var0, var1) {
			send("[*] Verbose log displayed with TAG: " + var0 + " and VALUE: " + var1 + "\n");
			this.v(var0, var1);
		};

		log.v.overload('java.lang.String', 'java.lang.String', 'java.lang.Throwable').implementation = function (var0, var1, var2) {
			send("[*] Verbose log displayed with TAG: " + var0 + " and VALUE: " + var1 + "\n");
			this.v(var0, var1, var2);
		};		

		log.w.overload('java.lang.String', 'java.lang.String').implementation = function (var0, var1) {
			send("[*] Warning log displayed with TAG: " + var0 + " and VALUE: " + var1 + "\n");
			this.w(var0, var1);
		};

		log.w.overload('java.lang.String', 'java.lang.String', 'java.lang.Throwable').implementation = function (var0, var1, var2) {
			send("[*] Warning log displayed with TAG: " + var0 + " and VALUE: " + var1 + "\n");
			this.w(var0, var1, var2);
		};	

		log.wtf.overload('java.lang.String', 'java.lang.String').implementation = function (var0, var1) {
			send("[*] What a terrible failure log displayed with TAG: " + var0 + " and VALUE: " + var1 + "\n");
			this.wtf(var0, var1);
		};


		log.wtf.overload('java.lang.String', 'java.lang.String', 'java.lang.Throwable').implementation = function (var0, var1, var2) {
			send("[*] What a terrible failure log displayed with TAG: " + var0 + " and VALUE: " + var1 + "\n");
			this.wtf(var0, var1, var2);
		};						
	});
});