setImmediate(function() {
	Java.perform(function() {
		var random = Java.use("java.util.Random");

		// int nextInt()
		random.nextInt.overload().implementation = function () {
			var intVal = this.nextInt();
			send("[*] Random.nextInt called: " + intVal + "\n");
			return intVal;
		};

		// int nextInt(int bound)
		random.nextInt.overload('int').implementation = function (var0) {
			var intVal = this.nextInt(var0);
			send("[*] Random.nextInt with bound: " + var0 + " called: " + intVal + "\n");
			return intVal;
		};

		// double nextDouble()
		random.nextDouble.implementation = function () {
			var doubleVal = this.nextDouble();
			send("[*] Random.nextDouble called: " + doubleVal + "\n");
			return doubleVal;
		};

		// double nextGaussian()
		random.nextGaussian.implementation = function () {
			var doubleVal = this.nextGaussian();
			send("[*] Random.nextGaussian called: " + doubleVal + "\n");
			return doubleVal;
		};

		// boolean nextBoolean()
		random.nextBoolean.implementation = function () {
			var booleanVal = this.nextBoolean();
			send("[*] Random.nextBoolean called: " + booleanVal + "\n");
			return booleanVal;
		};

		// float nextFloat()
		random.nextFloat.implementation = function () {
			var floatVal = this.nextFloat();
			send("[*] Random.nextFloat called: " + floatVal + "\n");
			return floatVal;
		};

		// long nextLong()
		random.nextLong.implementation = function () {
			var longVal = this.nextLong();
			send("[*] Random.nextLong called: " + longVal + "\n");
			return longVal;
		};
	});
});