setImmediate(function() {
	Java.perform(function() {
		var keyGenerator = Java.use("javax.crypto.KeyGenerator");
		keyGenerator.generateKey.implementation = function () {
			send("[*] Generate symmetric key called. ");
			return this.generateKey();
		};

		keyGenerator.getInstance.overload('java.lang.String').implementation = function (var0) {
			send("[*] KeyGenerator.getInstance called with algorithm: " + var0 + "\n");
			return this.getInstance(var0);
		};

		keyGenerator.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (var0, var1) {
			send("[*] KeyGenerator.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};

		keyGenerator.getInstance.overload('java.lang.String', 'java.security.Provider').implementation = function (var0, var1) {
			send("[*] KeyGenerator.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};

		var keyPairGenerator = Java.use("java.security.KeyPairGenerator");
		keyPairGenerator.getInstance.overload('java.lang.String').implementation = function (var0) {
			send("[*] GetPairGenerator.getInstance called with algorithm: " + var0 + "\n");
			return this.getInstance(var0);
		};

		keyPairGenerator.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (var0, var1) {
			send("[*] GetPairGenerator.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};

		keyPairGenerator.getInstance.overload('java.lang.String', 'java.security.Provider').implementation = function (var0, var1) {
			send("[*] GetPairGenerator.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};

		var messageDigest = Java.use("java.security.MessageDigest");
		messageDigest.getInstance.overload('java.lang.String').implementation = function (var0) {
			send("[*] MessageDigest.getInstance called with algorithm: " + var0 + "\n");
			return this.getInstance(var0);
		};

		messageDigest.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (var0, var1) {
			send("[*] MessageDigest.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};

		messageDigest.getInstance.overload('java.lang.String', 'java.security.Provider').implementation = function (var0, var1) {
			send("[*] MessageDigest.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};

		var secretKeyFactory = Java.use("javax.crypto.SecretKeyFactory");
		secretKeyFactory.getInstance.overload('java.lang.String').implementation = function (var0) {
			send("[*] SecretKeyFactory.getInstance called with algorithm: " + var0 + "\n");
			return this.getInstance(var0);
		};

		secretKeyFactory.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (var0, var1) {
			send("[*] SecretKeyFactory.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};

		secretKeyFactory.getInstance.overload('java.lang.String', 'java.security.Provider').implementation = function (var0, var1) {
			send("[*] SecretKeyFactory.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};

		var signature = Java.use("java.security.Signature");
		signature.getInstance.overload('java.lang.String').implementation = function (var0) {
			send("[*] Signature.getInstance called with algorithm: " + var0 + "\n");
			return this.getInstance(var0);
		};

		signature.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (var0, var1) {
			send("[*] Signature.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};

		signature.getInstance.overload('java.lang.String', 'java.security.Provider').implementation = function (var0, var1) {
			send("[*] Signature.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};

		var cipher = Java.use("javax.crypto.Cipher");
		cipher.getInstance.overload('java.lang.String').implementation = function (var0) {
			send("[*] Cipher.getInstance called with algorithm: " + var0 + "\n");
			return this.getInstance(var0);
		};

		cipher.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (var0, var1) {
			send("[*] Cipher.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};

		cipher.getInstance.overload('java.lang.String', 'java.security.Provider').implementation = function (var0, var1) {
			send("[*] Cipher.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};

		var mac = Java.use("javax.crypto.Mac");
		mac.getInstance.overload('java.lang.String').implementation = function (var0) {
			send("[*] Mac.getInstance called with algorithm: " + var0 + "\n");
			return this.getInstance(var0);
		};

		mac.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (var0, var1) {
			send("[*] Mac.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};

		mac.getInstance.overload('java.lang.String', 'java.security.Provider').implementation = function (var0, var1) {
			send("[*] Mac.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};

	});
});