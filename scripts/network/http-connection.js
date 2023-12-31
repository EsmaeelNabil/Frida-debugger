setImmediate(function() {
	Java.perform(function() {

		var url = Java.use("java.net.URL");

		url.$init.overload('java.lang.String').implementation = function (var0) {
			send("[*] Created new URL with value: " + var0 +"\n");
			return this.$init(var0);
		};

		url.openConnection.overload().implementation = function () {
			send("[*] Created new URL connection\n");
			return this.openConnection();
		};

		url.openConnection.overload('java.net.Proxy').implementation = function (var0) {
			send("[*] Created new URL connection with proxy value: " + var0 +"\n");
			return this.openConnection(var0);
		};


		var URLConnection = Java.use("java.net.URLConnection");

		URLConnection.connect.implementation = function () {
			send("[*] Connect called.\n");
			this.connect();
		};

		URLConnection.getContent.overload().implementation = function () {
			var content = this.getContent();
			send("[*] Get content called. Content: " + content + "\n");
			return content;
		};

		URLConnection.getContentType.implementation = function () {
			var contentType = this.getContentType();
			send("[*] Get content type called. Content type: " + contentType + "\n");
			return contentType;
		};

		URLConnection.getContentLength.implementation = function () {
			var contentLength = this.getContentLength();
			send("[*] Get content length called. Content length: " + contentLength + "\n");
			return contentLength;
		};

		URLConnection.getContentLengthLong.implementation = function () {
			var contentLengthLong = this.getContentLengthLong();
			send("[*] Get content length long called. Content length long: " + contentLengthLong + "\n");
			return contentLengthLong;
		};

		URLConnection.getContentEncoding.implementation = function () {
			var contentEncoding = this.getContentEncoding();
			send("[*] Get content encoding called. Content encoding: " + contentEncoding + "\n");
			return contentEncoding;
		};

		URLConnection.getDate.implementation = function () {
			var contentDate = this.getDate();
			send("[*] Get date called. Date: " + contentDate + "\n");
			return contentDate;
		};

		URLConnection.getExpiration.implementation = function () {
			var contentExpiration = this.getExpiration();
			send("[*] Get expiration called. Expiration: " + contentExpiration + "\n");
			return contentExpiration;
		};

		URLConnection.getLastModified.implementation = function () {
			var lastModified = this.getLastModified();
			send("[*] Get last modified called. Value: " + lastModified + "\n");
			return lastModified;
		};

		URLConnection.getInputStream.implementation = function () {
			send("[*] Get input stream called.\n");
			return this.getInputStream;
		};

		URLConnection.setDoOutput.overload('boolean').implementation = function (var0) {
			send("[*] URLConnection.setDoOutput called with value: " + var0 + ".\n");
			this.setDoOutput(var0);
		};

		URLConnection.setDoInput.overload('boolean').implementation = function (var0) {
			send("[*] URLConnection.setDoInput called with value: " + var0 + ".\n");
			this.setDoInput(var0);
		};

		var httpURLConnection = Java.use("com.android.okhttp.internal.huc.HttpURLConnectionImpl");

		httpURLConnection.setRequestMethod.overload('java.lang.String').implementation = function (var0) {
			send("[*] Set request method called: " + var0 + "\n");
			this.setRequestMethod(var0);
		};

		httpURLConnection.setRequestMethod.overload('java.lang.String').implementation = function (var0) {
			send("[*] Set request method called: " + var0 + "\n");
			this.setRequestMethod(var0);
		};	

		httpURLConnection.connect.implementation = function () {
			send("[*] Connect called.\n");
			this.connect();
		};

		httpURLConnection.disconnect.implementation = function () {
			send("[*] Disconnect called.\n");
			this.disconnect();
		};

		httpURLConnection.getResponseCode.implementation = function () {
			var responseCode  = this.getResponseCode();
			send("[*] Get response code called: " + responseCode + "\n");
			return responseCode;
		};

		var httpsURLConnection = Java.use("com.android.okhttp.internal.huc.HttpsURLConnectionImpl");

		httpsURLConnection.setRequestMethod.overload('java.lang.String').implementation = function (var0) {
			send("[*] Set request method called: " + var0 + "\n");
			this.setRequestMethod(var0);
		};

		httpsURLConnection.connect.implementation = function () {
			send("[*] Connect called.\n");
			this.connect();
		};

		httpsURLConnection.disconnect.implementation = function () {
			send("[*] Disconnect called.\n");
			this.disconnect();
		};

		httpsURLConnection.getResponseCode.implementation = function () {
			var responseCode  = this.getResponseCode();
			send("[*] Get response code called: " + responseCode + "\n");
			return responseCode;
		};

		httpsURLConnection.setRequestProperty.overload('java.lang.String', 'java.lang.String').implementation = function (var0, var1) {
			send("[*] URLConnection.setRequestProperty called with key: " + var0 + " and value: " + var1 + ".\n");
			this.setRequestProperty(var0, var1);
		};
	});
});