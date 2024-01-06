send("hook_okhttp3...");
Java.perform(function () {
    var ByteString = Java.use("com.android.okhttp.okio.ByteString");
    var Buffer = Java.use("com.android.okhttp.okio.Buffer");
    var Interceptor = Java.use("okhttp3.Interceptor");
    var MyInterceptor = Java.registerClass({
        name: "okhttp3.MyInterceptor",
        implements: [Interceptor],
        methods: {
            intercept: function (chain) {
                var request = chain.request();
                try {
                    send("MyInterceptor.intercept onEnter:", request, "\nrequest headers:\n", request.headers());
                    var requestBody = request.body();
                    var contentLength = requestBody ? requestBody.contentLength() : 0;
                    if (contentLength > 0) {
                        var BufferObj = Buffer.$new();
                        requestBody.writeTo(BufferObj);
                        try {
                            send("\nrequest body String:\n", BufferObj.readString(), "\n");
                        } catch (error) {
                            try {
                                send("\nrequest body ByteString:\n", ByteString.of(BufferObj.readByteArray()).hex(), "\n");
                            } catch (error) {
                                send("error 1:", error);
                            }
                        }
                    }
                } catch (error) {
                    send("error 2:", error);
                }
                var response = chain.proceed(request);
                try {
                    send("MyInterceptor.intercept onLeave:", response, "\nresponse headers:\n", response.headers());
                    var responseBody = response.body();
                    var contentLength = responseBody ? responseBody.contentLength() : 0;
                    if (contentLength > 0) {
                        send("\nresponsecontentLength:", contentLength, "responseBody:", responseBody, "\n");

                        var ContentType = response.headers().get("Content-Type");
                        send("ContentType:", ContentType);
                        if (ContentType.indexOf("video") == -1) {
                            if (ContentType.indexOf("application") == 0) {
                                var source = responseBody.source();
                                if (ContentType.indexOf("application/zip") != 0) {
                                    try {
                                        send("\nresponse.body StringClass\n", source.readUtf8(), "\n");
                                    } catch (error) {
                                        try {
                                            send("\nresponse.body ByteString\n", source.readByteString().hex(), "\n");
                                        } catch (error) {
                                            send("error 4:", error);
                                        }
                                    }
                                }
                            }

                        }

                    }

                } catch (error) {
                    send("error 3:", error);
                }
                return response;
            }
        }
    });
    var ArrayList = Java.use("java.util.ArrayList");
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    send(OkHttpClient);
    OkHttpClient.$init.overload('okhttp3.OkHttpClient$Builder').implementation = function (Builder) {
        send("OkHttpClient.$init:", this, Java.cast(Builder.interceptors(), ArrayList));
        this.$init(Builder);
    };

    var MyInterceptorObj = MyInterceptor.$new();
    var Builder = Java.use("okhttp3.OkHttpClient$Builder");
    send(Builder);
    Builder.build.implementation = function () {
        this.interceptors().clear();
        //var MyInterceptorObj = MyInterceptor.$new();
        this.interceptors().add(MyInterceptorObj);
        var result = this.build();
        return result;
    };

    Builder.addInterceptor.implementation = function (interceptor) {
        this.interceptors().clear();
        //var MyInterceptorObj = MyInterceptor.$new();
        this.interceptors().add(MyInterceptorObj);
        return this;
        //return this.addInterceptor(interceptor);
    };


});
