Java.perform(function () {
    var Log = Java.use('android.util.Log');

    // Hook into the v() method
    Log.v.overload('java.lang.String', 'java.lang.String').implementation = function (tag, msg) {
        send('[Log.v] Tag: ' + tag + ', Message: ' + msg);
        return this.v(tag, msg);
    };

    // Hook into the v() method with Throwable
    Log.v.overload('java.lang.String', 'java.lang.String', 'java.lang.Throwable').implementation = function (tag, msg, tr) {
        send('[Log.v] Tag: ' + tag + ', Message: ' + msg + ', Throwable: ' + tr.toString());
        return this.v(tag, msg, tr);
    };

    // Hook into the d() method
    Log.d.overload('java.lang.String', 'java.lang.String').implementation = function (tag, msg) {
        send('[Log.d] Tag: ' + tag + ', Message: ' + msg);
        return this.d(tag, msg);
    };

    // Hook into the d() method with Throwable
    Log.d.overload('java.lang.String', 'java.lang.String', 'java.lang.Throwable').implementation = function (tag, msg, tr) {
        send('[Log.d] Tag: ' + tag + ', Message: ' + msg + ', Throwable: ' + tr.toString());
        return this.d(tag, msg, tr);
    };

    // Hook into the i() method
    Log.i.overload('java.lang.String', 'java.lang.String').implementation = function (tag, msg) {
        send('[Log.i] Tag: ' + tag + ', Message: ' + msg);
        return this.i(tag, msg);
    };

    // Hook into the i() method with Throwable
    Log.i.overload('java.lang.String', 'java.lang.String', 'java.lang.Throwable').implementation = function (tag, msg, tr) {
        send('[Log.i] Tag: ' + tag + ', Message: ' + msg + ', Throwable: ' + tr.toString());
        return this.i(tag, msg, tr);
    };

    // Hook into the w() method
    Log.w.overload('java.lang.String', 'java.lang.String').implementation = function (tag, msg) {
        send('[Log.w] Tag: ' + tag + ', Message: ' + msg);
        return this.w(tag, msg);
    };

    // Hook into the w() method with Throwable
    Log.w.overload('java.lang.String', 'java.lang.String', 'java.lang.Throwable').implementation = function (tag, msg, tr) {
        send('[Log.w] Tag: ' + tag + ', Message: ' + msg + ', Throwable: ' + tr.toString());
        return this.w(tag, msg, tr);
    };

    // Hook into the e() method
    Log.e.overload('java.lang.String', 'java.lang.String').implementation = function (tag, msg) {
        send('[Log.e] Tag: ' + tag + ', Message: ' + msg);
        return this.e(tag, msg);
    };

    // Hook into the e() method with Throwable
    Log.e.overload('java.lang.String', 'java.lang.String', 'java.lang.Throwable').implementation = function (tag, msg, tr) {
        send('[Log.e] Tag: ' + tag + ', Message: ' + msg + ', Throwable: ' + tr.toString());
        return this.e(tag, msg, tr);
    };

    // Hook into the wtf() method
    Log.wtf.overload('java.lang.String', 'java.lang.String').implementation = function (tag, msg) {
        send('[Log.wtf] Tag: ' + tag + ', Message: ' + msg);
        return this.wtf(tag, msg);
    };

    // Hook into the wtf() method with Throwable
    Log.wtf.overload('java.lang.String', 'java.lang.String', 'java.lang.Throwable').implementation = function (tag, msg, tr) {
        send('[Log.wtf] Tag: ' + tag + ', Message: ' + msg + ', Throwable: ' + tr.toString());
        return this.wtf(tag, msg, tr);
    };
});
