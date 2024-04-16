Java.perform(function() {
    var Fragment = Java.use('androidx.fragment.app.Fragment');

    Fragment.onCreate.overload('android.os.Bundle').implementation = function(savedInstanceState) {
        send('[life.js] Fragment : [ ' + this.getClass().getName()+' ] ' + 'onCreate' );
        this.onCreate(savedInstanceState);
    };

    Fragment.onStart.implementation = function() {
        send('[life.js] Fragment : [ ' + this.getClass().getName()+' ] ' + 'onStart' );
        	this.onStart();
    };

    Fragment.onResume.implementation = function() {
        send('[life.js] Fragment : [ ' + this.getClass().getName()+' ] ' + 'onResume' );
        this.onResume();
    };

    Fragment.onStop.implementation = function() {
        send('[life.js] Fragment : [ ' + this.getClass().getName()+' ] ' + 'onStop' );
        this.onStop();
    };

    Fragment.onPause.implementation = function() {
        send('[life.js] Fragment : [ ' + this.getClass().getName()+' ] ' + 'onPause' );
        this.onPause();
    };

    Fragment.onDestroy.implementation = function() {
        send('[life.js] Fragment : [ ' + this.getClass().getName()+' ] ' + 'onDestroy' );
        this.onDestroy();
    };

});
