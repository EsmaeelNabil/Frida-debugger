Java.perform(function () {
    let Activity = Java.use('androidx.appcompat.app.AppCompatActivity');

    Activity.onCreate.implementation = function (savedInstanceState) {
        send('[+] Activity.onCreate : ' + this.$className);
        // Call the original onCreate method
        this.onCreate(savedInstanceState);
    };
    
    Activity.onDestroy.implementation = function () {
        send('[+] Activity.onDestroy : ' + this.$className);
        // Call the original onDestroy method
        this.onDestroy();
    };
    
});