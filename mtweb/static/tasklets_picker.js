function initialize() {
    var btn = $('#submitbtn');
    btn.click ( function (e) {
        navigate_to_task ($('#pickform').serializeArray());
    });
}

function navigate_to_task(arr) {
    if ( arr[0].name === 'difficulty' ) {
        var difficulty = arr[0].value;
        var ttype = arr[1].value;
    } else {
        var ttype = arr[0].value;
        var difficulty = arr[1].value;
    }

    var url = '/pick_tasklet/' + ttype +'/' + difficulty + '/' + username;
    window.location.href = url;
}



$(document).ready( function() {
    initialize();
});
