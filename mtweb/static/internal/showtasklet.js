$(document).ready(function() {
    var table = $('#turkinfos-table');

    $("#tid").text(tasklet['id']);
    $("#tprogram").text(tasklet['program']);
    $("#ttype").text(tasklet['type']);
    $("#tamount").text("$ " + tasklet['amount']);

    $("#startbtn").click( function (e) {
                var rnd = Math.floor(Math.random() * 100000);
                window.open('/tasklet/' + tasklet['id'] + '/' + '?assignmentId=picked_' + rnd + '&hitId=picked_' + rnd + '&workerId=internal_' + username );
        });

} );


