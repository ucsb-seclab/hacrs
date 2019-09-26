function resetvm() {
    var cf = confirm("Restart Session - Please Confirm. Prior progress will be considered.")
    if (cf){
        document.location.reload();
    }
}

function aborttasklet() {
    var cf = confirm("Aborting Tasklet - Please Confirm. You will not be able to pick up work on this tasklet again.")
    if (cf){
        var data = {
            'worker_id': worker_id,
            'tid': tasklet_id,
            'setstatus': 'ABORT'
        }

        var url = "/update_tasklet_status/";
        $.post( url, data)
        .done(function( e ) {
            alert( "Tasklet aborted");
            document.location.href = '/pick_tasklet/' + difficulty + "/?assignmentId=" + assignmentID + "&hitId=" + hit_id + "&workerId=" + worker_id;
        });
    }
}

function vm_loadstate (inputstring) {
    var cf = confirm("Restart Session with previous input - Please Confirm. Prior progress will be considered.")
    if (cf){
        var url = document.location.href.split('#')[0];
        var separator = (url.indexOf("?")===-1) ? "?" : "&";
        document.location.href = url + separator + "showinput=" + escape(inputstring);
    }
}

var interv = false;

$(document).ready(function() {

    // Do not show VNC window yet.
    if (! ( assignmentID == ""  || assignmentID == "ASSIGNMENT_ID_NOT_AVAILABLE")) {
        var iframe = document.getElementById('viewframe');
        iframe.src = "///" + document.location.hostname + ":{{vrport}}?passwd={{password}}"
        interv = setInterval(checkIframe, 1000);
    }

    adjustSubmitButton();

    show_hide('#PrograminstructionBody', '#ProgramcollapseTrigger', false);
    show_hide('#SeedinstructionBody', '#SeedcollapseTrigger', false);
    show_hide('#NotesinstructionBody', '#NotescollapseTrigger', false);

    if (( typeof tasktype !== 'undefined') && tasktype == 'SEEK'){
        show_hide('#TargetinstructionBody', '#TargetcollapseTrigger', false);
    }

    initialize_notes();
    populate_notes(tasklet_id );

    // end expand/collapse
});

function clear_notes( ) {
    $('#noteslist').empty();
}

function populate_notes(tasklet_id) {
    var notes_url = "/get_notes/" + tasklet_id + "/";

    clear_notes( );

    $.get( notes_url, function( data ) { 
        add_notes(data['notes']);
    }, "json"); 
}

function initialize_notes() {
    var btn = $("#notessubmitbtn");
    btn.click( function() { send_note(); });

}

function add_notes(notes) {
    var nd = $('#notesdisplay-placeholder');
    if ( nd !== undefined ) {
        nd.remove();
    }
    var dt = $('<dt/>');
    var dd = $('<dd/>');
    for ( var i = 0; i < notes.length ; i++) {
        dt = $('<dt/>');
        dd = $('<dd/>');
        dt.text( notes[i]['name'] +  ' ' + notes[i]['timestamp']);
        dd.text( notes[i]['note']);
        $('#noteslist').append(dt.clone());
        $('#noteslist').append(dd.clone());
    }
}

function send_note( ) {
    var send_notes_url = '/add_note/' + tasklet_id + "/";
    var note = $("#notesdata").val();
    if ( note.length == 0 ){
        return;
    }

    var post = $.post( send_notes_url, {'note': note}, function (data) {
        $("#notesdata").val('');
        populate_notes(tasklet_id);
    }).fail(function() {
        alert('Issue submitting note - are you authenticated?');
    });
}

function show_hide(instruction, trigger, hidecontent) {
    // Instructions expand/collapse
    var content = $(instruction);
    var trigger = $(trigger);
    if ( hidecontent ) {
        content.hide();
        $(trigger).find('.collapse-text').text('(Click to expand)');
    }
    trigger.click(function(){
        content.toggle();
        var isVisible = content.is(':visible');
        if(isVisible){
            $(trigger).find('.collapse-text').text('(Click to collapse)');
            }else{
            $(trigger).find('.collapse-text').text('(Click to expand)');
        }
    });
}


function checkIframe() {
    var iframe = document.getElementById('viewframe');
    var loadframe = document.getElementById('loadframe');
    if ( iframe.contentWindow.length == 0 ) {
        console.log('issue');
        iframe.src = IframeURL;
    } else {
        console.log('OK!');
        clearInterval(interv);
        iframe.style.display = "";
        loadframe.style.display = "none";
    }
}

