/**
 * Sets the assignment ID in the form. Defaults to use mturk_form and submitButton
 */ 
function adjustSubmitButton (currpayout ) {
  var button_name = "submitButton";
  var btn = document.getElementById(button_name);

  if (( typeof tasktype !== 'undefined') && tasktype == 'SEEK'){
      btn.disabled = false; 
      btn.value = "Submit here once the output matches the target description. Not qualifying submissions will be rejected.";
      return;
  }

  if (assignmentID.startsWith('qual-'))  {
      btn.disabled = true; 
      btn.value = "This is a sample task, no need to Submit.";

  } else if (assignmentID == "ASSIGNMENT_ID_NOT_AVAILABLE" || assignmentID == "" ) { 
    // If we're previewing, disable the button and give it a helpful message
    if (btn) {
      btn.disabled = true; 
      btn.value = "You must ACCEPT the HIT before you can submit the results.";
    } 
  } else if ( typeof(currpayout) == 'undefined' || currpayout == 0) {
      btn.disabled = true; 
      btn.value = "Submit here once you reached enough functions.";
  } else {
      btn.disabled = false; 
      btn.value = "Submit when done pursuing stretch goals.";
  }

  // Overload default submit behavior
  //$('#resultform').unbind('submit').bind('submit',(function(e) {
  //  e.preventDefault();
  //  submit_update();
  //  return false;
  //}));
}

function submit_to_mturk () {
    $.post(amazon_host, $('#resultform').serialize(), function (data) {
        alert('Data submitted to Amazon, forwarding to next tasklet! ' + JSON.stringify(data));
        document.location.href = '/pick_tasklet/' + difficulty + "/?assignmentId=" + assignmentID + "&hitId=" + hit_id + "&workerId=" + worker_id;
    }).fail( function (e) {
        alert('Failed submitting tasklet, please retry and contact our team if the error persists. Are you logged in at Mechanical Turk?');
    });
}

function submit_update () {
    // Don't keep track of assignments for pro turkers
    if ( worker_id.indexOf('internal') > -1 ) {
        return;
    }
    var data = {
        'worker_id': worker_id,
        'tid': tasklet_id,
        'setstatus': 'COMPLETE'
    }

    var url = "/update_tasklet_status/";
    $.post( url, data)
    .done(function( e ) {
        console.log( "Tasklet submitted! ");
        //submit_to_mturk();
    }).fail( function (e) {
        alert('Failed submitting tasklet internally, please retry and contact our team if the error persists.');
    });
}



function fetch_results(tid, assignmentid, workerid, hid) {

    if (assignmentid == "" || assignmentid == "ASSIGNMENT_ID_NOT_AVAILABLE") {
        return;
    }

    if (( typeof tasktype !== 'undefined') && tasktype == 'SEEK'){
        return;
    }

    var url = "/get_results/"+tid+"/"+assignmentid+"/"+workerid+"/"+hid+"/"
    $.get( url, function( data ) {
        $( ".result" ).html( data );
            update_results(data);
    });

}
