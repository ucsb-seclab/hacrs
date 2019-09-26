//var stats = {"total_transitions": 2135, "missing_transitions": 2135, "new_transitions": 114, "coverage_improvement": 5};

// Fetch JSON
function updatestats(){
    
}

// Reset values to 0
function initstats(){
    if (assignmentID == "" || assignmentID == "ASSIGNMENT_ID_NOT_AVAILABLE") {
        console.log("Not registering fetch_results");
        return;
    }

    setInterval(
        fetch_results.bind(null, tasklet_id, assignmentID, worker_id, hit_id),
        2000);
}

function update_results(dat) {
    var res = JSON.parse(dat);
    if ( Object.keys(res).length == 0 ) {
        // There was an issue fetching the data
        //console.log(res);
        return;
    }
    console.log(dat);
    setValue('transitions', res['total_transitions']);
    setValue('prevtransitions', res['previous_transitions']);
    updateno('foundtransitions', res['new_transitions']);
    handle_payout(res['missing_transitions'], res['new_transitions'], res['next_payout'], res['next_transition'], res['min_payout'], res['curr_payout']);
}

function handle_payout (missing, new_trans, next_payout, next_transition, min_payout, curr_payout) {
    adjustSubmitButton(curr_payout);

    if ( min_payout < next_payout ) {
        // For internal tracking
        submit_update();

        updateno('currpayoutvalue', curr_payout);

        $('#payoutvaluemsg')[0].textContent = 'HIT target payout (with Bonus):';
        $("#payoutdone")[0].textContent = 'Congrats!! - Well done. Started stretch goal.';
        $('#payoutmsg')[0].textContent = "Next Bonus Target:";
    }
    updateno('nextfunctions', next_transition);
    updateno('payoutvalue', next_payout);
}

function setValue(elemname, v) {
    $('#'+elemname)[0].textContent = v;
}


var globaltimeoutref = {};

function clearhighlight(elemname){
    $('#'+elemname).removeClass('highlighted');
}

function updateno(elemname, newval) {
    var oldval = parseFloat( $('#'+elemname)[0].textContent,10);
    if ( newval !== oldval ) {
        $('#'+elemname).effect( "bounce", {times:5}, 700 )
        $('#'+elemname)[0].textContent = newval;
        $('#'+elemname).addClass('highlighted');
        if ( elemname in globaltimeoutref && globaltimeoutref[elemname] != false ) {
            clearTimeout(globaltimeoutref[elemname]);
        }
        globaltimeoutref[elemname] = setTimeout(clearhighlight.bind(null, elemname), 3000);
    }
}

$(document).ready( function() {
    initstats();
});
