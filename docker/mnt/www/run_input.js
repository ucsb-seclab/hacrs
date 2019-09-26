// Forwards showinput parameter as keystrokes to the 
// VNC window. We poll whether the sindow status is 'normal'
// and then wait another two seconds before sending them.

function send_input_keys(input) {
    if ( rfb._rfb_state === 'normal' ) {
        for (var i = 0; i < input.length; i++) {
            rfb.sendKey(input.charCodeAt(i));
        }
    } else {
        console.log('Rescheduling input (state not "normal")');
        setTimeout(send_input_keys.bind(null, input), 1000);
    }   
}

function is_input_ready(input){
    if ( rfb._rfb_state === 'normal' ) {
        setTimeout(send_input_keys.bind(null, input), 4000);
    } else {
		setTimeout(is_input_ready.bind(null, input), 1000);
	}

}

function check_for_input( ) {
	var uri = URI(document.location.href);
    if ( uri.hasQuery('showinput') && uri.query(true).showinput !== "" ) {
		setTimeout(is_input_ready.bind(null, uri.query(true).showinput), 1000);
    }
}

check_for_input();

