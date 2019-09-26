
INTERACTION_CACHE={};
INTERACTION_CACHE['afl'] = {};
INTERACTION_CACHE['standard'] = {};

function fetch_interaction(i, seedid, seed_type) {
    var url = '/get_interaction/' + program_name + '/' + seedid;

    $.get( url, function( data ) { 
        $( ".result" ).html( data );
		//update_results(data);
        parsed_data = JSON.parse(data);
        console.log("Parsed data start");
        console.log(parsed_data.toString());
        console.log("Parsed data end");
		INTERACTION_CACHE[seed_type][i] = parsed_data; //data_filter(parsed_data);
		showConstraints(INTERACTION_CACHE[seed_type][""+i], seed_type);
    }); 



}

function show_interaction(i, jseeds, seed_type) {
    if ( typeof ( INTERACTION_CACHE[seed_type][""+i]) === "undefined" ) {
        fetch_interaction(i.toString(), jseeds[i], seed_type);
    } else {
		showConstraints(INTERACTION_CACHE[seed_type][i.toString()], seed_type);
	}
}


$(document).ready(
    function() {
        initializeSeeds(seeds, 'standard');
        if ( tasktype === 'DRILL' ) {
            initializeSeeds(afl_seeds, 'afl');
        }
    }
);

function initializeSeeds(seeds, seed_type)  {
    try {
        var dec = decodeURI(seeds); //.replace( new RegExp(/&amp;nbsp;/, 'g') , ' ');
        //dec = dec.replace( new RegExp(/&amp;gt;/, 'g') , '>');
        //dec = dec.replace( new RegExp(/&amp;lt;/, 'g') , '<');
        var jseeds = JSON.parse(dec);
        //console.log(jseeds);

        for ( var i = 0; i < jseeds.length; i++) {
            var a = $('<a href="javascript:void(0)"></a>').text(i+1).click(show_interaction.bind(null, i, jseeds, seed_type));
            var span = $('<span> </span>').append(a).append('<span> </span>');
            $("#sliderlinks-" + seed_type).append(span);
        }

        show_interaction(0, jseeds, seed_type);

    } catch(e) {
        console.log("Issue");
    }
}


/////////////////////////////////////////////////

function isIgnoreInput (c) {
    if ( c.substr(1).startsWith('\\x') ) {
        return true;
    }
    var ignorecharacters = [];
    ignorecharacters.push('\\r');
    return ignorecharacters.includes(c.substr(1, c.length-2));
}

function substr_match_len(a, b) {
    return b[1] - a[1];
}

function get_or_create_blank_tooltip(index)
{
    var tooltip_id = 'sample-tooltip-' + index.toString();
    var tooltip = $('div#' + tooltip_id);
    if (tooltip.length == 0)
    {
        tooltip = $('<div class="sample-tooltip" id="' + tooltip_id + '"/>');
    }
    else
    {
        tooltip.empty();
    }
    tooltip.attr('id', tooltip_id);
    return tooltip;
}

function make_hardcoded_options_table(hardcoded_options_list)
{
    var table = $('<table/>').attr('align', 'center').width('100%');

    //var colgroup = $('<colgroup/>');
    //colgroup.append($('<col>'));

    var header_row = $('<tr/>');
    //header_row.append($('<th/>').text('Likely'));
    header_row.append($('<th/>').text('Value'));
    table.append(header_row);

    //var prev_similarity = hardcoded_options_list.length > 0 ? hardcoded_options_list[0] : -1;
    for (var bin_opt_idx = 0; bin_opt_idx < hardcoded_options_list.length; bin_opt_idx++) {
        var option = hardcoded_options_list[bin_opt_idx];
        var data_val = $('<td/>').text(option[0]);
        var data_likelihood = $('<td/>').text(option[1].toString());
        var row = $('<tr/>').append(data_likelihood).append(data_val);
        table.append(row)
    }
    return table
}

/*
function constructTooltip(interaction_data, i)
{
    var cur_interaction = interaction_data[i];

    var tooltip = get_or_create_blank_tooltip(i);

    var hardcoded_options_list = cur_interaction['compartment']['other_options']['binary_string_options'].sort(substr_match_len);
    var generated_options = cur_interaction['compartment']['other_options']['generated_options'];

    if (hardcoded_options_list.length > 0) {
        tooltip.append($('<h3/>').text('Educated guesses'));
        //tooltip.append(make_hardcoded_options_table(hardcoded_options_list));
        hardcoded_options = [];
        for (i = 0; i < hardcoded_options_list.length; i++)
        {
            hardcoded_options.push(hardcoded_options_list[i])
        }
        getOutputList(hardcoded_options_list)
    }

    if (generated_options.length > 0) {
        tooltip.append($("<h3/>").text('Brute force');
        tooltip.append(getOutputList(generated_options));
    }

    return tooltip;
}*/

function populate_other_options_display(interaction_data, i)
{
    var cur_interaction = interaction_data[i];

    var targetHeight = Math.max($('#other-option-strings-display').height(), 400);
    var other_options_display = $('#other-option-strings-display');
    other_options_display.empty();
    other_options_display.css('height', targetHeight);

    var hardcoded_options_list = cur_interaction['compartment']['other_options']['binary_string_options'].sort(substr_match_len);
    var generated_options = cur_interaction['compartment']['other_options']['generated_options'];

    if (hardcoded_options_list.length > 0) {
        other_options_display.append($('<h3/>').text('Educated guesses'));
        hardcoded_options = [];
        for (i = 0; i < hardcoded_options_list.length; i++)
        {
            hardcoded_options.push(hardcoded_options_list[i][0])
        }
        other_options_display.append(getOutputList(hardcoded_options));
        //other_options_display.append(make_hardcoded_options_table(hardcoded_options_list));
    }

    if (generated_options.length > 0) {
        other_options_display.append($('<h3/>').text('Brute force'));
        other_options_display.append(getOutputList(generated_options));
    }
}

function showConstraints(data, seed_type ) {
	var previous_input = ""; // track all the input chars so far
	var dest = $('<div class="sampledata"/>'); // this is the DOM node we're going to be writing to
    var in_idx = 0, out_idx = 0;

	for (var i = 0; i in data; i++) {
        var c_type = data[i].type;
        var c_val = data[i].value;
        var is_input = c_type === 'output'; // Note that input/output are swapped in the API for whatever reason

        // catch a class of errors
        if (!is_input && c_type !== 'input') {
            console.log("data type issue: " + c_type);
            continue;
        }

        // Convert the character into something that can be displayed
        var c_val_printable;
        var c_val_special;
        if (c_val === '\n') {
            c_val_printable = String.fromCharCode(0x21b5);
            c_val_special = false;
        } else if (c_val.charCodeAt(0) < 0x20) {
            c_val_printable = '^' + String.fromCharCode(0x40 + c_val.charCodeAt(0));
            c_val_special = true;
        } else {
            c_val_printable = c_val;
            c_val_special = false;
        }

        // Create the initial span for the character
        var span = $('<span/>');
        span.text(c_val_printable);
        if (c_val_special) {
            span.addClass('special-char');
        }
        dest.append(span);

        // process the span and the character metadata more if needed
        if (!is_input) {
            span.addClass('sampleoutput');
            span.attr('id', "output-" + out_idx++);
        } else {
			previous_input += c_val;

            span.addClass('sampleinput');
            span.attr('id', "input-" + in_idx++);
            span.attr('title', "");
			span.click(vm_loadstate.bind(null, previous_input));

            if ( typeof data[i]['other_options'] === 'undefined' ) {
                //console.log('skip: ' + i);
                continue;
            }

            span.hover(populate_other_options_display.bind(null, data, i));

            //var tooltip = constructTooltip(data, i);
            //span.tooltip({content: tooltip});

            span.addClass('deviation-' + getConstraintType(data[i]['other_options']));
        }

        if (c_val === "\n") {
            dest.append($('<br>'));
        }
	}

    var destdest = $('#sliderdisplay-' + seed_type);
    destdest.text('');
    destdest.empty();

    var table = $('<table/>').attr('id', 'interaction-plus-strings-table');
    var row = $('<tr/>');
    var col_interaction = $('<td/>').attr('id', 'interactions-column').height(400);
    var col_strings = $('<td/>').attr('id', 'other-option-strings-column');
    var strings_scroll = $('<div/>').attr('id', 'other-option-strings-display');

    make_other_options_tutorial(strings_scroll);

    col_interaction.append(dest);
    col_strings.append(strings_scroll);

    row.append(col_interaction);
    row.append(col_strings);
    table.append(row);
    destdest.append();
    destdest.append(table);
}

function make_other_options_tutorial(sidebar)
{
    sidebar.empty();
    sidebar.append($('<h3/>').text("Possible options"));
    sidebar.append($("<p/>").text("Whenever you hover over parts of input in an interaction we will show you other possible " +
                    "options for that part of the input. These were recovered by our program analysis and might " +
                    "not be correct."));

    var explanation = $("<p/>").text("The options are divided into two groups: Educated guesses and brute force. ");
    explanation.append($("<br>")).append($("<br>"));
    explanation.append("Educated guesses are extracted from the program itself and sorted top-to-bottom by " +
                        "the likelihood of their appearance in that position. Your job is to take these guesses " +
                        "and figure out which ones fit the current situation.");

    explanation.append($("<br>")).append($("<br>"));

    explanation.append("Brute force guesses were generated directly by our AI and are provided as a guideline " +
                        "for the type of input that is expected at the hovered position. For example, they can " +
                        "give you a hint for whether the program is expecting numbers at some point.");

    explanation.append($("<br>")).append($("<br>"));

    explanation.append("Unfortunately, we can not provide options in all cases, if none are displayed that " +
        "means that our analysis was not able to extract any.");

    sidebar.append(explanation);
}

function getOutputList( strings ) {

    var ul = $('<ul/>');
    
    for ( var k = 0; k < strings.length; k++ ) {
        var li = $('<li/>');
        li.text(strings[k]);
        ul.append(li);
    }
    return ul;
}

function otherOptionsCmp(c1, c2) {
	if ( c1.length !== c2.length ) {
		console.log('options mismatch');
		return false;
	}
	for ( var i = 0; i < c1.length; i++ ) {
		if ( c1[i]['constraints'].length !== c2[i]['constraints'].length ) {
			console.log('constraint mismatch');
			return false;
		}
	}
    // possible TODO further compare the contents of the constraints
	return true;
}


function parseConstraint(c) {
	// multiple variables
	if ( ! ( c.startsWith('(input @ [') && c.endsWith(')') ) ) {
		//console.log('Skipping: ' + c);
		return false;
	}
	
	var v = c.match(/^\(input @ \[(\d+)\] ([=!<>]+) (.*)\)/)
	return {
		'at': v[1],
		'cmp': v[2],
		'value': v[3]
	}
}

function beautifyInputs(cmp, value) {
    return beautifyCMP(cmp) + beautifyValue(value);
}

function beautifyCharacter(value) {
    if ( value === "\\n") {
        return '<br>';
    }
    return value;
}

function beautifyValue(value) {
    if ( value === "'\\n'") {
        // \n => &#x23CE;
        return 'ENTER key';
    } else if ( value === "'\\t'") {
        return 'Tabulator key';
    } else if ( value === "' '") {
        return 'SPACE key';
    } else {
        return value;
    }
}

function beautifyCMP(cmp) {
    if ( cmp === '=' ) {
        return '';
    } else if ( cmp === '!=') {
        return "Anything <b>except</b> ";
    } else {
        return cmp;
    }
}

// If seen before: return Index
// Otherwise: append
CONSTRAINTTYPES = [];
function getConstraintType(c) {

    if ( c.length == 1 && c[0]['constraints'][0].endsWith("] = '\\n')") ) {
        return 'enter';
    }


    for ( var i = 0; i < CONSTRAINTTYPES.length; i++ ) {
        if ( otherOptionsCmp(CONSTRAINTTYPES[i], c)) {
            return i;
        }
    }
    CONSTRAINTTYPES.push(c);
    return CONSTRAINTTYPES.length - 1;
}

function data_filter(data ) {
    var dat = {};
    for ( var i = 0; i < Object.keys(data).length; i++ ) {
        dat[i] = {};
        dat[i]['value'] = data[""+i]['value'];
        dat[i]['type'] = data[""+i]['type'];

        if (data[""+i]['type'] == 'output') {
            dat[i]['other_options'] = [];
            for ( var j = 0; j < data[""+i]['other_options'].length; j++ ) {
                var c = parseConstraint(data[""+i]['other_options'][j]['constraints'][0]);
                if ( c && ! isIgnoreInput(c['value']) ) {
                    var cn = { 'constraints': [data[""+i]['other_options'][j]['constraints'][0]],
                            'reachable_strings': data[""+i]['other_options'][j]['reachable_strings']
                            };
                    dat[""+i]['other_options'].push(cn);
                }
            }
        }
    }
    return dat;
}

