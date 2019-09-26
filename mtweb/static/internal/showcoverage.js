$(document).ready(function() {
    var table = $('#coverage-table');

    pcoverage = [];

    for ( var k in coverage['coverage'] ) {
        pcoverage.push({'program': k,
                       'coverage': coverage['coverage'][k]
                      });

    }

    $(table).DataTable({
        'data': pcoverage,
        'iDisplayLength': 100,
        'columns': [
            { data: 'program',
              render: function(data, type, row) {
                if (type == 'display' ) {
                    //return '<a href="/internal/program/' + "row['']" + '">' + data + '</a>';
                    return data;
                }
                return data;
                },
            },
            { data: 'coverage',
              render: function ( data, type, row ) {
                if ( type == 'display' ) {
                    return Math.round(100 * data) / 100 + " %";
                }
                return data;
                } 
            }
        ]
        });


    $('#coverage-table tbody').on('click', 'tr', function () {
        var data = table.DataTable().row( this ).data();
        //document.location = '/internal/tasklet/' + data['id'];
    } );
} );

