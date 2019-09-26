$(document).ready(function() {
    var table = $('#turkinfos-table');

    $(table).DataTable({
        'data': turkinfos,
        'iDisplayLength': 100,
        'columns': [
            { data: 'tid',
              render: function(data, type, row) {
                if (type == 'display' ) {
                    return '<a href="/internal/tasklet/' + row['tid'] + '">' + data + '</a>';
                }
                return data;
                },
            },
            { data: 'hitid',
              render: function ( data, type, row ) {
                return data;
                } 
            },
            { data: 'hitgid',
              render: function ( data, type, row ) {
                return data;
                } 
            },


            { data: 'amount',
              render: function ( data, type, row ) {
                    if ( type == 'display' ) {
                        return '$ ' + data;
                    }
                    return data;
                }
            },
            {data : 'type'}
        ]
        });


    $('#turkinfos-table tbody').on('click', 'tr', function () {
        var data = table.DataTable().row( this ).data();
        document.location = '/internal/tasklet/' + data['tid'];
    } );
} );

