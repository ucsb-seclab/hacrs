$(document).ready(function() {
    var table = $('#tasklets-table');

    $(table).DataTable({
        'data':tasklets,
        'iDisplayLength': 100,
        'columns': [
            { data: 'program',
              render: function(data, type, row) {
                if (type == 'display' ) {
                    return '<a href="/internal/tasklet/' + row['id'] + '">' + data + '</a>';
                }
                return data;
                },
            },
            { data: 'keywords',
              render: function ( data, type, row ) {
                if (type == 'sort' ) {
                    return ['easy', 'medium', 'hard', 'very hard'].indexOf(data);
                }
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
        ], createdRow: function( row, data, dataIndex ) {
            $( row ).find('td:eq(0)').attr('data-sort', '0');
        }
        });


    $('#tasklets-table tbody').on('click', 'tr', function () {
        var data = table.DataTable().row( this ).data();
        document.location = '/internal/tasklet/' + data['id'];
    } );
} );

