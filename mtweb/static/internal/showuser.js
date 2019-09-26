$(document).ready(function() {
    var table = $('#user-table');

    $(table).DataTable({
        'data':attempts,
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
            }
        ], createdRow: function( row, data, dataIndex ) {
            $( row ).find('td:eq(0)').attr('data-sort', '0');
        }
        });


    $('#user-table tbody').on('click', 'tr', function () {
        var data = table.DataTable().row( this ).data();
        document.location = '/internal/tasklet/' + data['id'];
    } );
} );

