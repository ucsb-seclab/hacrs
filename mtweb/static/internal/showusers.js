$(document).ready(function() {
    var table = $('#users-table');

    $(table).DataTable({
        'data': users,
        'iDisplayLength': 100,
        'columns': [
            { data: 'name',
              render: function(data, type, row) {
                if (type == 'display' ) {
                    return '<a href="/internal/user/' + row['id'] + '">' + data + '</a>';
                }
                return data;
                },
            },
            { data: 'permissions',
              render: function ( data, type, row ) {
                return data;
                } 
            },
            { data: 'utype',
              render: function ( data, type, row ) {
                return data;
                } 
            }
        ]
        });


    $('#users-table tbody').on('click', 'tr', function () {
        var data = table.DataTable().row( this ).data();
        document.location = '/internal/user/' + data['id'];
    } );
} );

