var channel_table = (function() {
      var table;
      var initialiseTable = function() {
          table = $('#channels').dataTable( {
            "ajax": {
              "url": "http://localhost:5000/raiden/api/channels",
              "dataSrc": "channels",
            },
            "columns": [
                    { "data": "partner" },
                    { "data": "asset" },
                    { "data": "deposit" },
                    { "data": "status" }
            ]

          });
      }

    return {
        table: table,
        initialiseTable: initialiseTable
    };

})();

var assetSelect = ( function() {
      var initialiseAssetSelect = function(){ $.ajax({
          url: "http://localhost:5000/raiden/api/assets",
          type: 'get',
          dataType: 'json',
          success:function(response){
              var assets = response.assets;
              console.log(assets.length);
              $("#asset_address").empty();
              for( var i = 0; i < assets.length; i++){

                    $("#asset_address").
                    append("<option value='"+assets[i]+"'>"+assets[i]+"</option>");

                }
          }
        });
      }

      return {
          initialiseAssetSelect: initialiseAssetSelect
      };
})();



$( document ).ready( function() {
    channel_table.initialiseTable();
    assetSelect.initialiseAssetSelect();
});
