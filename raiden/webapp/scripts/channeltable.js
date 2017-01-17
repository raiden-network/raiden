var raidenAddress = "0xbff78da2ff4e106d5bd0637c12b893c5ab60cb41";

var channelTable = ( function() {

    var actionEditor = function(cell, value){
        //cell - JQuery object for current cell
        //value - the current value for current cell

        //create and style editor
        var editor = $("<select>"+
        "<option value='open' selected>Open Channel</option>"+
        "<option value='close'>Close Channel</option>"+
        "<option value='settle'>Settle Channel</option>"+
        "<option value='deposit'>Deposit in Channel</option>"+
        "</select>");
        editor.css({
          "padding":"3px",
          "width":"100%",
          "box-sizing":"border-box",
        })

        //set focus on the select box when the editor is selected (timeout allows for editor to be added to DOM)
        if(cell.hasClass("tabulator-cell")){
          setTimeout(function(){
              editor.focus();
          },100);
        }

        //return the editor element
          return editor;
    }


    var initialiseTable = function() {
      $("#channels").tabulator({
        ajaxURL: "http://localhost:5000/raiden/api/channels",
        fitColumns: true,
        columns:[ //set column definitions for imported table data
            {title: "Partner Address", field: "partner" },
            {title: "Asset Address", field: "asset" },
            {title: "Deposit", field: "deposit" },
            {title: "Status", field: "status" },
            {title: "Action", editable:true, editor:actionEditor}
        ],
      });
    }

    return {
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


var eventsTimeline = ( function() {

    var itemList = [];

    var pictos = {
      "transferred": '<i class="fa fa-money"></i>',
      "closed": '<i class="glyphicon glyphicon-ban-circle"></i>',
      "settled": '<i class="fa fa-calendar-check-o"></i>',
      "default": '<i class="fa fa-calendar-o"></i>'
    }

    var initialiseTimeline = function() {
      $.ajax({
        url: "http://localhost:5000/raiden/api/events",
        type: 'get',
        dataType: 'json',
        success:function(response){
            prepareItemList(response.events);
            $('#timeline-container-relativepos-dates').timelineMe({
              items: itemList
            });
        }
      });
    }

    var prepareItemList = function(events) {
        for( var i = 0; i < events.length; i++){
            var eventItem = {};
            eventItem["type"] = 'smallItem';
            var eventDate = new Date(events[i].timestamp*1000);
            eventItem["label"] = eventDate.toDateString();
            console.log(eventDate);
            eventItem["shortContent"] = events[i].status;
            eventItem["forcePosition"] = 'right';
            eventItem["showMore"] = ''+events[i].partner + "<br>" + events[i].status + "<br>" + raidenAddress;
            eventItem["picto"] = pictos.hasOwnProperty(events[i].status) ? pictos[events[i].status] : pictos["default"];
            itemList.push(eventItem);
        }
    }

    return {
        initialiseTimeline: initialiseTimeline
    };

})();

$( document ).ready( function() {
    channelTable.initialiseTable();
    assetSelect.initialiseAssetSelect();
    eventsTimeline.initialiseTimeline();
});
