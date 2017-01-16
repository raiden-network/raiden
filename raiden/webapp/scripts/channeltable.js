var raidenAddress = "0xbff78da2ff4e106d5bd0637c12b893c5ab60cb41";


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

var events = ( function() {
        var eventList;

        var initialiseEvents = function(){
          eventList = $(".timeline");
          $.ajax({
            url: "http://localhost:5000/raiden/api/events",
            type: 'get',
            dataType: 'json',
            success:function(response){
                var events = response.events;
                console.log("length of events=="+events[0]);
                eventList.empty();
                for( var i = 0; i < events.length; i++){
                    channelEvent = document.createElement('event-item');
                    channelEvent.setTitle(events[i].status);
                    channelEvent.setTime(events[i].timestamp);
                    channelEvent.setMessage(events[i]);
                    eventList.append(channelEvent);
                }
            }
          });

        }

        return {
            eventList: eventList,
            initialiseEvents: initialiseEvents
        };
})();

var eventListItem = Object.create(HTMLElement.prototype);

eventListItem.TEMPLATE =
    '<li>'+
      '<div class="timeline-badge"><i class="glyphicon glyphicon-check"></i></div>'+
      '<div class="timeline-panel">'+
        '<div class="timeline-heading">'+
          '<h4 class="timeline-title"></h4>'+
          '<p><small class="text-muted"><i class="glyphicon glyphicon-time"></i>'+

          '</small></p>'+
        '</div>'+
        '<div class="timeline-body">'+
          '<p class="message"></p>'+
        '</div>'+
      '</div>'+
    '</li>';


eventListItem.createdCallback = function() {
        this.innerHTML = eventListItem.TEMPLATE;
        this.titleElement = this.querySelector('.timeline-title');
        this.dateElement = this.querySelector('.text-muted');
        this.messageElement = this.querySelector('.message');
}

eventListItem.setMessage = function(event) {

        var message = event.partner +" "+ event.status +" "+ "with" + " "+ raidenAddress;
        this.messageElement.textContent = message;

}

eventListItem.setTime = function(timestamp) {
        var date = new Date(timestamp);
        //this.dateElement.textContent = date.toDateString();
        this.dateElement.insertAdjacentText('beforeend', date.toDateString());
}

eventListItem.setTitle = function(title) {
        this.titleElement.textContent = title;
}

document.registerElement('event-item', {
  prototype: eventListItem
});



$( document ).ready( function() {
    channel_table.initialiseTable();
    assetSelect.initialiseAssetSelect();
    events.initialiseEvents();

});
