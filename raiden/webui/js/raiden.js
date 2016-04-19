  // autobahn.ws code to interact with gevent-websocket and call python methods
  var sess = null;
  var wsuri = "ws://" + window.location.hostname + ":8080/ws";
  var current_id = 1;
  var assets;
  var tx_button = tx_button_init();

  ab.connect(
      wsuri,
      // WAMP session was established
      function (session) {
          sess = session;
          console.log("Connected to " + wsuri);
          subscribe_transfer(sess);
          get_assets(sess);
          tx_button(sess);

      },

      // WAMP session is gone
      function (code, reason) {
          sess = null;
          tx_button(sess);
          if (code == ab.CONNECTION_UNSUPPORTED) {
              window.location = "http://autobahn.ws/unsupportedbrowser";
          } else {
              console.log(reason);
          }
      }
  );


  function tx_button_init(){
    var is_active = false
    function toggle(session){
      if (session !== null) {
        is_active = true
      } else {
        is_active = false
      }
      if (is_active) {
        $('#transferButton').removeAttr("disabled").removeClass('expanded disabled button').addClass('expanded primary button')
        $('#transferButton').html('Create a new transaction')
      } else {
        $('#transferButton').removeClass('expanded primary button').addClass('expanded disabled button').attr("disabled", "disabled");
        $('#transferButton').html('Not connected to Raiden')
      }
    }
    toggle(null)
    return toggle;
  }

  // $('.disabled').click(function(e){
  //   return false;
  // });

  function subscribe_transfer(session) {
    session.subscribe("http://localhost:8080/raiden#transfer_cb", function (topic, event) {
      console.log(topic, event);
      var callback = event[0]
      var status = event[1]
      // should only be one element!
      // var row = getRowByCallback(callback)
      // console.log(row)
      // alert(callback, status, row);
      var status_txt = $("#cb_id_"+callback).find('.status');
      if (status == true) {
        status_txt.html('Success').css('color', 'green')
      }
      else if (status == false){
        status_txt.html('Failed').css('color', 'red')
      }
      else {
        status_txt.html('Error').css('color', 'red')
      }
    });
  }

  function get_assets(session) {
    session.call(
        'http://localhost:8080/raiden#get_assets'
    ).then(
        function (res) {
          console.log('Available assets: ' + res),
          assets = res;
          var content;
          for (i = 0; i < assets.length; i++) {
            content += '<option value=\"'+assets[i]+'\">'+assets[i]+'</option>'
          $("#transfer_pubAsset").html(content)
        }

      },
        function (error) { console.log('RPC error: ' + error.desc); }
    )
  };


  $('#transfer').click(function() {
      var asset = $('#transfer_pubAsset').val();
      var amount = $('#transfer_amount').val();
      var receiver = $('#transfer_pubTo').val();
      // TODO: create storage for current id..
      var callback_id = current_id;

      sess.call(
          'http://localhost:8080/raiden#transfer',
          asset,
          amount,
          receiver,
          callback_id
      );
      console.log(
        "Transfer requested:"
        + "  asset - " + asset
        + "; amount - " + amount
        + "; Receiver - " + receiver
        + "; callback ID - " + callback_id
      );
      $('#channelTab').find('tbody:last').append('<tr id=\'cb_id_'+callback_id+'\'>\
                  <td>'+callback_id+'</td>\
                  <td>'+asset+'</td>\
                  <td>'+receiver+'</td>\
                  <td style="text-align:right">'+amount+'</td>\
                  <td><span class=\'status\' style=\'color:yellow\' >Requesting</span></td>\
                </tr>');
      current_id++;
  });
