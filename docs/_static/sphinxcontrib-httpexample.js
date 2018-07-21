(function() {
  var jQuery = window.jQuery || function() {};

  jQuery(function($) {
    $('.http-example.container').each(function() {
      var $container = $(this),
          $blocks = $(this).children(),
          $captions = $(this).find('.caption');
      $captions.each(function() {
        var $block = $(this).parent();
        $(this).on('click', function() {
          $captions.removeClass('selected');
          $(this).addClass('selected');
          $blocks.hide();
          $block.show();
        });
        $container.append($(this));
      });
      $container.append($blocks);
      $captions.first().click();
    });
  });

})();
