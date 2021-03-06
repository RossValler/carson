'use strict';

angular.module('ngClipboard', []).
  value('ZeroClipboardPath', 'assets/js/ZeroClipboard.swf').
  directive('clipCopy', ['$window', 'ZeroClipboardPath', function ($window, ZeroClipboardPath) {
    return {
      scope: {
        clipCopy: '&',
        clipClick: '&'
      },
      restrict: 'A',
      link: function (scope, element, attrs) {
        // Create the clip object
        ZeroClipboard.config({ moviePath: ZeroClipboardPath });
        var clip = new ZeroClipboard( element );

        clip.on( 'mousedown', function(client) {
          client.setText(scope.$eval(scope.clipCopy));
          if (angular.isDefined(attrs.clipClick)) {
            scope.$apply(scope.clipClick);
          }
        });
      }
    }
  }]);
