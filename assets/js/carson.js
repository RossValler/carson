'use strict';

var carson = angular.module('carson', [ 'ngRoute'
                                      , 'ngClipboard'
                                      , 'angularFileUpload'
                                      , 'ui.bootstrap']);

carson.factory('Auth', ['$http', function($http) {
  var currentUser;

  return {
    getCurrent: function(cb) {
      return $http.get('/current_user').success(function (response) {
        currentUser = response;
      });
    },
    user: function() {
      return currentUser;
    },
    isAdmin: function() {
      if (currentUser == undefined)
        return false
      else
        return currentUser.role == 'admin';
    },
    logout: function(cb) {
      $http.post('/logout').
      success(function() {
        currentUser = undefined;
        cb();
      });
    },
    login: function(user, cb) {
      $http.post('/auth', user).
      success(function(data) {
        currentUser = user;
        cb(true);
      }).error(function(data) {
        cb(false);
      });
    }
  };
}]);

carson.config(['$routeProvider', '$locationProvider',
  function($routeProvider, $locationProvider) {
    var authResolver = {
      auth: function($location, Auth) {
        return Auth.getCurrent().success(function() {
          if ($location.path() == '/admin' && !Auth.isAdmin())
            $location.path('/');
        }).error(function() {
          $location.path('/login');
        });
      }
    };

    var registrationResolver = {
      token: function($location, $http, $route) {
        return $http.get('/invitations/' + $route.current.params.token + '.json').
        error(function() {
          $location.path('/login');
        });
      }
    };

    var downloadsHandler = { templateUrl: '/assets/html/downloads.html'
                           , controller:  'DownloadsController'
                           , resolve: authResolver }
      , downloadHandler  = { templateUrl: '/assets/html/download.html'
                           , controller:  'DownloadController'
                           , resolve: authResolver }
      , browseHandler    = { templateUrl: '/assets/html/browse.html'
                           , controller:  'BrowseController'
                           , resolve: authResolver }
      , adminHandler     = { templateUrl: '/assets/html/admin.html'
                           , controller:  'AdminController'
                           , resolve: authResolver }
      , registerHandler  = { templateUrl: '/assets/html/register.html'
                           , controller:  'RegistrationController'
                           , resolve: registrationResolver }
      , loginHandler     = { templateUrl: '/assets/html/login.html'
                           , controller:  'LoginController'};

    $routeProvider.
      when('/',                downloadsHandler).
      when('/download/:hash',  downloadHandler).
      when('/browse',          browseHandler).
      when('/admin',           adminHandler).
      when('/register/:token', registerHandler).
      when('/login',           loginHandler).
      otherwise({redirectTo: '/'});

    $locationProvider.html5Mode(true);
  }]);

carson.controller('RegistrationController', ['$scope', '$document', '$location', '$http', 'token',
  function ($scope, $document, $location, $http, token) {
    $document[0].title = 'Register';
    $scope.user = {};
    $scope.user.token = token.data.token;

    $scope.register = function() {
      $http.post('/users.json', $scope.user).
      success(function() {
        $location.path('/');
      }).error(function() {
        $scope.fail = true;
      });
    };
  }]);

carson.controller('LoginController', ['$scope', '$document', '$location', 'Auth',
  function ($scope, $document, $location, Auth) {
    $document[0].title = 'Login';
    $scope.fail = false;
    $scope.user = {};

    $scope.login = function() {
      Auth.login($scope.user, function(success) {
        if (success)
          $location.path('/');
        else
          $scope.fail = true;
      });
    };
  }]);

carson.factory('Downloads', ['$http', '$window', '$rootScope', 'Auth',
  function($http, $window, $rootScope, Auth) {
  var downloads = [];

  var decorateDownload = function(download) {
    download.locked = download.metadata.locks.indexOf(Auth.user().name) != -1;
    download.metadata.date = new Date(download.metadata.date);
  };

  return {
    push: function(dl) {
      decorateDownload(dl);
      downloads.push(dl);
      downloads.sort(function(a, b) {
        return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
      });
    },
    fetchDownloads: function(cb) {
      var that = this;
      return $http.get('/downloads.json').success(function(response) {
        that.setDownloads(response);
      });
    },
    getDownloads: function() {
      return downloads;
    },
    setDownloads: function(from) {
      angular.copy(from, downloads);
      downloads.sort(function(a, b) {
        return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
      });
      angular.forEach(downloads, function(v, k) {
        decorateDownload(v);
      });
    }
  };
}]);

carson.controller('AppController', ['$scope', '$location', 'Auth',
  function ($scope, $location, Auth) {
    $scope.$on("$routeChangeStart", function (event, next, current) {
      $scope.isLogin = $location.path() == "/login" || next.templateUrl == '/assets/html/register.html';
    });

    $scope.activateNav = function (path) {
      if (path == 'downloads' && $location.path() == '/')
        return 'active';
      else
        return $location.path() == '/' + path ? 'active' : '';
    };

    $scope.logout = function() {
      Auth.logout(function() {
        $location.path('/login');
      });
    };

    $scope.user = Auth;
  }]);

// TODO: handle errors gracefully. currently if 3rd
//       out of 6 uploads fails, all 4-6 don't proceed
carson.controller('UploadController', ['$scope', '$upload', '$q', '$http', 'Downloads',
  function ($scope, $upload, $q, $http, Downloads) {
    $scope.files = [];
    $scope.responses = [];
    $scope.magnet = {};
    $scope.failed = [];
    $scope.show = {};

    $scope.closeAlert = function(index) {
      $scope.failed.splice(index, 1);
    };

    $scope.isUploading = function(file) {
      return file.progress > 0 && file.progress < 100;
    };

    $scope.templateUrl = "/assets/html/upload.html";

    $scope.removeUpload = function(index) {
      $scope.files.splice(index, 1);
    };

    $scope.slideIcon = function(sectionShown) {
      return sectionShown ? 'glyphicon-arrow-up' : 'glyphicon-arrow-down';
    };

    $scope.onFileSelect = function($files) {
      $scope.show.section = true; // show upload section

      // if there are existing downloads and we added some others
      angular.forEach($files, function(val, key) {
        $scope.files.push({
          file: val,
          progress: -1
        });
      });
    };

    $scope.startAll = function() {
      if ($scope.magnet.uri != undefined && $scope.magnet.uri.length > 0) {
        $http.post('/magnet', {magnet: $scope.magnet.uri}).success(function(data) {
          Downloads.push(data);
          $scope.magnet.uri = "";
          $scope.$emit('uploaded');

          if ($scope.files.length == 0) {
            $scope.show.section = false;
          }
        });
      }

      if ($scope.files.length > 0) {
        var promise = $q.when(true);
        $scope.$emit('uploaded');

        angular.forEach($scope.files, function(val, key) {
          promise = promise.then(function() {
            return $upload.upload({
              url: '/upload',
              method: 'POST',
              file: val.file,
              fileFormDataName: 'file'
            }).then(function (response) {
              Downloads.push(response.data);
            }, null, function(e) {
              val.progress = parseInt(100.0 * e.loaded / e.total);
            });
          }).catch(function(response) {
            $scope.failed.push(response.config.file.name);
          });
        });

        return promise.finally(function() {
          $scope.show.section = false;
          var len = $scope.files.length;
          for (var i = 0; i < len; i++) {
            $scope.removeUpload(0);
          }
        });
      }
    };

    $scope.startUpload = function(index) {
      $upload.upload({
        url: '/upload',
        method: 'POST',
        data: {},
        file: $scope.files[index].file,
        fileFormDataName: 'file'
      }).then(function(response) {
        $scope.removeUpload(index);
        $scope.$emit('uploaded');
        Downloads.push(response.data);
      }, null, function(e) {
        $scope.files[index].progress = parseInt(100.0 * e.loaded / e.total);
      });
    };
  }]);

carson.controller('BrowseController', ['$scope', '$http', '$document', '$window', 'Auth',
  function ($scope, $http, $document, $window, Auth) {
    $document[0].title = 'Browse';
    $scope.user = Auth;
    $scope.edit_tracker = {};

    $http.get('/browse.json').success(function(data) {
      $scope.trackers = data;
    });

    $scope.edit = function(tracker) {
      $scope.edit_tracker = tracker;
      $scope.editing = 'edit';
    };

    $scope.add = function() {
      $scope.edit_tracker = {};
      $scope.editing = 'new';
    };

    $scope.cancel = function() {
      $scope.edit_tracker = {};
      $scope.editing = '';
    };

    $scope.submit = function() {
      if ($scope.editing == 'edit')
        $scope.submitEdit();
      else if ($scope.editing == 'new')
        $scope.submitNew();
    };

    $scope.submitEdit = function() {
      $http.put('/browse/' + $scope.edit_tracker.id + '.json', $scope.edit_tracker).
      success(function() {
        $scope.edit_tracker = {};
        $scope.editing = '';
      }).
      error(function() {
        $scope.edit_tracker = {};
        $scope.editing = '';
      });
    };

    $scope.submitNew = function() {
      $http.post('/browse.json', $scope.edit_tracker).
      success(function(response) {
        $scope.trackers.push(response);
        $scope.edit_tracker = {};
        $scope.editing = '';
      }).
      error(function() {
        $scope.edit_tracker = {};
        $scope.editing = '';
      });
    };

    $scope.destroy = function(tracker) {
      if (!$window.confirm('delete ' + tracker.name + '?')) return;

      $http.delete('/browse/' + tracker.id + '.json').
      success(function() {
        $http.get('/browse.json').success(function(data) {
          $scope.trackers = data;
        });
      }).
      error(function() {
        // TODO: error
      });
    };
  }]);

carson.controller('AdminController', ['$scope', '$http', '$document', '$window', 'Auth',
  function ($scope, $http, $document, $window, Auth) {
    $document[0].title = 'Admin';
    $scope.current_user = Auth;
    $scope.edit_user = {};

    $http.get('/users.json').success(function(data) {
      $scope.users = data;
    });

    $http.get('/invitations.json').success(function(data) {
      $scope.invitations = data;
    });

    $scope.edit = function(user) {
      $scope.edit_user = user;
      $scope.editing = 'edit';
    };

    $scope.add = function() {
      $scope.edit_tracker = {};
      $scope.editing = 'new';
    };

    $scope.createInvitation = function() {
      $http.post('/invitations.json').
      success(function(response) {
        $scope.invitations.push(response);
      });
    };

    $scope.cancel = function() {
      $scope.edit_user = {};
      $scope.editing = '';
    };

    $scope.submit = function() {
      if ($scope.editing == 'edit')
        $scope.submitEdit();
      else if ($scope.editing == 'new')
        $scope.submitNew();
    };

    $scope.submitEdit = function() {
      $http.put('/users/' + $scope.edit_user.id + '.json', $scope.edit_user).
      success(function() {
        $scope.edit_user = {};
        $scope.editing = '';
      }).
      error(function() {
        $scope.edit_user = {};
        $scope.editing = '';
      });
    };

    $scope.submitNew = function() {
      $http.post('/users.json', $scope.edit_user).
      success(function(response) {
        $scope.trackers.push(response);
        $scope.edit_user = {};
        $scope.editing = '';
      }).
      error(function() {
        $scope.edit_user = {};
        $scope.editing = '';
      });
    };

    $scope.destroy = function(user) {
      if (!$window.confirm('delete ' + user.name + '?')) return;

      $http.delete('/users/' + user.id + '.json').
      success(function() {
        $http.get('/users.json').success(function(data) {
          $scope.users = data;
        });
      }).
      error(function() {
        // TODO: error
      });
    };

    $scope.destroyInvitation = function(invitation) {
      if (!$window.confirm('delete ' + invitation.token + '?')) return;

      $http.delete('/invitations/' + invitation.token + '.json').
      success(function() {
        $http.get('/invitations.json').success(function(data) {
          $scope.invitations = data;
        });
      }).
      error(function() {
        // TODO: error
      });
    };
  }]);

carson.controller('DownloadsController', ['$scope', '$document', '$http', 'Downloads', 'Auth', '$window',
  function ($scope, $document, $http, Downloads, Auth, $window) {
    $document[0].title = 'Downloads';
    $scope.downloads = Downloads.getDownloads();

    // TODO: wss if https?
    var proto = $window.location.protocol == 'https:' ? 'wss://' : 'ws://';
    var ws = new WebSocket(proto + $window.location.host + '/ws/downloads');

    ws.onmessage = function(m) {
      var data = JSON.parse(m.data);

      if (data.error != undefined) {
        $scope.announcement = data.error;
        $scope.$apply();
        return;
      } else {
        $scope.announcement = '';
      }

      Downloads.setDownloads(data);
      $scope.$apply();
    };

    Downloads.fetchDownloads().error(function() {
      $scope.announcement = "can't connect to rtorrent"
    });

    $scope.scope = 'recent';

    $scope.$on('$destroy', function() {
      ws.close();
    });

    $scope.$on('uploaded', function(e, data) {
      $scope.scope = 'recent';
    });

    $scope.$watch('scope', function() {
      $scope.downloadCategory($scope.scope);
    });

    $scope.$watchCollection('downloads', function() {
      $scope.downloadCategory($scope.scope);
    });

    $scope.lockImg = function(download) {
      return download.locked ? 'glyphicon-lock' : 'glyphicon-link';
    };

    $scope.lock = function(download) {
      $http.get('/lock/' + download.hash + '.json').success(function(data) {
        download.locked = data.action == "locked";
        $scope.downloadCategory($scope.scope);
      });
    };

    $scope.downloadCategory = function(scope) {
      $scope.scoped = [];

      switch (scope) {
        case 'locked':
          angular.forEach($scope.downloads, function(val, key) {
            if (val.locked) $scope.scoped.push(val);
          });
          break;
        case 'mine':
          angular.forEach($scope.downloads, function(val, key) {
            if (val.metadata.user == Auth.user().name) $scope.scoped.push(val);
          });
          break;
        case 'recent':
          $scope.scoped = $scope.downloads.slice(0).sort(function(a, b) {
            return -(a.metadata.date - b.metadata.date);
          });
          break;
        case 'expiring':
          var now = new Date;
          var expiry = 14; // downloads expire after 14 days

          angular.forEach($scope.downloads, function(val, key) {
            if (val.metadata.locks.length > 0) return;

            var date = val.metadata.date.getDate();
            var expiration = val.metadata.date.setDate(date + (expiry - 1));
            if (now > expiration) $scope.scoped.push(val);
          });
          break;
        default:
          $scope.scoped = $scope.downloads.slice(0);
          break;
      }
    };
  }]);

carson.controller('DownloadController', ['$scope', '$http', '$routeParams', '$document', '$window',
  function ($scope, $http, $routeParams, $document, $window) {
    var hash = $routeParams.hash;

    $http.get('/download/' + hash + '.json').success(function(data) {
      // data.state = 'seeding';

      $scope.download = data;

      $document[0].title = data.name;

      var proto = $window.location.protocol == 'https:' ? 'wss://' : 'ws://';
      var ws = new WebSocket(proto + $window.location.host + '/ws/download/' + hash);

      ws.onmessage = function(m) {
        var download = JSON.parse(m.data);
        angular.copy(download, $scope.download);
        $scope.$apply();
      };

      $scope.$on('$destroy', function() {
        ws.close();
      });
    });

    $scope.hideSearch = function(e) {
      if (e.which != 27) return;

      $scope.search = false;
      $scope.query = "";
    };

    var handler = function(e) {
      if (e.which != 83) return;
      $scope.search = true;
      $scope.$apply();
    };

    $document.bind('keyup', handler);

    $scope.$on('$destroy', function() {
      $document.unbind('keyup', handler);
    });

    $scope.fileBadge = function(file) {
      return file.progress < 100 ? 'download-incomplete' : 'download-complete';
    };

    $scope.downloadMessage = function(download) {
      if (download == undefined) return '';

      if (download.message.length > 0)
        return download.message;
    };

    $scope.metadataInfo = function(download) {
      if (download == undefined) return '';
      // TODO: make moment from the start, to avoid recreating this all the time?
      var date = moment.utc(download.metadata.date).local().format('dddd, MMMM Do YYYY, h:mm:ss A');
      var meta = 'added by ' + download.metadata.user + ' on ' + date;

      if (download.metadata.locks.length > 0)
        return meta + '. locked by ' + download.metadata.locks.join(', ');
      else
        return meta;
    };

    $scope.notDoneMsg = function(file) {
      if (file.progress < 100)
        $window.alert("this file is incomplete (" + file.progress + "%)")
    };

    $scope.downloadLink = function(file) {
      if (file.progress < 100)
        return "#";
      else
        return "/file/" + file.sendpath;
    };

    $scope.sizeOrProgress = function(file) {
      return file.progress < 100 ? (file.progress + "%") : file.size;
    };

    $scope.progressColor = function(download) {
      if (download == undefined) return 'default';
      switch (download.state) {
        case 'closed':
          return 'default';
        case 'downloading':
          return 'info';
        case 'hashing':
          return 'warning';
        case 'seeding':
          return 'info';
        case 'stopped':
          return 'danger';
      };
    };
  }]);

carson.filter('downloadFilter', function() {
  return function(downloads, search) {
    if (search == undefined || search == "") return downloads;

    var results = [];

    angular.forEach(downloads, function(download, key) {
      var re = RegExp(search.replace(/\s+/g, "."), "i").test(download.name);

      if (re || download.hash == search)
        results.push(download);
    });

    return results;
  };
});

carson.directive('ngFileListener', ['$parse', '$timeout', function($parse, $timeout) {
  return function(scope, elem, attr) {
    var fn = $parse(attr['ngFileListener']);
    elem.bind('change', function (e) {
      var files = [];
      var fileList = e.target.files;

      if (fileList != null) {
        angular.forEach(fileList, function(file, key) {
          files.push(file);
        });
      }

      $timeout(function() {
        fn(scope, {
          $files: files,
          $event: e
        });
      }); // timeout
    }); // bind

    elem.bind('click', function() {
      this.value = null;
    });
  }; // lambda
}]);

carson.directive('ngDropListener', ['$parse', '$timeout', '$document',
  function($parse, $timeout, $document) {
  return function(scope, elem, attr) {
    var fn = $parse(attr['ngDropListener']);

    $document.on('dragover', function(e) {
      e.stopPropagation();
      e.preventDefault();
      elem.addClass('dragover');
    });

    $document.on('dragleave', function(e) {
      elem.removeClass('dragover');
    });

    $document.on('drop', function(e) {
      e.stopPropagation();
      e.preventDefault();
      elem.removeClass('dragover');

      var fileList = e.dataTransfer.files;
      var files = [];

      if (fileList != null) {
        angular.forEach(fileList, function(file, key) {
          files.push(file);
        });
      }

      $timeout(function() {
        fn(scope, {
          $files: files,
          $event: e
        });
      });
    });
  };
}]);

carson.directive('ngCircleProgress', ['$parse', function($parse) {
  return {
    restrict: 'A',
    scope: {
      download: '=ngCircleProgress'
    },
    link: function(scope, elem, attr) {
      var ctx = elem[0].getContext('2d');

      var size = attr.width
        , half = size / 2
        , x = half
        , y = half
        , rad = half - 1
        , statusColor = {
          'closed': '#9f9f9f'
        , 'downloading': '#5cb85c'
        , 'hashing': '#cc0'
        , 'seeding': '#5bc0de'
        , 'stopped': '#d9534f'
        };

      scope.$watch(scope.download, function() {
        var progress = scope.download.progress
          , state = scope.download.state;

        if (progress == 100) return;

        var angle = Math.PI * 2 * (progress / 100);
        ctx.clearRect(0, 0, size, size);
        ctx.lineWidth = 2;

        // outer
        ctx.strokeStyle = statusColor[state];
        ctx.beginPath();
        ctx.arc(x, y, rad - 1, 0, angle, false);
        ctx.stroke();

        // inner
        ctx.strokeStyle = '#eeeeee';
        ctx.beginPath();
        ctx.arc(x, y, rad, 0, angle, true);
        ctx.stroke();
      });
    }
  };
}]);

