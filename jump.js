(function () {
  'use strict';
  var form = document.getElementById('jumpForm');
  var input = document.getElementById('domainInput');
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var domain = input.value.trim();
    window.location.href = domain ? '/?domain=' + encodeURIComponent(domain) : '/';
  });
  var domainParam = new URLSearchParams(window.location.search).get('domain');
  if (domainParam) input.value = domainParam;
})();
