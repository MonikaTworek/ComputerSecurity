var mime_samples = [
  { 'mime': 'application/xhtml+xml', 'samples': [
    { 'url': 'http://127.0.0.1:8000/', 'dir': '_m0/0', 'linked': 2, 'len': 256 },
    { 'url': 'http://127.0.0.1:8000/admin/login/', 'dir': '_m0/1', 'linked': 5, 'len': 1637 },
    { 'url': 'http://127.0.0.1:8000/admin/login/', 'dir': '_m0/2', 'linked': 5, 'len': 1770 },
    { 'url': 'http://127.0.0.1:8000/history/', 'dir': '_m0/3', 'linked': 0, 'len': 321 },
    { 'url': 'http://127.0.0.1:8000/login/', 'dir': '_m0/4', 'linked': 5, 'len': 713 },
    { 'url': 'http://127.0.0.1:8000/login/', 'dir': '_m0/5', 'linked': 5, 'len': 2502 },
    { 'url': 'http://127.0.0.1:8000/login/', 'dir': '_m0/6', 'linked': 0, 'len': 863 },
    { 'url': 'http://127.0.0.1:8000/logout/', 'dir': '_m0/7', 'linked': 0, 'len': 358 },
    { 'url': 'http://127.0.0.1:8000/static/', 'dir': '_m0/8', 'linked': 2, 'len': 1623 } ]
  },
  { 'mime': 'text/css', 'samples': [
    { 'url': 'http://127.0.0.1:8000/static/admin/css/base.css/', 'dir': '_m1/0', 'linked': 2, 'len': 16066 },
    { 'url': 'http://127.0.0.1:8000/static/admin/css/login.css/', 'dir': '_m1/1', 'linked': 2, 'len': 1203 } ]
  },
  { 'mime': 'text/plain', 'samples': [
    { 'url': 'http://127.0.0.1:8000/static/', 'dir': '_m2/0', 'linked': 2, 'len': 59 } ]
  }
];

var issue_samples = [
  { 'severity': 0, 'type': 10803, 'samples': [
    { 'url': 'http://127.0.0.1:8000/static/', 'extra': '', 'sid': '0', 'dir': '_i0/0' },
    { 'url': 'http://127.0.0.1:8000/static/admin/', 'extra': '', 'sid': '0', 'dir': '_i0/1' },
    { 'url': 'http://127.0.0.1:8000/static/admin/css/', 'extra': '', 'sid': '0', 'dir': '_i0/2' },
    { 'url': 'http://127.0.0.1:8000/static/admin/css/base.css/', 'extra': '', 'sid': '0', 'dir': '_i0/3' },
    { 'url': 'http://127.0.0.1:8000/static/admin/css/login.css/', 'extra': '', 'sid': '0', 'dir': '_i0/4' } ]
  },
  { 'severity': 0, 'type': 10802, 'samples': [
    { 'url': 'http://127.0.0.1:8000/static/', 'extra': 'text/plain', 'sid': '0', 'dir': '_i1/0' },
    { 'url': 'http://127.0.0.1:8000/static/admin/', 'extra': 'text/plain', 'sid': '0', 'dir': '_i1/1' },
    { 'url': 'http://127.0.0.1:8000/static/admin/css/', 'extra': 'text/plain', 'sid': '0', 'dir': '_i1/2' } ]
  },
  { 'severity': 0, 'type': 10602, 'samples': [
    { 'url': 'http://127.0.0.1:8000/admin/login/', 'extra': '', 'sid': '0', 'dir': '_i2/0' },
    { 'url': 'http://127.0.0.1:8000/admin/login/', 'extra': '', 'sid': '0', 'dir': '_i2/1' },
    { 'url': 'http://127.0.0.1:8000/admin/login/', 'extra': '', 'sid': '0', 'dir': '_i2/2' },
    { 'url': 'http://127.0.0.1:8000/login/', 'extra': '', 'sid': '0', 'dir': '_i2/3' },
    { 'url': 'http://127.0.0.1:8000/login/', 'extra': '', 'sid': '0', 'dir': '_i2/4' } ]
  },
  { 'severity': 0, 'type': 10405, 'samples': [
    { 'url': 'http://127.0.0.1:8000/admin/auth/', 'extra': '', 'sid': '0', 'dir': '_i3/0' },
    { 'url': 'http://127.0.0.1:8000/admin/auth/group/', 'extra': '', 'sid': '0', 'dir': '_i3/1' },
    { 'url': 'http://127.0.0.1:8000/admin/logout/', 'extra': '', 'sid': '0', 'dir': '_i3/2' },
    { 'url': 'http://127.0.0.1:8000/history/', 'extra': '', 'sid': '0', 'dir': '_i3/3' },
    { 'url': 'http://127.0.0.1:8000/login/', 'extra': '', 'sid': '0', 'dir': '_i3/4' },
    { 'url': 'http://127.0.0.1:8000/logout/', 'extra': '', 'sid': '0', 'dir': '_i3/5' } ]
  },
  { 'severity': 0, 'type': 10403, 'samples': [
    { 'url': 'http://127.0.0.1:8000/static/', 'extra': '', 'sid': '0', 'dir': '_i4/0' },
    { 'url': 'http://127.0.0.1:8000/static/admin/', 'extra': '', 'sid': '0', 'dir': '_i4/1' },
    { 'url': 'http://127.0.0.1:8000/static/admin/css/', 'extra': '', 'sid': '0', 'dir': '_i4/2' } ]
  },
  { 'severity': 0, 'type': 10401, 'samples': [
    { 'url': 'http://127.0.0.1:8000/login/', 'extra': '', 'sid': '0', 'dir': '_i5/0' },
    { 'url': 'http://127.0.0.1:8000/login/', 'extra': '', 'sid': '0', 'dir': '_i5/1' },
    { 'url': 'http://127.0.0.1:8000/login/', 'extra': '', 'sid': '0', 'dir': '_i5/2' } ]
  },
  { 'severity': 0, 'type': 10205, 'samples': [
    { 'url': 'http://127.0.0.1:8000/sfi9876', 'extra': '', 'sid': '0', 'dir': '_i6/0' },
    { 'url': 'http://127.0.0.1:8000/admin/sfi9876', 'extra': '', 'sid': '0', 'dir': '_i6/1' },
    { 'url': 'http://127.0.0.1:8000/admin/auth/group/sfi9876', 'extra': '', 'sid': '0', 'dir': '_i6/2' },
    { 'url': 'http://127.0.0.1:8000/admin/auth/group/sfi9876/', 'extra': '', 'sid': '0', 'dir': '_i6/3' },
    { 'url': 'http://127.0.0.1:8000/static/admin/css/base.css/sfi9876', 'extra': '', 'sid': '0', 'dir': '_i6/4' },
    { 'url': 'http://127.0.0.1:8000/static/admin/css/login.css/sfi9876', 'extra': '', 'sid': '0', 'dir': '_i6/5' } ]
  },
  { 'severity': 0, 'type': 10204, 'samples': [
    { 'url': 'http://127.0.0.1:8000/', 'extra': 'X-Frame-Options', 'sid': '0', 'dir': '_i7/0' },
    { 'url': 'http://127.0.0.1:8000/static/', 'extra': 'X-Frame-Options', 'sid': '0', 'dir': '_i7/1' } ]
  },
  { 'severity': 0, 'type': 10202, 'samples': [
    { 'url': 'http://127.0.0.1:8000/', 'extra': 'WSGIServer/0.1 Python/2.7.12', 'sid': '0', 'dir': '_i8/0' } ]
  },
  { 'severity': 0, 'type': 10201, 'samples': [
    { 'url': 'http://127.0.0.1:8000/login/', 'extra': 'csrftoken', 'sid': '0', 'dir': '_i9/0' } ]
  }
];

