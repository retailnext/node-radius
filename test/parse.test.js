var testCase = require('nodeunit').testCase;
var radius = require('../lib/radius');
var fs = require('fs');

var secret = 'nearbuy';

radius.load_dictionaries();

module.exports = testCase({
  setUp: function(callback) {
    callback();
  },
  tearDown: function(callback) {
    callback();
  },

  test_parse_mac_auth: function(test) {
    var raw_packet = fs.readFileSync(__dirname + '/captures/aruba_mac_auth.packet');

    var parsed = radius.parse(raw_packet, secret);

    test.equal( 'Access-Request', parsed.code );
    test.equal( 58, parsed.identifier );
    test.equal( 208, parsed.length );

    var expected_attrs = {
      'NAS-IP-Address': '10.0.0.90',
      'NAS-Port': 0,
      'NAS-Port-Type': 'Wireless-802.11',
      'User-Name': '7c:c5:37:ff:f8:af',
      'User-Password': '7c:c5:37:ff:f8:af',
      'Calling-Station-Id': '7CC537FFF8AF',
      'Called-Station-Id': '000B86F02068',
      'Service-Type': 'Login-User',
      'Message-Authenticator': new Buffer('f8a12329c7ed5a6e2568515243efb918', 'hex'),

      // XXX parse me
      'Vendor-Specific': new Buffer('000039e70a0a636c6f75642d6370', 'hex'),
    };
    test.deepEqual( expected_attrs, parsed.attributes );

    test.done();
  }
});
