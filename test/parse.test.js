var testCase = require('nodeunit').testCase;
var radius = require('../lib/radius');
var fs = require('fs');

var secret = 'nearbuy';


module.exports = testCase({
  setUp: function(callback) {
    radius.load_dictionaries();
    callback();
  },
  tearDown: function(callback) {
    radius.unload_dictionaries();
    callback();
  },

  test_parse_mac_auth: function(test) {
    var raw_packet = fs.readFileSync(__dirname + '/captures/aruba_mac_auth.packet');

    radius.load_dictionary(__dirname + '/dictionaries/dictionary.aruba');

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
      'Vendor-Specific': {
        'Aruba-Essid-Name': 'muir-aruba-guest',
        'Aruba-Location-Id': '00:1a:1e:c6:b0:ca',
        'Aruba-AP-Group': 'cloud-cp'
      },
      'Message-Authenticator': new Buffer('f8a12329c7ed5a6e2568515243efb918', 'hex')
    };
    test.deepEqual( expected_attrs, parsed.attributes );

    test.done();
  },

  // make sure everthing is fine with no dictionaries
  test_parse_no_dicts: function(test) {
    var raw_packet = fs.readFileSync(__dirname + '/captures/aruba_mac_auth.packet');

    radius.unload_dictionaries();

    var parsed = radius.parse(raw_packet, secret);

    test.equal( 'Access-Request', parsed.code );
    test.equal( 58, parsed.identifier );
    test.equal( 208, parsed.length );

    // no pretty attributes
    test.deepEqual( {}, parsed.attributes );

    var expected_raw_attrs = [
      [4, new Buffer([10, 0, 0, 90])],
      [5, new Buffer([0, 0, 0, 0])],
      [61, new Buffer([0, 0, 0, 19])],
      [1, new Buffer('7c:c5:37:ff:f8:af')],
      [2, new Buffer('eb2ef7e83ec1a05e04fb5c6d91e088569a990fa2b1b2dc6a0f048596081164cd', 'hex')],
      [31, new Buffer('7CC537FFF8AF')],
      [30, new Buffer('000B86F02068')],
      [6, new Buffer([0, 0, 0, 1])],
      [26, new Buffer('000039e705126d7569722d61727562612d6775657374', 'hex')],
      [26, new Buffer('000039e7061330303a31613a31653a63363a62303a6361', 'hex')],
      [26, new Buffer('000039e70a0a636c6f75642d6370', 'hex')],
      [80, new Buffer('f8a12329c7ed5a6e2568515243efb918', 'hex')],
    ];

    test.deepEqual( expected_raw_attrs, parsed.raw_attributes );

    test.done();
  }

});
