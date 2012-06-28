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

  test_decode_mac_auth: function(test) {
    var raw_packet = fs.readFileSync(__dirname + '/captures/aruba_mac_auth.packet');

    radius.load_dictionary(__dirname + '/dictionaries/dictionary.aruba');

    var decoded = radius.decode(raw_packet, secret);

    test.equal( 'Access-Request', decoded.code );
    test.equal( 58, decoded.identifier );
    test.equal( 208, decoded.length );

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
    test.deepEqual( expected_attrs, decoded.attributes );

    test.done();
  },

  // make sure everthing is fine with no dictionaries
  test_decode_no_dicts: function(test) {
    var raw_packet = fs.readFileSync(__dirname + '/captures/aruba_mac_auth.packet');

    radius.unload_dictionaries();

    var decoded = radius.decode(raw_packet, secret);

    test.equal( 'Access-Request', decoded.code );
    test.equal( 58, decoded.identifier );
    test.equal( 208, decoded.length );

    // no pretty attributes
    test.deepEqual( {}, decoded.attributes );

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
      [80, new Buffer('f8a12329c7ed5a6e2568515243efb918', 'hex')]
    ];

    test.deepEqual( expected_raw_attrs, decoded.raw_attributes );

    test.done();
  },

  // can make a "naked" packet
  test_encode_access_request: function(test) {
    radius.load_dictionary(__dirname + '/dictionaries/dictionary.aruba');

    var attributes = [
      ['User-Name', 'ornithopter-aliptic'],
      ['User-Password', 'nucleohistone-overwilily'],
      ['Service-Type', 'Login-User'],
      ['NAS-IP-Address', '169.134.68.136'],

      ['Vendor-Specific', 14823, [
        ['Aruba-User-Role', 'cracked-tylote'],
        [2, 825]
      ]],
      ['Vendor-Specific', 14823, [['Aruba-Essid-Name', 'phene-dentinalgia']]]
    ];
    var packet = radius.encode({
      code: 'Access-Request',
      identifier: 123,
      attributes: attributes,
      secret: secret
    });

    var decoded = radius.decode(packet, secret);
    test.equal( 'Access-Request', decoded.code );
    test.equal( 123, decoded.identifier );

    var expected_attrs = {
      'User-Name': 'ornithopter-aliptic',
      'User-Password': 'nucleohistone-overwilily',
      'Service-Type': 'Login-User',
      'NAS-IP-Address': '169.134.68.136',
      'Vendor-Specific': {
        'Aruba-User-Role': 'cracked-tylote',
        'Aruba-User-Vlan': 825,
        'Aruba-Essid-Name': 'phene-dentinalgia'
      }
    };
    test.deepEqual( expected_attrs, decoded.attributes );

    test.done();
  },

  // test that our encoded packet matches bit-for-bit with a "real"
  // RADIUS packet
  test_encode_bit_for_bit: function(test) {
    var raw_packet = fs.readFileSync(__dirname + '/captures/aruba_mac_auth.packet');

    radius.load_dictionary(__dirname + '/dictionaries/dictionary.aruba');

    var encoded = radius.encode({
      code: 'Access-Request',
      identifier: 58,
      authenticator: new Buffer('4a45fae086d9e114286b37b5f371ec6c', 'hex'),
      attributes: [
        ['NAS-IP-Address', '10.0.0.90'],
        ['NAS-Port', 0],
        ['NAS-Port-Type', 'Wireless-802.11'],
        ['User-Name', '7c:c5:37:ff:f8:af'],
        ['User-Password', '7c:c5:37:ff:f8:af'],
        ['Calling-Station-Id', '7CC537FFF8AF'],
        ['Called-Station-Id', '000B86F02068'],
        ['Service-Type', 'Login-User'],
        ['Vendor-Specific', 14823, [['Aruba-Essid-Name', 'muir-aruba-guest']]],
        ['Vendor-Specific', 14823, [['Aruba-Location-Id', '00:1a:1e:c6:b0:ca']]],
        ['Vendor-Specific', 14823, [['Aruba-AP-Group', 'cloud-cp']]],
        ['Message-Authenticator', new Buffer('f8a12329c7ed5a6e2568515243efb918', 'hex')]
      ],
      secret: secret
    });

    test.equal( raw_packet.toString('hex'), encoded.toString('hex') );

    test.done();
  },

  // encode will choose a random identifier for you if you don't provide one
  test_encode_random_identifer: function(test) {
    var decoded = radius.decode(radius.encode({
      code: 'Access-Request'
    }));
    test.ok( decoded.identifier >= 0 && decoded.identifier < 256 );

    var starting_id = decoded.identifier;

    // if you are unlucky this is an infinite loop
    while (true) {
      decoded = radius.decode(radius.encode({
        code: 'Access-Request'
      }));
      if (decoded.identifier != starting_id)
        break;
    }

    test.ok( true );

    test.done();
  },

  // given a previously decoded packet, prepare a response packet
  test_packet_response: function(test) {
    var raw_packet = fs.readFileSync(__dirname + '/captures/cisco_mac_auth.packet');

    var decoded = radius.decode(raw_packet, secret);

    var response = radius.encode_response(decoded, {
      code: 'Access-Reject',
      secret: secret
    });

    var raw_response = fs.readFileSync(__dirname + '/captures/cisco_mac_auth_reject.packet');
    test.equal( raw_response.toString('hex'), response.toString('hex') );

    test.done();
  }

});
