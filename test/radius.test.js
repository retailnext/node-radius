var testCase = require('nodeunit').testCase;
var radius = require('../lib/radius');
var fs = require('fs');

var secret = 'nearbuy';

var test_args = {};

module.exports = testCase({
  setUp: function(callback) {
    callback();
  },
  tearDown: function(callback) {
    radius.unload_dictionaries();
    callback();
  },

  test_decode_mac_auth: function(test) {
    var raw_packet = fs.readFileSync(__dirname + '/captures/aruba_mac_auth.packet');

    radius.load_dictionary(__dirname + '/dictionaries/dictionary.aruba');

    var decoded = radius.decode({ packet: raw_packet, secret: secret });

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
    var orig_load = radius.load_dictionary;
    radius.load_dictionary = function() { };

    var decoded = radius.decode({ packet: raw_packet, secret: secret });

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

    radius.load_dictionary = orig_load;

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

    var decoded = radius.decode({ packet: packet, secret: secret });
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

  test_decode_hash_attributes: function(test) {
    var attrs = {
      'User-Name': 'ornithopter-aliptic',
      'User-Password': 'nucleohistone-overwilily',
      'Service-Type': 'Login-User',
      'NAS-IP-Address': '169.134.68.136'
    };
    var packet = radius.encode({
      code: 'Access-Request',
      identifier: 123,
      attributes: attrs,
      secret: secret
    });

    var decoded = radius.decode({ packet: packet, secret: secret });
    test.equal( 'Access-Request', decoded.code );
    test.equal( 123, decoded.identifier );
    test.deepEqual( attrs, decoded.attributes );

    test.done();
  },

  test_throws_on_nested_hash_attributes: function(test) {
    var attrs = {
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

    test.throws(function() {
      var packet = radius.encode({
        code: 'Access-Request',
        identifier: 123,
        attributes: attrs,
        secret: secret
      });
    });
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
    var decoded = radius.decode({
      packet: radius.encode({
        code: 'Access-Request',
        secret: secret
      }),
      secret: secret
    });
    test.ok( decoded.identifier >= 0 && decoded.identifier < 256 );

    var starting_id = decoded.identifier;

    // if you are unlucky this is an infinite loop
    while (true) {
      decoded = radius.decode({
        packet: radius.encode({
          code: 'Access-Request',
          secret: secret
        }),
        secret: secret
      });
      if (decoded.identifier != starting_id)
        break;
    }

    test.ok( true );

    test.done();
  },

  // given a previously decoded packet, prepare a response packet
  test_packet_response: function(test) {
    var raw_packet = fs.readFileSync(__dirname + '/captures/cisco_mac_auth.packet');

    var decoded = radius.decode({ packet: raw_packet, secret: secret });

    var response = radius.encode_response({
      packet: decoded,
      code: 'Access-Reject',
      secret: secret
    });

    var raw_response = fs.readFileSync(__dirname + '/captures/cisco_mac_auth_reject.packet');
    test.equal( raw_response.toString('hex'), response.toString('hex') );

    test.done();
  },

  // response needs to include proxy state
  test_response_include_proxy_state: function(test) {
    var request_with_proxy = radius.decode({
      packet: radius.encode({
        code: 'Access-Request',
        secret: secret,
        attributes: [
          ['User-Name', 'ascribe-despairer'],
          ['Proxy-State', new Buffer('womanhouse-Pseudotsuga')],
          ['User-Password', 'ridiculous'],
          ['Proxy-State', new Buffer('regretfully-unstability')]
        ]
      }),
      secret: secret
    });

    var decoded_response = radius.decode({
      packet: radius.encode_response({
        packet: request_with_proxy,
        code: 'Access-Reject',
        secret: secret
      }),
      secret: secret
    });

    var expected_raw_attributes = [
      [radius.attr_name_to_id('Proxy-State'), new Buffer('womanhouse-Pseudotsuga')],
      [radius.attr_name_to_id('Proxy-State'), new Buffer('regretfully-unstability')]
    ];

    test.deepEqual( expected_raw_attributes, decoded_response.raw_attributes );

    test.done();
  },

  // dont accidentally strip null bytes when encoding
  test_password_encode: function(test) {
    var decoded = radius.decode({
      packet: radius.encode({
        code: 'Access-Request',
        authenticator: new Buffer('426edca213c1bf6e005e90a64105ca3a', 'hex'),
        attributes: [['User-Password', 'ridiculous']],
        secret: secret
      }),
      secret: secret
    });

    test.equal( decoded.attributes['User-Password'], 'ridiculous' );

    test.done();
  },

  accounting_group: {
    setUp: function(cb) {
      radius.load_dictionary(__dirname + '/dictionaries/dictionary.airespace');

      test_args = {};
      test_args.raw_acct_request = fs.readFileSync(__dirname + '/captures/cisco_accounting.packet');
      test_args.expected_acct_attrs = {
        'User-Name': 'user_7C:C5:37:FF:F8:AF_134',
	      'NAS-Port': 1,
	      'NAS-IP-Address': '10.0.3.4',
        'Framed-IP-Address': '10.2.0.252',
        'NAS-Identifier': 'Cisco 4400 (Anchor)',
        'Vendor-Specific': {
          'Airespace-Wlan-Id': 2
        },
        'Acct-Session-Id': '4fecc41e/7c:c5:37:ff:f8:af/9',
        'Acct-Authentic': 'RADIUS',
        'Tunnel-Type': [0x00, 'VLAN'],
        'Tunnel-Medium-Type': [0x00, 'IEEE-802'],
        'Tunnel-Private-Group-Id': 5,
        'Acct-Status-Type': 'Start',
        'Calling-Station-Id': '7c:c5:37:ff:f8:af',
        'Called-Station-Id': '00:22:55:90:39:60'
      };
      cb();
    },

    test_accounting: function(test) {
      var raw_acct_request = test_args.raw_acct_request;
      var decoded = radius.decode({ packet: raw_acct_request, secret: secret });

      var expected_attrs = test_args.expected_acct_attrs;

      test.deepEqual( expected_attrs, decoded.attributes );

      // test we can encode the same packet
      var encoded = radius.encode({
        code: 'Accounting-Request',
        identifier: decoded.identifier,
        secret: secret,
        attributes: [
       	  ['User-Name', 'user_7C:C5:37:FF:F8:AF_134'],
	        ['NAS-Port', 1],
	        ['NAS-IP-Address', '10.0.3.4'],
          ['Framed-IP-Address', '10.2.0.252'],
          ['NAS-Identifier', 'Cisco 4400 (Anchor)'],
          ['Vendor-Specific', 'Airespace', [['Airespace-Wlan-Id', 2]]],
          ['Acct-Session-Id', '4fecc41e/7c:c5:37:ff:f8:af/9'],
          ['Acct-Authentic', 'RADIUS'],
          ['Tunnel-Type', 0x00, 'VLAN'],
          ['Tunnel-Medium-Type', 0x00, 'IEEE-802'],
          ['Tunnel-Private-Group-Id', '5'],
          ['Acct-Status-Type', 'Start'],
          ['Calling-Station-Id', '7c:c5:37:ff:f8:af'],
          ['Called-Station-Id', '00:22:55:90:39:60']
        ]
      });
      test.equal( encoded.toString('hex'), raw_acct_request.toString('hex') );

      var raw_acct_response = fs.readFileSync(__dirname +
                                              '/captures/cisco_accounting_response.packet');
      encoded = radius.encode_response({
        packet: decoded,
        secret: secret,
        code: 'Accounting-Response'
      });
      test.equal( encoded.toString('hex'), raw_acct_response.toString('hex') );

      test.done();
    },

    test_invalid_accounting_packet_authenticator: function(test) {
      var raw_acct_request = test_args.raw_acct_request;
      var expected_attrs = test_args.expected_acct_attrs;

      // detect invalid accounting packets
      test.throws( function() {
        radius.decode({ packet: raw_acct_request, secret: 'not-secret' });
      } );

      try {
        radius.decode({ packet: raw_acct_request, secret: 'not-secret' });
      } catch (err) {
        test.deepEqual( expected_attrs, err.decoded.attributes );
      }
      test.done();
    },

    test_invalid_accounting_packet_authenticator_async: function(test) {
      var raw_acct_request = test_args.raw_acct_request;
      var expected_attrs = test_args.expected_acct_attrs;

      var decode_callback = function(err, packet) {
        test.ok( err );
        test.deepEqual( expected_attrs, err.decoded.attributes );
        test.done();
      };

      radius.decode({
        packet: raw_acct_request,
        secret: 'not-secret',
        callback: decode_callback
      });
    }
  },

  test_async_encode_decode: function(test) {
    var decode_callback = function(err, decoded) {
      test.ok( !err );

      test.equal( 187, decoded.identifier );
      test.equal( 'Access-Accept', decoded.code );
      test.equal( 'Eurypterida-lactucerin', decoded.attributes['User-Name'] );

      test.done();
    };
    var encode_callback = function(err, encoded) {
      test.ok( !err );

      radius.decode({ packet: encoded, secret: secret, callback: decode_callback });
    };

    radius.encode({
      code: 'Access-Accept',
      secret: secret,
      identifier: 187,
      attributes: [['User-Name', 'Eurypterida-lactucerin']],
      callback: encode_callback
    });
  },

  test_async_encode_response: function(test) {
    var decoded = radius.decode({
      packet: radius.encode({
        code: 'Access-Request',
        secret: secret,
        attributes: [
          ['User-Name', 'Italian-impale'],
          ['User-Password', 'iambus-nondecision']
        ]
      }),
      secret: secret
    });

    radius.unload_dictionaries();
    var encode_response_cb = function(err, response) {
      test.ok( !err );

      var decoded_resp = radius.decode({ packet: response, secret: secret });
      test.equal( 'Access-Reject', decoded_resp.code );
      test.equal( 'unstrangulable-theoretical', decoded_resp.attributes['Reply-Message'] );

      test.done();
    };

    radius.encode_response({
      code: 'Access-Reject',
      packet: decoded,
      secret: secret,
      attributes: [['Reply-Message', 'unstrangulable-theoretical']],
      callback: encode_response_cb
    });
  },

  test_no_empty_strings: function(test) {
    var decoded = radius.decode({
      secret: secret,
      packet: radius.encode({
        code: 'Access-Request',
        attributes: [['User-Name', '']],
        secret: secret
      })
    });

    // don't send empty strings (see RFC2865)
    test.deepEqual( {}, decoded.attributes );

    test.done();
  },

  test_repeated_attribute: function(test) {
    var decoded = radius.decode({
      secret: secret,
      packet: radius.encode({
        secret: secret,
        code: 'Access-Reject',
        attributes: [
          ['Reply-Message', 'message one'],
          ['Reply-Message', 'message two']
        ]
      })
    });

    var expected_attrs = {
      'Reply-Message': ['message one', 'message two']
    };
    test.deepEqual( expected_attrs, decoded.attributes );

    test.done();
  },

  test_dictionary_include: function(test) {
    radius.unload_dictionaries();
    radius.add_dictionary(__dirname + '/dictionaries/dictionary.test1');

    var decoded = radius.decode({
      secret: secret,
      packet: radius.encode({
        secret: secret,
        code: 'Access-Request',
        attributes: [['Attribute-Test1', 'foo'], ['Attribute-Test2', 'bar']]
      })
    });

    var expected_attrs = {
      'Attribute-Test1': 'foo',
      'Attribute-Test2': 'bar'
    };
    test.deepEqual( expected_attrs, decoded.attributes );

    // make sure it works with async loading too
    radius.unload_dictionaries();

    var encode_callback = function(err, encoded) {
      var decode_callback = function(err, decoded) {
        test.deepEqual( expected_attrs, decoded.attributes );

        test.done();
      };

      radius.decode({
        secret: secret,
        packet: encoded,
        callback: decode_callback
      });
    };
    radius.encode({
      secret: secret,
      code: 'Access-Request',
      attributes: [['Attribute-Test1', 'foo'], ['Attribute-Test2', 'bar']],
      callback: encode_callback
    });
  },

  // make sure we can load the dicts in any order
  test_dictionary_out_of_order: function(test) {
    var dicts = fs.readdirSync(__dirname + '/../dictionaries');

    // make sure we can load any dictionary first
    for (var i = 0; i < dicts.length; i++) {
      radius.unload_dictionaries();
      radius.load_dictionary(__dirname + '/../dictionaries/' + dicts[i]);
    }

    // and spot check things actually work loaded out of order
    radius.unload_dictionaries();
    radius.load_dictionary(__dirname + '/../dictionaries/dictionary.rfc2867');
    radius.load_dictionary(__dirname + '/../dictionaries/dictionary.rfc2866');

    var decoded = radius.decode({
      secret: secret,
      packet: radius.encode({
        code: 'Accounting-Request',
        secret: secret,
        attributes: [
         ['Acct-Status-Type', 'Tunnel-Reject']
        ]
      })
    });

    test.equal( 'Tunnel-Reject', decoded.attributes['Acct-Status-Type'] );

    radius.unload_dictionaries();
    radius.load_dictionary(__dirname + '/dictionaries/dictionary.test_tunnel_type');
    radius.load_dictionaries();

    decoded = radius.decode({
      secret: secret,
      packet: radius.encode({
        code: 'Accounting-Request',
        secret: secret,
        attributes: [
          ['Tunnel-Type', 0x00, 'TESTTUNNEL']
        ]
      })
    });

    var expected_attrs = {'Tunnel-Type': [0x00, 'TESTTUNNEL']};
    test.deepEqual( expected_attrs, decoded.attributes );

    test.done();
  },

  test_zero_identifer: function(test) {
    var decoded = radius.decode({
      packet: radius.encode({
        secret: secret,
        code: 'Access-Request',
        identifier: 0
      }),
      secret: secret
    });

    test.equal( 0, decoded.identifier );
    test.done();
  },

  // handle two packets quickly before dictionaries are loaded
  test_async_dictionary_race: function(test) {
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

    var raw_packet = fs.readFileSync(__dirname + '/captures/aruba_mac_auth.packet');

    var attempts = 0;
    var try_once = function() {
      radius.add_dictionary(__dirname + '/dictionaries/dictionary.aruba');
      radius.unload_dictionaries();

      radius.decode({
        packet: raw_packet,
        secret: secret,
        callback: function(err, decoded) {
          test.deepEqual( expected_attrs, decoded.attributes );
          attempts += 1;
        }
      });

      radius.decode({
        packet: raw_packet,
        secret: secret,
        callback: function(err, decoded) {
          test.deepEqual( expected_attrs, decoded.attributes );

          attempts += 1;
          if (attempts == 100) {
            test.done();
          } else  {
            try_once();
          }
        }
      });
    };

    try_once();
  },

  test_date_type: function(test) {
    var raw_packet = fs.readFileSync(__dirname + '/captures/motorola_accounting.packet');

    var decoded = radius.decode({
      packet: raw_packet,
      secret: secret
    });

    var epoch = 1349879753;

    test.equal( epoch * 1000, decoded.attributes['Event-Timestamp'].getTime() );

    var encoded = radius.encode({
      code: 'Accounting-Request',
      identifier: decoded.identifier,
      attributes: [
        ['User-Name', '00-1F-3B-8C-3A-15'],
        ['Acct-Status-Type', 'Start'],
        ['Acct-Session-Id', '1970D5A4-001F3B8C3A15-0000000001'],
        ['Calling-Station-Id', '00-1F-3B-8C-3A-15'],
        ['Called-Station-Id', 'B4-C7-99-77-59-D0:muir-moto-guest-site1'],
        ['NAS-Port', 1],
        ['NAS-Port-Type', 'Wireless-802.11'],
        ['NAS-IP-Address', '10.2.0.3'],
        ['NAS-Identifier', 'ap6532-70D5A4'],
        ['NAS-Port-Id', 'radio2'],
        ['Event-Timestamp', new Date(epoch * 1000)],
        ['Tunnel-Type', 0x00, 'VLAN' ],
        ['Tunnel-Medium-Type', 0x00, 'IEEE-802'],
        ['Tunnel-Private-Group-Id', '30'],
        ['Acct-Authentic', 'RADIUS']
      ],
      secret: secret
    });

    test.equal( raw_packet.toString('hex'), encoded.toString('hex') );

    test.done();
  }
});
