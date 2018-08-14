var testCase = require('nodeunit').testCase;
var radius = require('../lib/radius');
var fs = require('fs');
var crypto = require('crypto');

var secret;

var test_args = {};

module.exports = testCase({
  setUp: function(callback) {
    secret = "nearbuy";
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

    test.equal( decoded.code, 'Access-Request' );
    test.equal( decoded.identifier, 58 );
    test.equal( decoded.length, 208 );

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
    test.deepEqual( decoded.attributes, expected_attrs );

    test.done();
  },

  test_decode_mac_auth_without_secret: function(test) {
    var raw_packet = fs.readFileSync(__dirname + '/captures/aruba_mac_auth.packet');

    radius.load_dictionary(__dirname + '/dictionaries/dictionary.aruba');

    var decoded = radius.decode_without_secret({ packet: raw_packet });

    test.equal( decoded.code, 'Access-Request' );
    test.equal( decoded.identifier, 58 );
    test.equal( decoded.length, 208 );

    var expected_attrs = {
      'NAS-IP-Address': '10.0.0.90',
      'NAS-Port': 0,
      'NAS-Port-Type': 'Wireless-802.11',
      'User-Name': '7c:c5:37:ff:f8:af',
      'User-Password': null, // this is an encrypted field, and so cannot be read without the password
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
    test.deepEqual( decoded.attributes, expected_attrs );

    decoded = radius.decode({
      secret: secret,
      packet: radius.encode({
        secret: secret,
        code: "Access-Request",
        attributes: {
          'User-Name': 'Caenogaean-asphyxia',
          'User-Password': 'barratry-Wertherism'
        }
      })
    });

    test.equal( decoded.attributes['User-Password'], 'barratry-Wertherism' );

    test.done();
  },

  // make sure everthing is fine with no dictionaries
  test_decode_no_dicts: function(test) {
    var raw_packet = fs.readFileSync(__dirname + '/captures/aruba_mac_auth.packet');

    radius.unload_dictionaries();
    var orig_load = radius.load_dictionary;
    radius.load_dictionary = function() { };

    var decoded = radius.decode({ packet: raw_packet, secret: secret });

    test.equal( decoded.code, 'Access-Request' );
    test.equal( decoded.identifier, 58 );
    test.equal( decoded.length, 208 );

    // no pretty attributes
    test.deepEqual( decoded.attributes, {} );

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

    test.deepEqual( decoded.raw_attributes, expected_raw_attrs );

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
    test.equal( decoded.code, 'Access-Request' );
    test.equal( decoded.identifier, 123 );

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
    test.deepEqual( decoded.attributes, expected_attrs );

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
    test.equal( decoded.code, 'Access-Request' );
    test.equal( decoded.identifier, 123 );
    test.deepEqual( decoded.attributes, attrs );

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
        ['Vendor-Specific', 14823, [['Aruba-AP-Group', 'cloud-cp']]]
      ],
      secret: secret,
      add_message_authenticator: true
    });

    test.equal( encoded.toString('hex'), raw_packet.toString('hex') );

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
    test.equal( response.toString('hex'), raw_response.toString('hex') );

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

    test.deepEqual( decoded_response.raw_attributes, expected_raw_attributes );

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

      test.deepEqual( decoded.attributes, expected_attrs );

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
        test.deepEqual( err.decoded.attributes, expected_attrs );
      }
      test.done();
    }
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
    test.deepEqual( decoded.attributes, {} );

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
    test.deepEqual( decoded.attributes, expected_attrs );

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
    test.deepEqual( decoded.attributes, expected_attrs );

    test.done();
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

    test.equal( decoded.attributes['Acct-Status-Type'], 'Tunnel-Reject' );

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
    test.deepEqual( decoded.attributes, expected_attrs );

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

    test.equal( decoded.identifier, 0 );
    test.done();
  },

  test_date_type: function(test) {
    var raw_packet = fs.readFileSync(__dirname + '/captures/motorola_accounting.packet');

    var decoded = radius.decode({
      packet: raw_packet,
      secret: secret
    });

    var epoch = 1349879753;

    test.equal( decoded.attributes['Event-Timestamp'].getTime(), epoch * 1000 );

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

    test.equal( encoded.toString('hex'), raw_packet.toString('hex') );

    test.done();
  },

  test_date_type_non_mult_1000_ms: function(test) {
    var encoded;
    test.doesNotThrow(function() {
      encoded = radius.encode({
        code: 'Accounting-Request',
        identifier: 123,
        attributes: [
          ['Event-Timestamp', new Date(1403025894009)]
        ],
        secret: secret
      });
    });

    // truncates ms
    var decoded = radius.decode({ packet: encoded, secret: secret });
    test.equal( decoded.attributes['Event-Timestamp'].getTime(), 1403025894000 );

    test.done();
  },

  test_disconnect_request: function(test) {
    var encoded = radius.encode({
      code: 'Disconnect-Request',
      identifier: 54,
      secret: secret,
      attributes: [
        ['User-Name', 'mariticide-inquietation'],
        ['NAS-Identifier', 'Aglauros-charioted']
      ]
    });

    // check we did the non-user-password authenticator
    var got_authenticator = new Buffer(16);
    encoded.copy(got_authenticator, 0, 4);
    encoded.fill(0, 4, 20);

    var expected_authenticator = new Buffer(16);
    var hasher = crypto.createHash("md5");
    hasher.update(encoded);
    hasher.update(secret);
    expected_authenticator.write(hasher.digest("binary"), 0, 16, "binary");

    test.equal( got_authenticator.toString('hex'), expected_authenticator.toString('hex') );

    // and make sure we check the authenticator when decoding
    test.throws(function() {
      radius.decode({
        packet: encoded,
        secret: secret
      });
    });

    expected_authenticator.copy(encoded, 4, 0);
    test.doesNotThrow(function() {
      radius.decode({
        packet: encoded,
        secret: secret
      });
    });

    test.done();
  },

  test_verify_response: function(test) {
    var request = radius.encode({
      secret: secret,
      code: 'Accounting-Request',
      attributes: {
        'User-Name': '00-1F-3B-8C-3A-15',
        'Acct-Status-Type':  'Start'
      }
    });

    var response = radius.encode_response({
      secret: secret,
      code: 'Accounting-Response',
      packet: radius.decode({ packet: request, secret: secret })
    });

    test.ok( radius.verify_response({
      request: request,
      response: response,
      secret: secret
    }) );

    test.ok( !radius.verify_response({
      request: request,
      response: response,
      secret: "Calliopsis-misbeholden"
    }) );

    // response encoded with wrong secret
    response = radius.encode_response({
      secret: "moyenne-paraboliform",
      code: 'Accounting-Response',
      packet: radius.decode({ packet: request, secret: secret })
    });
    test.ok( !radius.verify_response({
      request: request,
      response: response,
      secret: secret
    }) );

    test.done();
  },

  test_server_request: function(test) {
    var encoded1 = radius.encode({
      code: 'Status-Server',
      identifier: 54,
      secret: secret,
      attributes: [
        ['NAS-Identifier', 'symphilism-dicentrine']
      ]
    });

    var encoded2 = radius.encode({
      code: 'Status-Server',
      identifier: 54,
      secret: secret,
      attributes: [
        ['NAS-Identifier', 'symphilism-dicentrine']
      ]
    });

    // check we are doing a random authenticator
    var got_authenticator1 = new Buffer(16);
    encoded1.copy(got_authenticator1, 0, 4);

    var got_authenticator2 = new Buffer(16);
    encoded2.copy(got_authenticator2, 0, 4);

    test.notEqual( got_authenticator1.toString(), got_authenticator2.toString() );

    var response = radius.encode_response({
      code: 'Access-Accept',
      secret: secret,
      packet: radius.decode({packet: encoded1, secret: secret})
    });

    test.ok( radius.verify_response({
      request: encoded1,
      response: response,
      secret: secret
    }) );

    test.done();
  },

  test_vendor_names_with_numbers: function(test) {
    radius.load_dictionary(__dirname + '/dictionaries/dictionary.number_vendor_name');

    var encoded = radius.encode({
      code: "Access-Request",
      secret: secret,

      attributes: [
        ['Vendor-Specific', '123Foo', [
          ['1Integer', 478],
          ['1String', 'Zollernia-fibrovasal'],
          ['12345', 'myrmecophagoid-harn']
        ]]
      ]
    });

    var decoded = radius.decode({
      packet: encoded,
      secret: secret
    });

    test.equal( radius.vendor_name_to_id('123Foo'), 995486 );

    test.deepEqual( decoded.attributes, {
      'Vendor-Specific': {
        '1Integer': 478,
        '1String': 'Zollernia-fibrovasal',
        '12345': 'myrmecophagoid-harn'
      }
    } );

    test.done();
  },

  message_authenticator_group: {
    setUp: function(cb) {
      secret = "testing123";

      test_args = {
        raw_request: fs.readFileSync(__dirname + '/captures/eap_request.packet')
      };
      test_args.parsed_request = radius.decode({
        packet: test_args.raw_request,
        secret: secret
      });
      cb();
    },

    // make sure we calculate the same Message-Authenticator
    test_calculate: function(test) {
      var attrs_without_ma = test_args.parsed_request.raw_attributes.filter(function(a) {
        return a[0] != radius.attr_name_to_id('Message-Authenticator');
      });

      var encoded = radius.encode({
        code: test_args.parsed_request.code,
        identifier: test_args.parsed_request.identifier,
        authenticator: test_args.parsed_request.authenticator,
        attributes: attrs_without_ma,
        secret: secret
      });

      test.equal( encoded.toString('hex'), test_args.raw_request.toString('hex') );

      test.done();
    },

    // encode_response should calculate the appropriate Message-Authenticator
    test_encode_response: function(test) {
      var response = radius.encode_response({
        code: "Access-Accept",
        secret: secret,
        packet: test_args.parsed_request
      });

      var parsed_response = radius.decode({
        packet: response,
        secret: secret
      });

      // calculate expected Message-Authenticator

      var empty = new Buffer(16);
      empty.fill(0);

      var expected_response = radius.encode({
        code: "Access-Accept",
        identifier: test_args.parsed_request.identifier,
        authenticator: test_args.parsed_request.authenticator,
        attributes: [["Message-Authenticator", empty]],
        secret: secret
      });

      // expected_response's authenticator is correct, but Message-Authenticator is wrong
      // (it's all 0s). make sure verify_response checks both
      test.ok( !radius.verify_response({
        request: test_args.raw_request,
        response: expected_response,
        secret: secret
      }) );

      // put back the request's authenticator
      test_args.parsed_request.authenticator.copy(expected_response, 4);

      var expected_ma = radius.calculate_message_authenticator(expected_response, secret);
      test.equal(
        parsed_response.attributes["Message-Authenticator"].toString("hex"),
        expected_ma.toString("hex")
      );

      test.ok( radius.verify_response({
        request: test_args.raw_request,
        response: response,
        secret: secret
      }) );

      test.done();
    },

    // response is missing Message-Authenticator, not okay
    test_response_missing_ma: function(test) {
      var bad_response = radius.encode({
        code: "Access-Accept",
        identifier: test_args.parsed_request.identifier,
        authenticator: test_args.parsed_request.authenticator,
        attributes: [],
        secret: secret
      });

      test.ok( !radius.verify_response({
        request: test_args.raw_request,
        response: bad_response,
        secret: secret
      }) );

      test.done();
    },

    // make sure we verify Message-Authenticator when decoding requests
    test_decode_verify: function(test) {
      test.throws(function() {
        radius.decode({
          packet: test_args.raw_request,
          secret: 'wrong secret'
        });
      });

      test.done();
    }
  },

  test_utf8_strings: function(test) {
    var encoded = radius.encode({
      secret: "密码",
      code: "Access-Request",
      attributes: {
        "User-Name": "金庸先生",
        "User-Password": "降龙十八掌"
      }
    });

    var decoded = radius.decode({
      packet: encoded,
      secret: "密码"
    });

    test.deepEqual( {
      "User-Name": "金庸先生",
      "User-Password": "降龙十八掌"
    }, decoded.attributes );

    test.done();
  },

  test_invalid_packet_attribute_length: function(test) {
    var invalid_packet  = fs.readFileSync(__dirname + '/captures/invalid_register.packet');
    var raw_packet      = fs.readFileSync(__dirname + '/captures/aruba_mac_auth.packet');

    // should fail decode packet attributes
    test.throws(function() {
      radius.decode_without_secret({ packet: invalid_packet });
    } );

    // should decode packet attributes
    test.doesNotThrow(function() {
      radius.decode_without_secret({ packet: raw_packet });
    });

    test.done();
  },

  test_tag_fields: function(test) {
    var decoded = radius.decode({
      secret: secret,
      packet: radius.encode({
        code: 'Accounting-Request',
        secret: secret,
        attributes: [
          ['Tunnel-Type', 0x01, 'VLAN'],
          ['User-Name', 'honeymooner-hitched'],
        ]
      })
    });

    test.deepEqual( {
      'Tunnel-Type': [ 1, 'VLAN'],
      'User-Name': 'honeymooner-hitched'
    }, decoded.attributes );
    test.done();
  }
});
