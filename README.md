# node-radius [![Build Status](https://secure.travis-ci.org/retailnext/node-radius.png)](http://travis-ci.org/retailnext/node-radius) - A RADIUS library for node.js

node-radius is a RADIUS packet encoding/decoding library for node.js written in Javascript. With node-radius you can easily decode received packets, encode packets to send, and prepare responses to received packets. node-radius supports both RADIUS authentication and RADIUS accounting packets.

node-radius requires node.js v0.8.0. To install node-radius, simply run `npm install radius` in your project directory.

Let's look at some examples of how to use node-radius:

    var radius = require('radius');

    // ... receive raw_packet from UDP socket

    var decoded = radius.decode({ packet: raw_packet, secret: "shared_secret" });

"decoded" might look something like this:

    {
      code: 'Access-Request',
      identifer: 123,
      length: 250,
      attributes: {
        'NAS-IP-Address': '10.1.2.3',
        'User-Name': 'jlpicard',
        'User-Password': 'beverly123',
        'Vendor-Specific': {
          'Federation-Starship': 'Enterprise'
        }
      }
    }

To prepare your response packet, use the encode_response function:

    var response = radius.encode_response({
      packet: decoded,
      code: "Access-Accept",
      secret: "section31"
    });

To prepare a stand-alone packet, try this:

    var packet = radius.encode({
      code: "Access-Request",
      secret: "obsidian order",
      attributes: [
        ['NAS-IP-Address', '10.5.5.5'],
        ['User-Name', 'egarak'],
        ['User-Password', 'tailoredfit'],
        ['Vendor-Specific', 555, [['Real-Name', 'arobinson']]]
      ]
    });


## Method descriptions:

### radius.decode(\<args>)

decode takes as input an object with the following fields:

- packet (required): a Buffer containing the raw UDP RADIUS packet (as read off a socket)
- secret (required): a String containing the RADIUS shared secret

Using the dictionaries available, decode parses the raw packet and yields an object representation of the packet. The object has the following fields:

- code: string representation of the packet code ("Access-Request", "Accounting-Response", etc)
- identifier: packet identifier number (used for duplicate packet detection)
- length: RADIUS packet length
- attributes: an object containing all attributes node-radius knew how to parse. If an attribute is repeated, its value in the "attributes" object will become an Array containing each value. Unfortunately the dictionary files do not specify which attributes are repeatable, so if an attribute might be repeated then you need to check if the value in "attributes" is a scalar value or an Array.
- raw_attributes: an array of arrays containing each raw attribute (attribute type and a Buffer containing the attribute value). This is mainly used by node-radius for generating the response packet, and would only be useful to you if you are missing relevant dictionaries and/or want to decode attributes yourself.

When decoding requests (e.g. "Access-Request", "Accounting-Request"), decode will automatically verify the request authenticator and the Message-Authenticator attribute, if present. If the request doesn't check out, decode will raise an error. The error, an instance of Radius.InvalidSecretError, has a "decoded" field you can use to inspect the decoded but invalid message. The most common reason for an incorrect authenticator is using the wrong shared secret.

### radius.decode_without_secret(\<args>)

Identical to decode, but does not need the secret.  This can be useful to "pre-decode" a message, in order to look-up (or calculate) the secret to be used to properly decode the message later.

A message decoded without a secret will contain null values for encrypted fields (typically passwords, etc.).

### radius.encode(\<args>)

encode takes an object for arguments and returns a Buffer ready to be sent over the wire. The accepted arguments are:

- code (required): string representation of the packet code ("Access-Request", "Accounting-Response", etc)
- secret (required): RADIUS shared secret
- identifier (optional): packet identifer number (defaults to a random number from 0 to 255)
- attributes (optional): RADIUS attributes you want to add to the packet
- add_message_authenticator (optional): a boolean value controlling whether the library adds the Message-Authenticator HMAC to the packet. See below for more details.

encode will automatically add the Message-Authenticator when:

- encoding a message with an "EAP-Message" attribute
- encoding a "Status-Server" message
- you manually pass the "add_message_authenticator: true" option

encode will not add the Message-Authenticator when:

- the attributes already contain a "Message-Authenticator" attribute
- you manually pass the "add_message_authenticator: false" option

The attributes will typically be like the following (see above example):

    attributes: [
      [<attribute name>, <attribute value>],
      ...
    ]

If you don't care about attribute ordering, you can use a hash for the attributes:

    attributes: {
      <attribute name>: <attribute value>,
      ...
    }

If you want to send attributes that you haven't loaded a dictionary for, you can do:

    attributes: [
      [<attribute id>, <Buffer>],
      ...
    ]

Where the first item is the numeric attribute id and the second item is just a Buffer containing the value of the attribute (not including length).

You can specify Vendor-Specific attributes like so:

    attributes: [
      ['Vendor-Specific', <vendor id>, [
        [<attribute name>, <attribute value>],
        [<attribute name>, <attribute value>]
      ],
      ...
    ]

Or if you want each vendor attribute as a separate attribute, try this:

    attributes: [
      ['Vendor-Specific', <vendor id>, [[<attribute name>, <attribute value>]]],
      ['Vendor-Specific', <vendor id>, [[<attribute name>, <attribute value>]]]
      ...
    ]

Like regular attributes, you can also specify the attribute id and a raw Buffer value for VSAs. If your dictionary specifies vendor attributes using the BEGIN-VENDOR/END-VENDOR format, you can use the symbolic vendor name as defined in the dictionary in place of the numeric \<vendor id>.

You can specify the tag field-attribute like so (see RFC2868):

    attributes: [
      [<attribute name>, <tag number>, <attribute value>],
      ...
    ]

If the attribute has an optional tag and you don't want to send it, then only specify the \<attribute name> and the \<attribute value>.

### radius.encode\_response(\<args>)

encode_response prepares a response packet based on previously received and decoded packet. "args" is an object with the following properties:

- packet (required): the output of a previous call to radius.decode
- code (required): String representation of the packet code ("Access-Reject, "Accounting-Response", etc)
- attributes (optional): RADIUS attributes you want to add to the packet

encode_response does a few things for you to prepare the response:

1. sets the response packet's message identifier to the identifer of the previously received packet
1. copies any "Proxy-State" attributes from the previously received packet into the response packet
1. calculates the appropriate response authenticator based on the request's authenticator
1. calculates and adds a Message-Authenticator attribute if the request contained one

### radius.verify\_response(\<args>)

verify_response checks the authenticator and Message-Authenticator attribute, if applicable, of a response packet you receive. It returns true if the packet checks out, and false otherwise (likely because the other side's shared secret is wrong). "args" is an object with the following properties:

- request (required): the request packet you previously sent (should be the raw packet, i.e. the output of a call to radius.encode)
- response (required): the response you received to your request packet (again, the raw packet)
- secret (required): RADIUS shared secret

This method is useful if you are acting as the NAS. For example, if you send an "Access-Request", you can use this method to verify the response you get ("Reject" or "Accept") is legitimate.

Note that if the request contained a Message-Authenticator, the response must also contain a Message-Authenticator.

## Dictionaries

node-radius supports reading freeradius-style RADIUS dictionary files. node-radius comes with a slew of RFC dictionary files, so you should only worry about adding any vendor-specific dictionary files you have. node-radius will load all the dictionaries it knows about (the default RFC ones and any you added) automatically the first time it needs to, so you should add your dictionaries before you start to use the module.

### radius.add_dictionary(\<path>)

To add a dictionary to be loaded, use the **add_dictionary** function:

    var radius = require('radius');

    radius.add_dictionary('/path/to/my/dictionary');

add\_dictionary takes either a file or a directory (given a directory, it assumes everything in the directory is a dictionary file). add\_dictionary does not block or perform any IO. It simply adds the given path to a list which is used to load dictionaries later.

node-radius supports reading both the VENDORATTR and the BEGIN-VENDOR/END-VENDOR style for defining VSAs. node-radius also supports reading the following attribute modifiers: has_tag, encrypt=1.

node-radius will also follow "$INCLUDE" directives inside of dictionary files (to load other dictionary files).

## Example usage

The following is an example of a simple radius authentication server:

    var radius = require('radius');
    var dgram = require("dgram");

    var secret = 'radius_secret';
    var server = dgram.createSocket("udp4");

    server.on("message", function (msg, rinfo) {
      var code, username, password, packet;
      packet = radius.decode({packet: msg, secret: secret});

      if (packet.code != 'Access-Request') {
        console.log('unknown packet type: ', packet.code);
        return;
      }

      username = packet.attributes['User-Name'];
      password = packet.attributes['User-Password'];

      console.log('Access-Request for ' + username);

      if (username == 'jlpicard' && password == 'beverly123') {
        code = 'Access-Accept';
      } else {
        code = 'Access-Reject';
      }

      var response = radius.encode_response({
        packet: packet,
        code: code,
        secret: secret
      });

      console.log('Sending ' + code + ' for user ' + username);
      server.send(response, 0, response.length, rinfo.port, rinfo.address, function(err, bytes) {
        if (err) {
          console.log('Error sending response to ', rinfo);
        }
      });
    });

    server.on("listening", function () {
      var address = server.address();
      console.log("radius server listening " +
          address.address + ":" + address.port);
    });

    server.bind(1812);

Client and server examples can be found in the examples directory.

## Important notes:

- node-radius in general does _not_ perform "higher-level" protocol validation, so for example node-radius will not complain if you encode an Access-Request packet but fail to include a NAS-IP-Address or NAS-Identifier.
- node-radius in general assumes most strings are UTF-8 encoded. This will work fine for ASCII and UTF-8 strings, but will not work for other encodings. At some point I might add an "encoding" option to override this default encoding, and/or a "raw" mode that just deals with Buffers (rather than Strings) when the encoding is not known.
- node-radius does not support non-standard VSAs (where type or length field for attributes are not one octet each).
- node-radius does not support special decoding/encoding for the following attribute types: ipv6addr, ifid, ipv6prefix, short. If node-radius encounters a type it doesn't support, node-radius will return a raw Buffer when decoding, and expect a Buffer when encoding.
- node-radius does not support any password encryption types other than that defined by RFC2865 for User-Password (e.g. does not support Tunnel-Password).

But, on the plus-side, unlike many other RADIUS libraries node-radius supports encrypting/decrypting passwords longer than 16 bytes!
