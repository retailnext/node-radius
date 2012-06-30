node-radius is a RADIUS packet encoding/decoding library for node.js written in Javascript. With node-radius you can easily decode received packets, encode packets to send, and prepare responses to received packets.

node-radius requires node.js v0.8.0. To install node-radius, clone this project, then change to the directory you want to install it in and run `npm install /path/to/cloned/node-radius`. It should be in npm soon, which will make installation easier.

Let's look at some examples of how to use node-radius:

    var radius = require('radius');

    // ... receive raw_packet from UDP socket

    var decoded = radius.decode(raw_packet, secret);

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

    var response = radius.encode_response(decoded, {
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


Method descriptions:

radius.decode(\<packet>, \<shared secret>)

Decode takes as input the raw UDP RADIUS packet (as a Buffer) and the RADIUS shared secret. Using the dictionaries available, decode parses the packet and returns an object representation of the packet. The object has the following fields:

- code: string representation of the packet code ("Access-Request", "Accounting-Response", etc)
- identifier: packet identifier number (used for duplicate packet detection)
- length: RADIUS packet length
- attributes: a hash containing all attributes the library knew how to parse
- raw_attributes: an array of arrays containing each raw attribute (attribute type and a Buffer containing the attribute value). This is mainly used by the library for generating the response packet, and would only be useful to you if you are missing relevant dictionaries and want to decode attributes yourself.


radius.encode(\<args>)

Encode takes a hash of arguments and returns a Buffer ready to be sent over the wire. The accepted arguments are:

- code (required): string representation of the packet code ("Access-Request", "Accounting-Response", etc)
- secret (required): RADIUS shared secret
- identifier (optional): packet identifer number (defaults to a random number from 0 to 255)
- attributes (optional): RADIUS attributes you want to add to the packet
- authenticator (optional): the 16 octet authenticator field (defaults to a random 16 bytes except for "Accounting-Request" messages, which sets the authenticator per RFC2866)

The attributes will typically be like the following (see above example):

    attributes: [
      [<attribute name>, <attribute value>],
      ...
    ]

If you want to send attributes that you haven't loaded a dictonary for, you can do:

    attributes: [
      [<attribute id>, <Buffer>],
      ...
    ]

Where the first item is the numeric attribute id and the second item is just a Buffer containing the value of the attribute.

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

You can specify the tag field-attribute like so (see RFC2868) :

    attributes: [
      [<attribute name>, <tag number>, <attribute value>],
      ...
    ]

If the attribute has an optional tag and you don't want to send it, then only specify the <attribute name> and the <attribute value>.


radius.encode\_response(<decoded packet>, <args>)

Encode_response prepares a response packet based on previously received packet. <decoded packet> is the output of a previous call to radius.decode. <args> is a hash similar to what encode takes:

- code (required): string representation of the packet code ("Access-Reject, "Accounting-Response", etc)
- secret (required): RADIUS shared secret
- attributes (optional): RADIUS attributes you want to add to the packet

Encode_response does a few things for you to prepare the response:
1. sets your message identifier to the identifer of the previously received packet
1. copies any "Proxy-State" attributes from the previously received packet
1. calculates the appropriate response authenticator


Dictionaries

node-radius supports reading freeradius-style RADIUS dictionary files. node-radius comes with a slew of RFC dictionary files, so you should only worry about adding any vendor-specific dictionary files you have. node-radius will load all the dictionaries it knows about (the default RFC ones and any you added) automatically the first time it needs to, so you should add your dictionaries before you start to use the module.

To add a dictionary to be loaded, use the add_dictionary function:

    var radius = require('radius');

    radius.add_dictionary('/path/to/my/dictionary');

add\_dictionary takes either a file or a directory (given a directory, it assumes everything in the directory is a dictionary file).

node-radius supports reading both the VENDORATTR and the BEGIN-VENDOR/END-VENDOR style for defining VSAs. node-radius also supports reading the following attribute modifiers: has_tag, encrypt=1.

Here are a few things that node-radius does not yet support:
 - non-standard VSAs (where type or length field for attributes are not one octet each)
 - decoding/encoding the following attribute types: date, ipv6addr, ifid, ipv6prefix, short. If it encounters a type it doesn't support, node-radius will return a raw Buffer when decoding, and expect a Buffer when encoding.
 - asynchronous interface for encoding/decoding (the only things that necessitate this are loading the dictionary files and generating the seed for the random 16 octet authenticator using openssl, both of which only happen once)

But on the plus-side, unlike many other RADIUS libraries, node-radius supports encrypting/decrypting passwords longer than 16 bytes!
