// Example radius client sending auth packets.

var radius = require('../lib/radius');
var dgram = require('dgram');
var util = require('util');

var secret = 'radius_secret';


var packet_good = {
  code: "Access-Request",
  secret: secret,
  identifier: 0,
  attributes: [
    ['NAS-IP-Address', '10.5.5.5'],
    ['User-Name', 'jlpicard'],
    ['User-Password', 'beverly123']
  ]
};

var packet_bad = {
  code: "Access-Request",
  secret: secret,
  identifier: 1,
  attributes: [
    ['NAS-IP-Address', '10.5.5.5'],
    ['User-Name', 'egarak'],
    ['User-Password', 'tailoredfit']
  ]
};

var client = dgram.createSocket("udp4");

client.bind(49001);

var response_count = 0;

client.on('message', function (msg, rinfo) {
  var response = radius.decode({packet: msg, secret: secret});
  var p = [packet_good, packet_bad].filter(function (packet) { return packet.identifier == response.identifier; });
  console.log('Got ' + response.code + ' for ' + p[0].attributes[1][1]);
  response_count++;
  if (response_count > 1) client.close();
});


[packet_good, packet_bad].forEach(function(packet) {
  var encoded = radius.encode(packet);
  client.send(encoded, 0, encoded.length, 1812, "localhost");
});
