var fs = require('fs');
var crypto = require('crypto');

var Radius = {};

var attributes_map = {};
var dictionary_locations = [__dirname + '/../dictionaries'];

const NON_VENDOR_ATTR = -1;

Radius.add_dictionary = function(path) {
  dictionary_locations.push(path);
};

Radius.load_dictionaries = function() {
  for (var i = 0; i < dictionary_locations.length; i++) {
    var path = dictionary_locations[i];
    if (!fs.existsSync(path))
      throw "Invalid dictionary location: " + path;

    if (fs.statSync(path).isDirectory()) {
      var files = fs.readdirSync(path);
      for (var j = 0; j < files.length; j++) {
        this.load_dictionary(path + '/' + files[j]);
      }
    } else {
     this.load_dictionary(path);
    }
  }
};

Radius.load_dictionary = function(path) {
  var lines = fs.readFileSync(path, 'ascii').split("\n");

  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];

    var match = line.match(/^\s*(VENDOR)?ATTR(?:IBUTE)?\s+(\d+)?\s*(\S+)\s+(\d+)\s+(.+)/);
    if (match) {
      var vendor = match[1] ? match[2] : NON_VENDOR_ATTR;
      if (!attributes_map[vendor])
        attributes_map[vendor] = {};
      attributes_map[vendor][match[4]] = [match[3], match[5], {}];
      attributes_map[vendor][match[3]] = match[4];
      continue;
    }

    match = line.match(/^\s*(VENDOR)?VALUE\s+(\d+)?\s*(\S+)\s+(\S+)\s+(\d+)/);
    if (match) {
      var vendor = match[1] ? match[2] : NON_VENDOR_ATTR;
      attributes_map[vendor][attributes_map[vendor][match[3]]][2][match[5]] = match[4];
      continue;
    }
  }
};

Radius.unload_dictionaries = function() {
  attributes_map = {};
};

var code_map = {
  1: 'Access-Request',
  2: 'Access-Accept',
  3: 'Access-Reject',
  4: 'Accounting-Request',
  5: 'Accounting-Response',
  11: 'Access-Challenge',
  12: 'Status-Server',
  13: 'Status-Client'
};

Radius.parse = function(packet, secret) {
  if (!packet || packet.length < 4)
    throw "Invalid packet";

  var ret = {};

  ret.code = code_map[packet.readUInt8(0)];

  if (!ret.code)
    throw "Invalid packet code";

  ret.identifier = packet.readUInt8(1);
  ret.length = packet.readUInt16BE(2);

  if (packet.length < ret.length)
    throw "Incomplete packet";

  this.request_authenticator = packet.slice(4, 20);
  this.secret = secret;

  var attrs = packet.slice(20, ret.length);
  ret.attributes = {};
  ret.raw_attributes = [];

  this.parse_attributes(attrs, ret.attributes, NON_VENDOR_ATTR, ret.raw_attributes);

  return ret;
};

Radius.parse_attributes = function(data, attr_hash, vendor, raw_attrs) {
  var type, length, value;
  while (data.length > 0) {
    type = data.readUInt8(0);
    length = data.readUInt8(1);
    value = data.slice(2, length);

    if (raw_attrs)
      raw_attrs.push([type, value]);

    data = data.slice(length);

    var attr_info = attributes_map[vendor] && attributes_map[vendor][type];
    if (!attr_info)
      continue;

    switch (attr_info[1]) {
    case "string": // assumes utf8 encoding for strings
    case "text":
      value = value.toString("utf8");
      break;
    case "string encrypt=1":
      value = this.decrypt_field(value);
      break;
    case "ipaddr":
      var octets = [];
      for (var i = 0; i < value.length; i++)
        octets.push(value[i]);
      value = octets.join(".");
      break;
    case "time":
    case "integer":
      value = value.readUInt32BE(0);
      value = attr_info[2][value] || value;
      break;
    }

    if (attr_info[0] == 'Vendor-Specific') {
      if (value[0] != 0x00)
        throw "Invalid vendor id";

      var vendor_attrs = attr_hash['Vendor-Specific'];
      if (!vendor_attrs)
        vendor_attrs = attr_hash['Vendor-Specific'] = {};

      this.parse_attributes(value.slice(4), vendor_attrs, value.readUInt32BE(0));
      value = vendor_attrs;
    }

    attr_hash[attr_info[0]] = value;
  }
};

Radius.decrypt_field = function(field) {
  if (field.length < 16)
    throw "Invalid password: too short";

  if (field.length > 128)
    throw "Invalid password: too long";

  if (field.length % 16 != 0)
    throw "Invalid password: not padded";

  var decrypted_field = '';
  var second_part_to_be_hashed = this.request_authenticator;

  for (var i = 0; i < field.length; i = i + 16) {
    var hasher = crypto.createHash("md5");
    hasher.update(this.secret, 'binary');
    hasher.update(second_part_to_be_hashed, 'binary');
    var hash = new Buffer(hasher.digest('binary'), 'binary');

    var xor_result = new Buffer(16);
    for (var j = 0; j < 16; j++) {
      xor_result[j] = field[i + j] ^ hash[j];
      if (xor_result[j] == 0x00) {
        xor_result = xor_result.slice(0, j);
        break;
      }
    }
    decrypted_field = decrypted_field + xor_result.toString("utf8");
    second_part_to_be_hashed = field.slice(i, i + 16);
  }

  return decrypted_field;
};

module.exports = Radius;
