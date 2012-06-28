var fs = require('fs');
var crypto = require('crypto');

var Radius = {};

var attributes_map = {};
var dictionary_locations = [__dirname + '/../dictionaries'];

const NO_VENDOR = -1;

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

const ATTR_ID = 0;
const ATTR_NAME = 1;
const ATTR_TYPE = 2;
const ATTR_ENUM = 3;
const ATTR_REVERSE_ENUM = 4;

Radius.load_dictionary = function(path) {
  var lines = fs.readFileSync(path, 'ascii').split("\n");

  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];

    var match = line.match(/^\s*(VENDOR)?ATTR(?:IBUTE)?\s+(\d+)?\s*(\S+)\s+(\d+)\s+(.+)/);
    if (match) {
      var vendor = match[1] ? match[2] : NO_VENDOR;
      if (!attributes_map[vendor])
        attributes_map[vendor] = {};
      // The seecond level is keyed by attribute name and attribute id for
      // convenience (assumes no id<->name collisions).
      // The format of the value is [id, name, type, enum values]
      attributes_map[vendor][match[4]] = [match[4], match[3], match[5], {}, {}];
      attributes_map[vendor][match[3]] = attributes_map[vendor][match[4]];
      continue;
    }

    match = line.match(/^\s*(VENDOR)?VALUE\s+(\d+)?\s*(\S+)\s+(\S+)\s+(\d+)/);
    if (match) {
      var vendor = match[1] ? match[2] : NO_VENDOR;
      attributes_map[vendor][match[3]][ATTR_ENUM][match[5]] = match[4];
      attributes_map[vendor][match[3]][ATTR_REVERSE_ENUM][match[4]] = match[5];
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

var reverse_code_map = {};
for (var code in code_map)
  reverse_code_map[code_map[code]] = code;

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

  this.parse_attributes(attrs, ret.attributes, NO_VENDOR, ret.raw_attributes);

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

    switch (attr_info[ATTR_TYPE]) {
    case "string":
    case "text":
      // assumes utf8 encoding for strings
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
      value = attr_info[ATTR_ENUM][value] || value;
      break;
    }

    if (attr_info[ATTR_NAME] == 'Vendor-Specific') {
      if (value[0] != 0x00)
        throw "Invalid vendor id";

      var vendor_attrs = attr_hash['Vendor-Specific'];
      if (!vendor_attrs)
        vendor_attrs = attr_hash['Vendor-Specific'] = {};

      this.parse_attributes(value.slice(4), vendor_attrs, value.readUInt32BE(0));
      value = vendor_attrs;
    }

    attr_hash[attr_info[ATTR_NAME]] = value;
  }
};

Radius.decrypt_field = function(field) {
  if (field.length < 16)
    throw "Invalid password: too short";

  if (field.length > 128)
    throw "Invalid password: too long";

  if (field.length % 16 != 0)
    throw "Invalid password: not padded";

  return this._crypt_field(field, true).toString("utf8");
};

Radius.encrypt_field = function(field) {
  var buf = new Buffer(field.length + (field.length % 16));
  buf.write(field, 0, field.length);

  // null-out the padding
  for (var i = field.length; i < buf.length; i++)
    buf[i] = 0x00;

  return this._crypt_field(buf, false);
};

Radius._crypt_field = function(field, is_decrypt) {
  var ret = new Buffer(0);
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
    ret = Buffer.concat([ret, xor_result]);
    second_part_to_be_hashed = is_decrypt ? field.slice(i, i + 16) : xor_result;
  }

  return ret;
};

Radius.encode = function(args) {
  if (!args || !args.code)
    throw "Invalid args: must specify code";

  var packet = new Buffer(4096);
  var offset = 0;

  var code = reverse_code_map[args.code];
  if (!code)
    throw "Invalid packet code";

  packet.writeUInt8(+code, offset);
  offset += 1;

  packet.writeUInt8(args.identifier || Math.floor(Math.random() * 255), offset);
  offset += 1;

  // save room for length
  offset += 2;

  var request_authenticator = args.request_authenticator || crypto.randomBytes(16);
  request_authenticator.copy(packet, offset);
  offset += 16;

  this.secret = args.secret;
  this.request_authenticator = request_authenticator;
  offset += this.encode_attributes(packet.slice(offset), args.attributes, NO_VENDOR);

  // now write the length in
  packet.writeUInt16BE(offset, 2);

  return packet.slice(0, offset);
};

Radius.encode_attributes = function(packet, attributes, vendor) {
  if (!attributes)
    return 0;

  var offset = 0;
  for (var i = 0; i < attributes.length; i++) {
    var attr = attributes[i];
    var attr_info = attributes_map[vendor] && attributes_map[vendor][attr[0]];
    if (!attr_info && !(attr[1] instanceof Buffer)) {
      throw "Invalid attributes in encode: must give Buffer for " +
        "unknown attribute '" + attr[0] + "'";
    }

    packet.writeUInt8(attr_info ? +attr_info[ATTR_ID] : +attr[0], offset);
    offset += 1;

    var out_value, in_value = attr[1];
    if (in_value instanceof Buffer) {
      out_value = in_value;
    } else {
      switch (attr_info[ATTR_TYPE]) {
      case "string":
      case "text":
        out_value = new Buffer(in_value + '', 'utf8');
        break;
      case "string encrypt=1":
        out_value = this.encrypt_field(in_value);
        break;
      case "ipaddr":
        out_value = new Buffer(in_value.split('.'));
        break;
      case "time":
      case "integer":
        out_value = new Buffer(4);

        in_value = attr_info[ATTR_REVERSE_ENUM][in_value] || in_value;
        if (isNaN(in_value))
          throw "Invalid attribute value: " + in_value;

        out_value.writeUInt32BE(+in_value, 0);
        break;
      case "octets":
        if (attr_info[ATTR_NAME] != "Vendor-Specific")
          throw "Must provide Buffer for attribute '" + attr_info[ATTR_NAME] + "'";
        break;
      }

      if (attr_info[ATTR_NAME] == "Vendor-Specific") {
        var length = this.encode_attributes(packet.slice(offset + 5), attr[2], attr[1]);

        if (length > 255)
          throw "Too many vendor specific attributes (try splitting them up)";

        packet.writeUInt8(2 + 4 + length, offset);
        packet.writeUInt32BE(attr[1], offset + 1);
        offset += 5 + length;
        continue;
      }
    }

    packet.writeUInt8(2 + out_value.length, offset);
    offset += 1;

    out_value.copy(packet, offset);
    offset += out_value.length;
  }

  return offset;
};

module.exports = Radius;
