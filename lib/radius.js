var fs = require("fs");
var util = require("util");
var crypto = require("crypto");
var path = require("path");

var Radius = {};

var attributes_map = {}, vendor_name_to_id = {};
var dictionary_locations = [path.normalize(__dirname + "/../dictionaries")];

const NOT_LOADED = 1;
const LOADING = 2;
const LOADED = 3;

var dictionaries_state = NOT_LOADED;

const NO_VENDOR = -1;

const ATTR_ID = 0;
const ATTR_NAME = 1;
const ATTR_TYPE = 2;
const ATTR_ENUM = 3;
const ATTR_REVERSE_ENUM = 4;
const ATTR_MODIFIERS = 5;

const AUTH_START = 4;
const AUTH_END = 20;
const AUTH_LENGTH = 16;

Radius.InvalidSecretError = function(msg, decoded, constr) {
  Error.captureStackTrace(this, constr || this);
  this.message = msg || 'Error';
  this.decoded = decoded;
};
util.inherits(Radius.InvalidSecretError, Error);
Radius.InvalidSecretError.prototype.name = 'Invalid Secret Error';

Radius.add_dictionary = function(file) {
  dictionary_locations.push(path.resolve(file));
};

var load_dictionaries_cbs = [];
Radius.load_dictionaries = function(callback) {
  var self = this;

  if (callback) {
    load_dictionaries_cbs.push(callback);
  }

  if (dictionaries_state == LOADING) {
    return;
  }

  dictionaries_state = LOADING;

  var locations_to_check = dictionary_locations.length, files_to_load = 0;
  var load_dict_callback = function(more_files_to_check) {
    files_to_load += more_files_to_check;
    files_to_load -= 1;
    if (locations_to_check == 0 && files_to_load == 0) {
      dictionaries_state = LOADED;
      var cbs = load_dictionaries_cbs;
      load_dictionaries_cbs = [];
      cbs.forEach(function(cb) { cb(); });
    }
  };

  dictionary_locations.forEach(function(file) {
    if (callback) {
      fs.stat(file, function(err, stats) {
        if (err) throw err;

        if (stats.isDirectory()) {
          fs.readdir(file, function(err, fs) {
            if (err) throw err;

            files_to_load += fs.length;
            locations_to_check--;
            fs.forEach(function(f) {
              self.load_dictionary(file + "/" + f, load_dict_callback);
            });
          });
        } else {
          files_to_load++;
          locations_to_check--;
          self.load_dictionary(file, load_dict_callback);
        }
      });
    } else {
      if (!fs.existsSync(file)) {
        throw new Error("Invalid dictionary location: " + file);
      }

      if (fs.statSync(file).isDirectory()) {
        var files = fs.readdirSync(file);
        for (var j = 0; j < files.length; j++) {
          self.load_dictionary(file + "/" + files[j]);
        }
      } else {
        self.load_dictionary(file);
      }
      dictionaries_state = LOADED;
    }
  });
};

Radius.load_dictionary = function(file, callback, seen_files) {
  file = path.normalize(file);
  var self = this;

  if (seen_files === undefined) {
    seen_files = {};
  }

  if (seen_files[file]) {
    if (callback) {
      callback(0);
    }
    return;
  }

  seen_files[file] = true;

  if (callback) {
    fs.readFile(file, "ascii", function(err, contents) {
      if (err) throw err;
      var includes = self._load_dictionary(contents);
      callback(includes.length);
      includes.forEach(function (i) {
        self.load_dictionary(path.join(path.dirname(file), i), callback, seen_files);
      });
    });
  } else {
    var includes = self._load_dictionary(fs.readFileSync(file, "ascii"));
    includes.forEach(function (i) {
      self.load_dictionary(path.join(path.dirname(file), i), callback, seen_files);
    });
  }
};

Radius._load_dictionary = function(content) {
  var lines = content.split("\n");

  var vendor = NO_VENDOR, includes = [];
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];

    line = line.replace(/#.*/, "").replace(/\s+/g, " ");

    var match = line.match(/^\s*VENDOR\s+(\S+)\s+(\d+)/);
    if (match) {
      vendor_name_to_id[match[1]] = match[2];
      continue;
    }

    if ((match = line.match(/^\s*BEGIN-VENDOR\s+(\S+)/))) {
      vendor = vendor_name_to_id[match[1]];
      continue;
    }

    if (line.match(/^\s*END-VENDOR/)) {
      vendor = NO_VENDOR;
      continue;
    }

    var init_entry = function(vendor, attr_id) {
      if (!attributes_map[vendor]) {
        attributes_map[vendor] = {};
      }

      if (!attributes_map[vendor][attr_id]) {
        attributes_map[vendor][attr_id] = [null, null, null, {}, {}, {}];
      }
    };

    match = line.match(/^\s*(?:VENDOR)?ATTR(?:IBUTE)?\s+(\d+)?\s*(\S+)\s+(\d+)\s+(\S+)\s*(.+)?/);
    if (match) {
      var attr_vendor = vendor;
      if (match[1] !== undefined) {
        attr_vendor = match[1];
      }

      var modifiers = {};
      if (match[5] !== undefined) {
        match[5].replace(/\s*/g, "").split(",").forEach(function(m) {
          modifiers[m] = true;
        });
      }

      init_entry(attr_vendor, match[3]);

      attributes_map[attr_vendor][match[3]][ATTR_ID] = match[3];
      attributes_map[attr_vendor][match[3]][ATTR_NAME] = match[2];
      attributes_map[attr_vendor][match[3]][ATTR_TYPE] = match[4];
      attributes_map[attr_vendor][match[3]][ATTR_MODIFIERS] = modifiers;

      var by_name = attributes_map[attr_vendor][match[2]];
      if (by_name !== undefined) {
        var by_index = attributes_map[attr_vendor][match[3]];
        [ATTR_ENUM, ATTR_REVERSE_ENUM].forEach(function(field) {
          for (var name in by_name[field]) {
            by_index[field][name] = by_name[field][name];
          }
        });
      }
      attributes_map[attr_vendor][match[2]] = attributes_map[attr_vendor][match[3]];

      continue;
    }

    match = line.match(/^\s*(?:VENDOR)?VALUE\s+(\d+)?\s*(\S+)\s+(\S+)\s+(\d+)/);
    if (match) {
      var attr_vendor = vendor;
      if (match[1] !== undefined) {
        attr_vendor = match[1];
      }

      init_entry(attr_vendor, match[2]);

      attributes_map[attr_vendor][match[2]][ATTR_ENUM][match[4]] = match[3];
      attributes_map[attr_vendor][match[2]][ATTR_REVERSE_ENUM][match[3]] = match[4];

      continue;
    }

    if ((match = line.match(/^\s*\$INCLUDE\s+(.*)/))) {
      includes.push(match[1]);
    }
  }

  return includes;
};

Radius.unload_dictionaries = function() {
  attributes_map = {};
  vendor_name_to_id = {};
  dictionaries_state = NOT_LOADED;
};

Radius.attr_name_to_id = function(attr_name, vendor_id) {
  return this._attr_to(attr_name, vendor_id, ATTR_ID);
};

Radius.attr_id_to_name = function(attr_name, vendor_id) {
  return this._attr_to(attr_name, vendor_id, ATTR_NAME);
};

Radius._attr_to = function(attr, vendor_id, target) {
  if (vendor_id === undefined) {
    vendor_id = NO_VENDOR;
  }

  if (!attributes_map[vendor_id]) {
    return;
  }

  var attr_info = attributes_map[vendor_id][attr];
  if (!attr_info) {
    return;
  }

  return attr_info[target];
};

var code_map = {
  1: "Access-Request",
  2: "Access-Accept",
  3: "Access-Reject",
  4: "Accounting-Request",
  5: "Accounting-Response",
  6: "Interim-Accounting",
  7: "Password-Request",
  8: "Password-Ack",
  9: "Password-Reject",
  10: "Accounting-Message",
  11: "Access-Challenge",
  12: "Status-Server",
  13: "Status-Client",
  21: "Resource-Free-Request",
  22: "Resource-Free-Response",
  23: "Resource-Query-Request",
  24: "Resource-Query-Response",
  25: "Alternate-Resource-Reclaim-Request",
  26: "NAS-Reboot-Request",
  27: "NAS-Reboot-Response",
  29: "Next-Passcode",
  30: "New-Pin",
  31: "Terminate-Session",
  32: "Password-Expired",
  33: "Event-Request",
  34: "Event-Response",
  40: "Disconnect-Request",
  41: "Disconnect-ACK",
  42: "Disconnect-NAK",
  43: "CoA-Request",
  44: "CoA-ACK",
  45: "CoA-NAK",
  50: "IP-Address-Allocate",
  51: "IP-Address-Release"
};

var reverse_code_map = {};
for (var code in code_map) {
  reverse_code_map[code_map[code]] = code;
}

Radius.error = function(error_msg, callback) {
  var err = error_msg;
  if (typeof(error_msg) === 'string') {
    err = new Error(error_msg);
  }

  if (callback) {
    callback(err, null);
  } else {
    throw err;
  }
};

Radius.decode = function(args) {
  return this.check_dictionaries(args, this._decode);
};

// this is a convenience method, "decode({..., no_secret: true})" will also do the job
Radius.decode_without_secret = function(args) {
  // copy args' fields without modifiying the orginal
  var nargs = {no_secret: true};
  for (var p in args) {
    nargs[p] = args[p];
  }
  return this.check_dictionaries(nargs, this._decode);
};

Radius._decode = function(args) {
  var packet = args.packet;
  if (!packet || packet.length < 4) {
    this.error("decode: packet too short", args.callback);
    return;
  }

  var ret = {};

  ret.code = code_map[packet.readUInt8(0)];

  if (!ret.code) {
    this.error("decode: invalid packet code '" + packet.readUInt8(0) + "'", args.callback);
    return;
  }

  ret.identifier = packet.readUInt8(1);
  ret.length = packet.readUInt16BE(2);

  if (packet.length < ret.length) {
    this.error("decode: incomplete packet", args.callback);
    return;
  }

  this.authenticator = ret.authenticator = packet.slice(AUTH_START, AUTH_END);
  this.no_secret = args.no_secret;
  this.secret = args.secret;

  var attrs = packet.slice(AUTH_END, ret.length);
  ret.attributes = {};
  ret.raw_attributes = [];

  try {
    this.decode_attributes(attrs, ret.attributes, NO_VENDOR, ret.raw_attributes);
  } catch(err) {
    this.error(err, args.callback);
    return;
  }

  // "Access-Request" has a random, unpredictable authenticator
  if (ret.code != "Access-Request" && ret.code.match(/Request/) && !args.no_secret) {
    var orig_authenticator = new Buffer(AUTH_LENGTH);
    packet.copy(orig_authenticator, 0, AUTH_START, AUTH_END);
    packet.fill(0, AUTH_START, AUTH_END);

    var checksum = this.calculate_packet_checksum(packet, args.secret);
    orig_authenticator.copy(packet, AUTH_START);

    if (checksum.toString() != this.authenticator.toString()) {
      this.error(new Radius.InvalidSecretError("decode: authenticator mismatch (possible shared secret mismatch)", ret), args.callback);
      return;
    }
  }

  if (args.callback) {
    args.callback(null, ret);
  } else {
    return ret;
  }
};

Radius.verify_response = function(args) {
  if (!args || !Buffer.isBuffer(args.request) || !Buffer.isBuffer(args.response)) {
    this.error("verify_response: must provide raw request and response packets");
    return;
  }

  if (!args.secret) {
    this.error("verify_response: must specify shared secret");
    return;
  }

  var got_checksum = new Buffer(AUTH_LENGTH);
  args.response.copy(got_checksum, 0, AUTH_START, AUTH_END);
  args.request.copy(args.response, AUTH_START, AUTH_START, AUTH_END);

  var expected_checksum = this.calculate_packet_checksum(args.response, args.secret);
  got_checksum.copy(args.response, AUTH_START);

  return expected_checksum.toString() == args.response.slice(AUTH_START, AUTH_END).toString();
};

Radius.decode_attributes = function(data, attr_hash, vendor, raw_attrs) {
  var type, length, value, tag;
  while (data.length > 0) {
    type = data.readUInt8(0);
    length = data.readUInt8(1);
    value = data.slice(2, length);

    if (raw_attrs) {
      raw_attrs.push([type, value]);
    }

    data = data.slice(length);
    var attr_info = attributes_map[vendor] && attributes_map[vendor][type];
    if (!attr_info) {
      continue;
    }

    if (attr_info[ATTR_MODIFIERS]["has_tag"]) {
      var first_byte = value.readUInt8(0);
      if (first_byte <= 0x1F) {
        tag = first_byte;
        value = value.slice(1);
      } else {
        tag = undefined;
      }
    }

    if (attr_info[ATTR_MODIFIERS]["encrypt=1"]) {
      value = this.decrypt_field(value);
    } else {
      switch (attr_info[ATTR_TYPE]) {
      case "string":
      case "text":
        // assumes utf8 encoding for strings
        value = value.toString("utf8");
        break;
      case "ipaddr":
        var octets = [];
        for (var i = 0; i < value.length; i++) {
          octets.push(value[i]);
        }
        value = octets.join(".");
        break;
      case "date":
        value = new Date(value.readUInt32BE(0) * 1000);
        break;
      case "time":
      case "integer":
        if (attr_info[ATTR_MODIFIERS]["has_tag"]) {
          var buf = new Buffer([0, 0, 0, 0]);
          value.copy(buf, 1);
          value = buf;
        }

        value = value.readUInt32BE(0);
        value = attr_info[ATTR_ENUM][value] || value;
        break;
      }

      if (attr_info[ATTR_NAME] == "Vendor-Specific") {
        if (value[0] !== 0x00) {
          throw new Error("Invalid vendor id");
        }

        var vendor_attrs = attr_hash["Vendor-Specific"];
        if (!vendor_attrs) {
          vendor_attrs = attr_hash["Vendor-Specific"] = {};
        }

        this.decode_attributes(value.slice(4), vendor_attrs, value.readUInt32BE(0));
        continue;
      }
    }

    if (tag !== undefined) {
      value = [tag, value];
    }

    if (attr_hash[attr_info[ATTR_NAME]] !== undefined) {
      if (!(attr_hash[attr_info[ATTR_NAME]] instanceof Array)) {
        attr_hash[attr_info[ATTR_NAME]] = [attr_hash[attr_info[ATTR_NAME]]];
      }

      attr_hash[attr_info[ATTR_NAME]].push(value);
    } else {
      attr_hash[attr_info[ATTR_NAME]] = value;
    }
  }
};

Radius.decrypt_field = function(field) {
  if (field.length < 16) {
    throw new Error("Invalid password: too short");
  }

  if (field.length > 128) {
    throw new Error("Invalid password: too long");
  }

  if (field.length % 16 != 0) {
    throw new Error("Invalid password: not padded");
  }

  return this._crypt_field(field, true).toString("utf8");
};

Radius.encrypt_field = function(field) {
  var buf = new Buffer(field.length + 15 - ((15 + field.length) % 16));
  buf.write(field, 0, field.length);

  // null-out the padding
  for (var i = field.length; i < buf.length; i++) {
    buf[i] = 0x00;
  }

  return this._crypt_field(buf, false);
};

Radius._crypt_field = function(field, is_decrypt) {
  var ret = new Buffer(0);
  var second_part_to_be_hashed = this.authenticator;

  if (this.no_secret) {
    return new Buffer(0);
  }
  if (this.secret === undefined) {
    throw new Error("Must provide RADIUS shared secret");
  }

  for (var i = 0; i < field.length; i = i + 16) {
    var hasher = crypto.createHash("md5");
    hasher.update(this.secret);
    hasher.update(second_part_to_be_hashed);
    var hash = new Buffer(hasher.digest("binary"), "binary");

    var xor_result = new Buffer(16);
    for (var j = 0; j < 16; j++) {
      xor_result[j] = field[i + j] ^ hash[j];
      if (is_decrypt && xor_result[j] == 0x00) {
        xor_result = xor_result.slice(0, j);
        break;
      }
    }
    ret = Buffer.concat([ret, xor_result]);
    second_part_to_be_hashed = is_decrypt ? field.slice(i, i + 16) : xor_result;
  }

  return ret;
};

Radius.encode_response = function(args) {
  return this.check_dictionaries(args, this._encode_response);
};

Radius._encode_response = function(args) {
  var self = this;
  var packet = args.packet;
  if (!packet) {
    this.error("encode_response: must provide packet", args.callback);
    return;
  }

  if (!args.attributes) {
    args.attributes = [];
  }

  var proxy_state_id = attributes_map[NO_VENDOR]["Proxy-State"][ATTR_ID];
  for (var i = 0; i < packet.raw_attributes.length; i++) {
    var attr = packet.raw_attributes[i];
    if (attr[0] == proxy_state_id) {
      args.attributes.push(attr);
    }
  }

  var response = this.encode({
    code: args.code,
    identifier: packet.identifier,
    authenticator: packet.authenticator,
    attributes: args.attributes,
    secret: args.secret,
    callback: args.callback
  });

  if (!args.callback) {
    return response;
  }
};

Radius.check_dictionaries = function(args, callback) {
  var self = this;
  if (dictionaries_state != LOADED) {
    if (args.callback) {
      this.load_dictionaries(function() { callback.call(self, args); });
      return;
    } else {
      this.load_dictionaries();
    }
  }

  return callback.call(this, args);
};

Radius.encode = function(args) {
  return this.check_dictionaries(args, this._encode);
};

Radius._encode = function(args) {
  var self = this;
  if (!args || args.code === undefined) {
    self.error("encode: must specify code", args.callback);
    return;
  }

  if (args.secret === undefined) {
    self.error("encode: must provide RADIUS shared secret", args.callback);
    return;
  }

  var packet = new Buffer(4096);
  var offset = 0;

  var code = reverse_code_map[args.code];
  if (code === undefined) {
    self.error("encode: invalid packet code '" + args.code + "'", args.callback);
    return;
  }

  packet.writeUInt8(+code, offset++);

  var identifier = args.identifier;
  if (identifier === undefined) {
    identifier = Math.floor(Math.random() * 256);
  }
  if (identifier > 255) {
    self.error("encode: identifier too large", args.callback);
    return;
  }
  packet.writeUInt8(identifier, offset++);

  // save room for length
  offset += 2;

  var authenticator = args.authenticator;

  if (!authenticator) {
    if (args.code == "Access-Request") {
      if (args.callback) {
        crypto.randomBytes(AUTH_LENGTH, function(err, buf) {
          if (err) {
            self.error(err, args.callback);
            return;
          }
          self._encode_with_authenticator(args, packet, offset, buf);
        });
        return;
      } else {
        authenticator = crypto.randomBytes(AUTH_LENGTH);
      }
    } else {
      authenticator = new Buffer(AUTH_LENGTH);
      authenticator.fill(0x00);
    }
  }
  return self._encode_with_authenticator(args, packet, offset, authenticator);
};

Radius._encode_with_authenticator = function(args, packet, offset, authenticator) {
  authenticator.copy(packet, offset);
  offset += AUTH_LENGTH;

  this.secret = args.secret;
  this.authenticator = authenticator;

  try {
    offset += this.encode_attributes(packet.slice(offset), args.attributes, NO_VENDOR);
  } catch (err) {
    this.error(err, args.callback);
    return;
  }

  // now write the length in
  packet.writeUInt16BE(offset, 2);

  packet = packet.slice(0, offset);

  if (args.code != "Access-Request") {
    this.calculate_packet_checksum(packet, args.secret).copy(packet, AUTH_START);
  }

  if (args.callback) {
    args.callback(null, packet);
  } else {
    return packet;
  }
};

Radius.calculate_packet_checksum = function(packet, secret) {
  var hasher = crypto.createHash("md5");
  hasher.update(packet);
  hasher.update(secret);
  return new Buffer(hasher.digest("binary"), "binary");
};

Radius.encode_attributes = function(packet, attributes, vendor) {
  if (!attributes) {
    return 0;
  }

  if (typeof(attributes) == 'object' && !Array.isArray(attributes)) {
    var array_attributes = [];
    for (var name in attributes) {
      var val = attributes[name];
      if (typeof(val) == 'object') {
        throw new Error("Cannot have nested attributes when using hash syntax. Use array syntax instead");
      }
      array_attributes.push([name, val]);
    }
    attributes = array_attributes;
  }

  var offset = 0;
  for (var i = 0; i < attributes.length; i++) {
    var attr = attributes[i];
    var attr_info = attributes_map[vendor] && attributes_map[vendor][attr[0]];
    if (!attr_info && !(attr[1] instanceof Buffer)) {
      throw new Error("encode: invalid attributes - must give Buffer for " +
        "unknown attribute '" + attr[0] + "'");
    }

    var out_value, in_value = attr[1];
    if (in_value instanceof Buffer) {
      out_value = in_value;
    } else {
      var has_tag = attr_info[ATTR_MODIFIERS]["has_tag"] && attr.length == 3;

      if (has_tag) {
        in_value = attr[2];
      }

      if (attr_info[ATTR_MODIFIERS]["encrypt=1"]) {
        out_value = this.encrypt_field(in_value);
      } else {
        switch (attr_info[ATTR_TYPE]) {
        case "string":
        case "text":
          if (in_value.length == 0) {
            continue;
          }
          out_value = new Buffer(in_value + "", "utf8");
          break;
        case "ipaddr":
          out_value = new Buffer(in_value.split("."));
          if (out_value.length != 4) {
            throw new Error("encode: invalid IP: " + in_value);
          }
          break;
        case "date":
          in_value = in_value.getTime() / 1000;
        case "time":
        case "integer":
          out_value = new Buffer(4);

          in_value = attr_info[ATTR_REVERSE_ENUM][in_value] || in_value;
          if (isNaN(in_value)) {
            throw new Error("envode: invalid attribute value: " + in_value);
          }

          out_value.writeUInt32BE(+in_value, 0);

          if (has_tag) {
            out_value = out_value.slice(1);
          }

          break;
        default:
          if (attr_info[ATTR_NAME] != "Vendor-Specific") {
            throw new Error("encode: must provide Buffer for attribute '" + attr_info[ATTR_NAME] + "'");
          }
        }

        // handle VSAs specially
        if (attr_info[ATTR_NAME] == "Vendor-Specific") {
          var vendor_id = isNaN(attr[1]) ? vendor_name_to_id[attr[1]] : attr[1];
          if (vendor_id === undefined) {
            throw new Error("encode: unknown vendor '" + attr[1] + "'");
          }

          // write the attribute id
          packet.writeUInt8(+attr_info[ATTR_ID], offset++);

          var length = this.encode_attributes(packet.slice(offset + 5), attr[2], vendor_id);

          // write in the length
          packet.writeUInt8(2 + 4 + length, offset++);
          // write in the vendor id
          packet.writeUInt32BE(+vendor_id, offset);
          offset += 4;

          offset += length;
          continue;
        }
      }
    }

    // write the attribute id
    packet.writeUInt8(attr_info ? +attr_info[ATTR_ID] : +attr[0], offset++);

    // write in the attribute length
    packet.writeUInt8(2 + out_value.length + (has_tag ? 1 : 0), offset++);

    if (has_tag) {
      packet.writeUInt8(attr[1], offset++);
    }

    // copy in the attribute value
    out_value.copy(packet, offset);
    offset += out_value.length;
  }

  return offset;
};

module.exports = Radius;
