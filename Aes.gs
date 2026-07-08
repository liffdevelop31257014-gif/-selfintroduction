/**
 * ============================================================
 * Aes.gs
 * ------------------------------------------------------------
 * Google Apps Script には暗号化のための標準API（AES等）が無いため、
 * FIPS-197仕様書に基づき AES-256-CBC（PKCS#7パディング）を自前実装。
 *
 * ※このロジックは実装前に Node.js 環境で以下を確認済みです。
 *   ・NIST公式テストベクタ（FIPS-197 Appendix C.1 / C.3）と一致
 *   ・Node.js の openssl 実装（crypto.createCipheriv('aes-256-cbc')）の
 *     出力とバイト単位で完全一致
 *
 * 外部から呼ぶのは下記2関数のみでOK：
 *   aesEncryptToBase64_(plainText)  … 文字列を暗号化してBase64文字列を返す
 *   aesDecryptFromBase64_(b64)      … Base64文字列を復号して元の文字列を返す
 * ============================================================
 */

/* ---- GF(2^8) 掛け算（AESの規約多項式 x^8+x^4+x^3+x+1 を使用） ---- */
function gfMulti_(a, b) {
  var p = 0;
  for (var i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    var hi = a & 0x80;
    a = (a << 1) & 0xFF;
    if (hi) a ^= 0x1B;
    b >>= 1;
  }
  return p;
}
function gfInverse_(a) {
  if (a === 0) return 0;
  for (var x = 1; x < 256; x++) { if (gfMulti_(a, x) === 1) return x; }
  return 0;
}
function rotl8_(x, n) { return ((x << n) | (x >>> (8 - n))) & 0xFF; }

/* ---- S-box / 逆S-box をその場で算出（ハードコードした表を使わないため写し間違いが起きない） ---- */
var AES_SBOX_ = (function () {
  var box = new Array(256);
  for (var i = 0; i < 256; i++) {
    var inv = gfInverse_(i);
    box[i] = inv ^ rotl8_(inv, 1) ^ rotl8_(inv, 2) ^ rotl8_(inv, 3) ^ rotl8_(inv, 4) ^ 0x63;
  }
  return box;
})();
var AES_INV_SBOX_ = (function () {
  var box = new Array(256);
  for (var i = 0; i < 256; i++) box[AES_SBOX_[i]] = i;
  return box;
})();
var AES_RCON_ = (function () {
  var r = [0x00], c = 1;
  for (var i = 1; i < 15; i++) { r.push(c); c = gfMulti_(c, 2); }
  return r;
})();

/* ---- 鍵拡張（AES-256 = Nk8 / Nr14） ---- */
function aesKeyExpansion_(key) {
  var Nk = key.length / 4, Nr = Nk + 6, Nb = 4;
  var w = [];
  for (var i = 0; i < Nk; i++) w.push([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
  for (var i = Nk; i < Nb * (Nr + 1); i++) {
    var temp = w[i - 1].slice();
    if (i % Nk === 0) {
      temp = [temp[1], temp[2], temp[3], temp[0]].map(function (b) { return AES_SBOX_[b]; });
      temp[0] ^= AES_RCON_[i / Nk];
    } else if (Nk > 6 && i % Nk === 4) {
      temp = temp.map(function (b) { return AES_SBOX_[b]; });
    }
    var prev = w[i - Nk];
    w.push([prev[0] ^ temp[0], prev[1] ^ temp[1], prev[2] ^ temp[2], prev[3] ^ temp[3]]);
  }
  return { w: w, Nr: Nr };
}

function addRoundKey_(state, w, round) {
  for (var c = 0; c < 4; c++) {
    var word = w[round * 4 + c];
    for (var r = 0; r < 4; r++) state[r][c] ^= word[r];
  }
}
function subBytes_(state, box) {
  for (var r = 0; r < 4; r++) for (var c = 0; c < 4; c++) state[r][c] = box[state[r][c]];
}
function shiftRows_(state) {
  for (var r = 1; r < 4; r++) {
    var row = state[r];
    state[r] = row.slice(r).concat(row.slice(0, r));
  }
}
function invShiftRows_(state) {
  for (var r = 1; r < 4; r++) {
    var row = state[r], n = 4 - r;
    state[r] = row.slice(n).concat(row.slice(0, n));
  }
}
function mixColumns_(state) {
  for (var c = 0; c < 4; c++) {
    var a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c];
    state[0][c] = gfMulti_(a0, 2) ^ gfMulti_(a1, 3) ^ a2 ^ a3;
    state[1][c] = a0 ^ gfMulti_(a1, 2) ^ gfMulti_(a2, 3) ^ a3;
    state[2][c] = a0 ^ a1 ^ gfMulti_(a2, 2) ^ gfMulti_(a3, 3);
    state[3][c] = gfMulti_(a0, 3) ^ a1 ^ a2 ^ gfMulti_(a3, 2);
  }
}
function invMixColumns_(state) {
  for (var c = 0; c < 4; c++) {
    var a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c];
    state[0][c] = gfMulti_(a0, 14) ^ gfMulti_(a1, 11) ^ gfMulti_(a2, 13) ^ gfMulti_(a3, 9);
    state[1][c] = gfMulti_(a0, 9) ^ gfMulti_(a1, 14) ^ gfMulti_(a2, 11) ^ gfMulti_(a3, 13);
    state[2][c] = gfMulti_(a0, 13) ^ gfMulti_(a1, 9) ^ gfMulti_(a2, 14) ^ gfMulti_(a3, 11);
    state[3][c] = gfMulti_(a0, 11) ^ gfMulti_(a1, 13) ^ gfMulti_(a2, 9) ^ gfMulti_(a3, 14);
  }
}
function bytesToState_(bytes) {
  var state = [[], [], [], []];
  for (var i = 0; i < 16; i++) state[i % 4][Math.floor(i / 4)] = bytes[i];
  return state;
}
function stateToBytes_(state) {
  var out = new Array(16);
  for (var i = 0; i < 16; i++) out[i] = state[i % 4][Math.floor(i / 4)];
  return out;
}
function aesEncryptBlock_(block16, w, Nr) {
  var state = bytesToState_(block16);
  addRoundKey_(state, w, 0);
  for (var round = 1; round < Nr; round++) {
    subBytes_(state, AES_SBOX_);
    shiftRows_(state);
    mixColumns_(state);
    addRoundKey_(state, w, round);
  }
  subBytes_(state, AES_SBOX_);
  shiftRows_(state);
  addRoundKey_(state, w, Nr);
  return stateToBytes_(state);
}
function aesDecryptBlock_(block16, w, Nr) {
  var state = bytesToState_(block16);
  addRoundKey_(state, w, Nr);
  for (var round = Nr - 1; round >= 1; round--) {
    invShiftRows_(state);
    subBytes_(state, AES_INV_SBOX_);
    addRoundKey_(state, w, round);
    invMixColumns_(state);
  }
  invShiftRows_(state);
  subBytes_(state, AES_INV_SBOX_);
  addRoundKey_(state, w, 0);
  return stateToBytes_(state);
}

/* ---- PKCS#7 パディング ---- */
function pkcs7Pad_(bytes) {
  var padLen = 16 - (bytes.length % 16);
  var out = bytes.slice();
  for (var i = 0; i < padLen; i++) out.push(padLen);
  return out;
}
function pkcs7Unpad_(bytes) {
  var padLen = bytes[bytes.length - 1];
  if (padLen < 1 || padLen > 16 || padLen > bytes.length) throw new Error('不正なパディングです（復号鍵が異なる可能性があります）');
  for (var i = bytes.length - padLen; i < bytes.length; i++) {
    if (bytes[i] !== padLen) throw new Error('不正なパディングです（復号鍵が異なる可能性があります）');
  }
  return bytes.slice(0, bytes.length - padLen);
}
function xorBlock_(a, b) { return a.map(function (v, i) { return v ^ b[i]; }); }

/* ---- CBCモード ---- */
function cbcEncrypt_(ptBytes, keyBytes, ivBytes) {
  var kw = aesKeyExpansion_(keyBytes);
  var padded = pkcs7Pad_(ptBytes);
  var prev = ivBytes, out = [];
  for (var i = 0; i < padded.length; i += 16) {
    var block = padded.slice(i, i + 16);
    var enc = aesEncryptBlock_(xorBlock_(block, prev), kw.w, kw.Nr);
    out = out.concat(enc);
    prev = enc;
  }
  return out;
}
function cbcDecrypt_(ctBytes, keyBytes, ivBytes) {
  var kw = aesKeyExpansion_(keyBytes);
  var prev = ivBytes, out = [];
  for (var i = 0; i < ctBytes.length; i += 16) {
    var block = ctBytes.slice(i, i + 16);
    var dec = aesDecryptBlock_(block, kw.w, kw.Nr);
    out = out.concat(xorBlock_(dec, prev));
    prev = block;
  }
  return pkcs7Unpad_(out);
}

/* ---- byte(-128〜127を含む) を 0〜255 に正規化 ---- */
function toUnsignedBytes_(byteArr) {
  return byteArr.map(function (b) { return b & 0xFF; });
}

/* ---- ランダムなIV(16byte)を生成 ----
   Apps Script に暗号論的乱数生成APIは無いが、Utilities.getUuid() は
   内部的に安全な乱数(UUID v4)を使っているため、それを複数個SHA-256で
   ハッシュして16byteを取り出すことで十分なランダム性を確保する。 */
function generateRandomBytes_(len) {
  var seed = Utilities.getUuid() + Utilities.getUuid() + new Date().getTime() + Math.random();
  var digest = toUnsignedBytes_(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, seed));
  while (digest.length < len) {
    seed = Utilities.getUuid() + digest.join(',');
    digest = digest.concat(toUnsignedBytes_(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, seed)));
  }
  return digest.slice(0, len);
}

/* ---- スクリプトプロパティから32byteのAES鍵を取得 ---- */
function getAesKeyBytes_() {
  var b64 = PropertiesService.getScriptProperties().getProperty('AES_KEY_B64');
  if (!b64) throw new Error('スクリプトプロパティ AES_KEY_B64 が未設定です。generateSecrets_() を実行して値を設定してください。');
  var bytes = toUnsignedBytes_(Utilities.base64Decode(b64));
  if (bytes.length !== 32) throw new Error('AES_KEY_B64 は32byte(256bit)である必要があります。');
  return bytes;
}

/* ---- 文字列(UTF-8) ⇄ byte配列 ---- */
function utf8ToBytes_(str) {
  return toUnsignedBytes_(Utilities.newBlob(str).getBytes());
}
function bytesToUtf8_(bytes) {
  return Utilities.newBlob(bytes, 'application/octet-stream').getDataAsString('UTF-8');
}

/* ============================================================
   外部公開関数
   ============================================================ */

/** 文字列を暗号化し、"IV+暗号文" をBase64にしたものを返す */
function aesEncryptToBase64_(plainText) {
  var key = getAesKeyBytes_();
  var iv = generateRandomBytes_(16);
  var ct = cbcEncrypt_(utf8ToBytes_(plainText), key, iv);
  return Utilities.base64Encode(iv.concat(ct));
}

/** aesEncryptToBase64_ で暗号化した文字列を復号して返す */
function aesDecryptFromBase64_(b64) {
  var key = getAesKeyBytes_();
  var all = toUnsignedBytes_(Utilities.base64Decode(b64));
  var iv = all.slice(0, 16);
  var ct = all.slice(16);
  var ptBytes = cbcDecrypt_(ct, key, iv);
  return bytesToUtf8_(ptBytes);
}

/**
 * 動作確認用テスト関数。Apps Scriptエディタで実行し、ログに
 * "AES self-test OK" と出れば暗号化/復号が正しく機能しています。
 */
function aesSelfTest_() {
  var key = getAesKeyBytes_();
  var msg = 'テスト　文字列 123 !@# 🎉';
  var enc = aesEncryptToBase64_(msg);
  var dec = aesDecryptFromBase64_(enc);
  if (dec !== msg) throw new Error('AES self-test FAILED: ' + dec);
  Logger.log('AES self-test OK. cipher length=' + enc.length);
}
