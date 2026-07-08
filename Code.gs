/**
 * ============================================================
 * Code.gs — 婚活プロフィール 共有バックエンド
 * ------------------------------------------------------------
 * スプレッドシート「konkatsuapp_selfintroduction_sheet」
 * シート名「sheet」（1行目=ヘッダー固定、2行目以降にGASが書き込む）
 *
 * 列（1行目のヘッダー文字列と一致させること）:
 *   id / cipherText / encryptedKey / ownerHash / viewerHash / status /
 *   schemaVersion / createdAt / updatedAt / firstViewedAt / lastViewedAt / viewCount
 *
 * ------------------------------------------------------------
 * 事前準備（スクリプトプロパティ / [プロジェクトの設定]→[スクリプト プロパティ]）
 *   SPREADSHEET_ID  : このスプレッドシートのID（URLの /d/ と /edit の間の文字列）
 *   AES_KEY_B64     : generateSecrets_() を実行してログに出た値を貼る
 *   HASH_SALT       : generateSecrets_() を実行してログに出た値を貼る
 *   LIFF_CHANNEL_ID : LIFF IDの「-」より前の数字部分（例 "2010606389-v29ZSV0f" なら "2010606389"）
 *
 * デプロイ：[デプロイ]→[新しいデプロイ]→種類「ウェブアプリ」
 *   実行するユーザー：自分
 *   アクセスできるユーザー：全員
 *   発行されたURLを app.js の WEB_APP_URL に設定する。
 * ============================================================
 */

var SHEET_NAME_ = 'sheet';

/* ------------------------------------------------------------
   初回セットアップ用：この関数だけはApps Scriptエディタから
   手動で一度実行し、ログに出力された2つの値をスクリプトプロパティ
   （AES_KEY_B64 / HASH_SALT）に貼り付けてください。
   ------------------------------------------------------------ */
function generateSecrets_() {
  var keyBytes = [];
  var raw = Utilities.getUuid() + Utilities.getUuid() + Utilities.getUuid();
  var digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, raw)
    .map(function (b) { return b & 0xFF; });
  // SHA-256は32byte＝AES-256の鍵長にちょうど一致
  var aesKeyB64 = Utilities.base64Encode(digest);
  var salt = Utilities.getUuid() + '-' + Utilities.getUuid();
  Logger.log('AES_KEY_B64 = ' + aesKeyB64);
  Logger.log('HASH_SALT   = ' + salt);
  Logger.log('↑ この2行の値を [プロジェクトの設定]→[スクリプト プロパティ] に登録してください。');
}

/* ------------------------------------------------------------
   スプレッドシート／シートの取得
   ------------------------------------------------------------ */
function getSheet_() {
  var props = PropertiesService.getScriptProperties();
  var ssId = props.getProperty('SPREADSHEET_ID');
  if (!ssId) throw new Error('スクリプトプロパティ SPREADSHEET_ID が未設定です。');
  var ss = SpreadsheetApp.openById(ssId);
  var sheet = ss.getSheetByName(SHEET_NAME_);
  if (!sheet) throw new Error('シート「' + SHEET_NAME_ + '」が見つかりません。');
  return sheet;
}

/** 1行目のヘッダーから { 列名: 列番号(1始まり) } のマップを作る */
function getHeaderMap_(sheet) {
  var lastCol = Math.max(sheet.getLastColumn(), 1);
  var headers = sheet.getRange(1, 1, 1, lastCol).getValues()[0];
  var map = {};
  headers.forEach(function (h, i) { if (h) map[String(h).trim()] = i + 1; });
  return map;
}

/** データ行(2行目〜)を配列で読み込み、{ rowIndex, row:{列名:値} } のリストにする */
function readAllRows_(sheet, headerMap) {
  var lastRow = sheet.getLastRow();
  if (lastRow < 2) return [];
  var lastCol = sheet.getLastColumn();
  var values = sheet.getRange(2, 1, lastRow - 1, lastCol).getValues();
  return values.map(function (arr, i) {
    var row = {};
    Object.keys(headerMap).forEach(function (name) { row[name] = arr[headerMap[name] - 1]; });
    return { rowIndex: i + 2, row: row };
  });
}

function findByOwnerHash_(sheet, headerMap, ownerHash, wantStatus) {
  var rows = readAllRows_(sheet, headerMap);
  for (var i = 0; i < rows.length; i++) {
    if (rows[i].row.ownerHash === ownerHash && (!wantStatus || rows[i].row.status === wantStatus)) {
      return rows[i];
    }
  }
  return null;
}
function findById_(sheet, headerMap, id) {
  var rows = readAllRows_(sheet, headerMap);
  for (var i = 0; i < rows.length; i++) {
    if (rows[i].row.id === id) return rows[i];
  }
  return null;
}

/** { 列名: 値 } を渡された行番号のセルへ書き込む（存在する列だけ更新） */
function updateCells_(sheet, headerMap, rowIndex, patch) {
  Object.keys(patch).forEach(function (name) {
    var col = headerMap[name];
    if (!col) return;
    sheet.getRange(rowIndex, col).setValue(patch[name]);
  });
}

/** 新規行を追加（ヘッダー順に合わせて配列を組み立てる） */
function appendRowByHeader_(sheet, headerMap, obj) {
  var lastCol = sheet.getLastColumn();
  var arr = new Array(lastCol).fill('');
  Object.keys(obj).forEach(function (name) {
    var col = headerMap[name];
    if (col) arr[col - 1] = obj[name];
  });
  sheet.appendRow(arr);
}

/* ------------------------------------------------------------
   LINE IDのハッシュ化（秘密saltを使ったHMAC-SHA256・一方向）
   スプレッドシートを閲覧できる管理者がいても、このsaltを知らない
   限りLINEユーザーIDから逆算・特定することはできない。
   ------------------------------------------------------------ */
function hmacHex_(text) {
  var salt = PropertiesService.getScriptProperties().getProperty('HASH_SALT');
  if (!salt) throw new Error('スクリプトプロパティ HASH_SALT が未設定です。');
  var sig = Utilities.computeHmacSha256Signature(text, salt);
  return sig.map(function (b) {
    var v = b < 0 ? b + 256 : b;
    return ('0' + v.toString(16)).slice(-2);
  }).join('');
}

/* ------------------------------------------------------------
   LIFFのIDトークンをLINEのサーバーで検証し、userId(sub)を取得する。
   なりすまし防止のため、クライアントから送られたuserIdを直接
   信用せず、必ずこの検証を経由する。
   ------------------------------------------------------------ */
function verifyLineIdToken_(idToken) {
  if (!idToken) throw new Error('idTokenがありません');
  var channelId = PropertiesService.getScriptProperties().getProperty('LIFF_CHANNEL_ID');
  if (!channelId) throw new Error('スクリプトプロパティ LIFF_CHANNEL_ID が未設定です。');

  var resp = UrlFetchApp.fetch('https://api.line.me/oauth2/v2.1/verify', {
    method: 'post',
    payload: { id_token: idToken, client_id: channelId },
    muteHttpExceptions: true
  });
  var json = JSON.parse(resp.getContentText());
  if (resp.getResponseCode() !== 200 || !json.sub) {
    throw new Error('idTokenの検証に失敗しました: ' + resp.getContentText());
  }
  if (String(json.aud) !== String(channelId)) {
    throw new Error('idTokenのaudが一致しません');
  }
  return json.sub; // LINEのuserId
}

function jsonOut_(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(ContentService.MimeType.JSON);
}
function nowIso_() { return new Date().toISOString(); }

/* ============================================================
   action = save : プロフィールを暗号化して保存（同一LINEアカウントなら上書き）
   ============================================================ */
function handleSave_(payload) {
  var userId = verifyLineIdToken_(payload.idToken);
  var ownerHash = hmacHex_(userId);
  var sheet = getSheet_();
  var headerMap = getHeaderMap_(sheet);
  var now = nowIso_();
  var cipherText = aesEncryptToBase64_(JSON.stringify(payload.data || {}));

  var lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    var found = findByOwnerHash_(sheet, headerMap, ownerHash, 'active');
    var id;
    if (found) {
      id = found.row.id;
      updateCells_(sheet, headerMap, found.rowIndex, { cipherText: cipherText, updatedAt: now });
    } else {
      id = Utilities.getUuid();
      appendRowByHeader_(sheet, headerMap, {
        id: id, cipherText: cipherText, encryptedKey: '', ownerHash: ownerHash, viewerHash: '',
        status: 'active', schemaVersion: 1, createdAt: now, updatedAt: now,
        firstViewedAt: '', lastViewedAt: '', viewCount: 0
      });
    }
    return { ok: true, id: id };
  } finally {
    lock.releaseLock();
  }
}

/* ============================================================
   action = revoke : 自分のアクティブな共有リンクを無効化する
   ============================================================ */
function handleRevoke_(payload) {
  var userId = verifyLineIdToken_(payload.idToken);
  var ownerHash = hmacHex_(userId);
  var sheet = getSheet_();
  var headerMap = getHeaderMap_(sheet);

  var lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    var found = findByOwnerHash_(sheet, headerMap, ownerHash, 'active');
    if (!found) return { ok: false, reason: 'not_found' };
    updateCells_(sheet, headerMap, found.rowIndex, { status: 'revoked', updatedAt: nowIso_() });
    return { ok: true };
  } finally {
    lock.releaseLock();
  }
}

/* ============================================================
   action = view : 共有リンクを開いたときの閲覧制御＋復号
   ------------------------------------------------------------
   ルール:
   ・本人（ownerHashと一致）は何度でも閲覧可能（カウントは更新しない）
   ・viewerHashが空 → 初めて開いた他人として登録し、閲覧を許可
   ・viewerHashが自分と一致 → 同一人物の再訪問として閲覧を許可
   ・それ以外（別人） → 閲覧不可（forbidden）＝転送されたリンクを保護
   ============================================================ */
function handleView_(id, idToken) {
  var sheet = getSheet_();
  var headerMap = getHeaderMap_(sheet);

  var found = findById_(sheet, headerMap, id);
  if (!found) return { ok: false, reason: 'not_found' };
  if (found.row.status !== 'active') return { ok: false, reason: 'revoked' };

  var viewerHash;
  try {
    var userId = verifyLineIdToken_(idToken);
    viewerHash = hmacHex_(userId);
  } catch (e) {
    return { ok: false, reason: 'auth_failed' };
  }

  var isOwner = false;
  var lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    // ロック取得後に最新状態を読み直す（競合対策）
    found = findById_(sheet, headerMap, id);
    if (!found || found.row.status !== 'active') return { ok: false, reason: 'revoked' };
    var row = found.row;
    var now = nowIso_();
    isOwner = (viewerHash === row.ownerHash);

    if (isOwner) {
      // 本人の確認閲覧。閲覧者情報・カウントは変更しない。
    } else if (!row.viewerHash) {
      updateCells_(sheet, headerMap, found.rowIndex, {
        viewerHash: viewerHash, firstViewedAt: now, lastViewedAt: now, viewCount: 1
      });
    } else if (row.viewerHash === viewerHash) {
      updateCells_(sheet, headerMap, found.rowIndex, {
        lastViewedAt: now, viewCount: (parseInt(row.viewCount, 10) || 0) + 1
      });
    } else {
      return { ok: false, reason: 'forbidden' };
    }
  } finally {
    lock.releaseLock();
  }

  var plain = aesDecryptFromBase64_(found.row.cipherText);
  return { ok: true, isOwner: isOwner, data: JSON.parse(plain) };
}

/* ============================================================
   エントリーポイント
   ============================================================ */
function doGet(e) {
  try {
    var action = e.parameter.action;
    if (action === 'view') {
      return jsonOut_(handleView_(e.parameter.id, e.parameter.idToken));
    }
    if (action === 'ping') {
      return jsonOut_({ ok: true, message: 'pong' });
    }
    return jsonOut_({ ok: false, reason: 'unknown_action' });
  } catch (err) {
    return jsonOut_({ ok: false, reason: 'server_error', message: String(err) });
  }
}

function doPost(e) {
  try {
    var payload = JSON.parse(e.postData.contents);
    if (payload.action === 'save') return jsonOut_(handleSave_(payload));
    if (payload.action === 'revoke') return jsonOut_(handleRevoke_(payload));
    return jsonOut_({ ok: false, reason: 'unknown_action' });
  } catch (err) {
    return jsonOut_({ ok: false, reason: 'server_error', message: String(err) });
  }
}
