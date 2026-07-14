/* ============================================================
   婚活プロフィール（自分史＆喜怒哀楽＆スケジュール） – GAS バックエンド (Code.gs)
   スプレッドシートID: 18EsNFzS77rYcL1jGiGJ-JtOCCcyDGO1dVh9FSCUJjg4
   ------------------------------------------------------------
   ・シート「sheet」のみ作成（Analyticsシートは作成しない）
   ------------------------------------------------------------
   共有リンクの扱い（ハイブリッド方式）:
   ・まだ誰にも開かれていない間は、同じid・同じリンクのまま
     中身だけ上書き更新する（＝編集してもリンクは変わらない）。
   ・誰かがそのリンクを一度開いた後にプロフィールを更新すると、
     その行は履歴として残したまま、新しいid・新しいリンクを
     発行する（＝閲覧済みのリンクの中身は勝手に変わらない）。
   ・アクセス制御（本人／初回閲覧者のみ）は他アプリと同様。
   ------------------------------------------------------------
   デプロイ方法:
   1. スプレッドシートを開き「拡張機能 > Apps Script」でこのコードを貼り付ける。
   2. 「デプロイ > 新しいデプロイ」→ 種類「ウェブアプリ」
      - 実行するユーザー: 自分
      - アクセスできるユーザー: 全員
      でデプロイする（すでに発行済みの /exec URL を app.js の
      GAS_ENDPOINT に設定済み）。
   ============================================================ */

var SPREADSHEET_ID = '18EsNFzS77rYcL1jGiGJ-JtOCCcyDGO1dVh9FSCUJjg4';
var SHEET_NAME      = 'Shares';
var SCHEMA_VERSION  = 1;

// シートの列番号（1-indexed）
var COL = {
  ID: 1, CIPHER_TEXT: 2, ENCRYPTED_KEY: 3, OWNER_HASH: 4, VIEWER_HASH: 5,
  STATUS: 6, SCHEMA_VERSION: 7, CREATED_AT: 8, UPDATED_AT: 9,
  FIRST_VIEWED_AT: 10, LAST_VIEWED_AT: 11, VIEW_COUNT: 12
};

var DATA_START_ROW = 2; // 1行目=見出し, 2行目以降がデータ


/* ------------------------------------------------------------
   エントリポイント
   ------------------------------------------------------------ */
function doGet(e) {
  try {
    var action = e.parameter.action;
    if (action === 'view') {
      return handleView(e.parameter.id, e.parameter.viewerHash);
    }
    return jsonResponse({ ok: false, reason: 'invalid_action' });
  } catch (err) {
    return jsonResponse({ ok: false, reason: 'server_error', message: String(err) });
  }
}

function doPost(e) {
  try {
    var body = JSON.parse(e.postData.contents);
    if (body.action === 'share') {
      return handleShare(body);
    }
    return jsonResponse({ ok: false, reason: 'invalid_action' });
  } catch (err) {
    return jsonResponse({ ok: false, reason: 'server_error', message: String(err) });
  }
}

function jsonResponse(obj) {
  return ContentService
    .createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}

function getSheet() {
  return SpreadsheetApp.openById(SPREADSHEET_ID).getSheetByName(SHEET_NAME);
}


/* ------------------------------------------------------------
   共有登録／更新（ハイブリッド方式）
   ・cipherText はクライアント側で AES-GCM 暗号化済みのため、
     このサーバー（および管理者）は復号鍵を一切受け取らない。
   ・id が既存行に存在し、かつ ownerHash が一致する場合：
     - その行がまだ誰にも開かれていない（VIEWER_HASH が空）
       → その行を上書き更新する（同じリンクのまま。従来通り）
     - その行はすでに誰かに開かれている
       → その行は履歴として残し、新しいidを発行して新しい行を
         追加する（＝閲覧済みのリンクの中身は変えない）
   ・id が存在しない場合（初回共有、または新しいidでの共有）：
     → 同じ ownerHash の「未閲覧」の古い行があれば削除したうえで
       新しい行を追加する（1人につき未閲覧の行は常に最大1つ）。
   ・戻り値の id は実際に使われた（更新／追加された）行の id。
     クライアント側は、送信した id と異なる id が返ってきた場合、
     新しいリンクが発行されたと判断して保存し直す必要がある。
   ------------------------------------------------------------ */
function handleShare(body) {
  var id         = body.id;
  var cipherText = body.cipherText;
  var ownerHash  = body.ownerHash;

  if (!id || !cipherText || !ownerHash) {
    return jsonResponse({ ok: false, reason: 'invalid_params' });
  }

  var lock = LockService.getScriptLock();
  lock.waitLock(30000);
  try {
    var sheet = getSheet();
    var now = new Date();

    var rowIndex = findRowById(sheet, id);

    if (rowIndex) {
      // 既存行（本人確認のためownerHashを照合）
      var existingOwnerHash  = sheet.getRange(rowIndex, COL.OWNER_HASH).getValue();
      var existingViewerHash = sheet.getRange(rowIndex, COL.VIEWER_HASH).getValue();
      if (existingOwnerHash !== ownerHash) {
        return jsonResponse({ ok: false, reason: 'forbidden' });
      }

      if (!existingViewerHash) {
        // まだ誰にも開かれていない → 同じ行・同じリンクのまま上書き
        sheet.getRange(rowIndex, COL.CIPHER_TEXT).setValue(cipherText);
        sheet.getRange(rowIndex, COL.UPDATED_AT).setValue(now);
        sheet.getRange(rowIndex, COL.STATUS).setValue('active');
        return jsonResponse({ ok: true, id: id });
      }
      // すでに誰かに開かれている → この行はそのまま残し、下で新しい行を作る
    }

    // 新しい行を追加する（id未発見、または既存行が閲覧済みだったため新規発行）。
    // 同じownerHashの「未閲覧」の古い行があれば削除して、未閲覧の行は
    // 常に最大1つになるようにする。
    removePreviousUnviewedRows(sheet, ownerHash);

    var newId = rowIndex ? Utilities.getUuid() : id;
    sheet.appendRow([
      newId, cipherText, '', ownerHash, '', 'active', SCHEMA_VERSION,
      now, now, '', '', 0
    ]);
    return jsonResponse({ ok: true, id: newId });
  } finally {
    lock.releaseLock();
  }
}

/* 同じ ownerHash の既存行のうち、まだ誰にも開かれていない
   （VIEWER_HASH が空の）行だけを削除する。
   すでに誰かが開いた行は履歴として残すため削除しない。 */
function removePreviousUnviewedRows(sheet, ownerHash) {
  var lastRow = sheet.getLastRow();
  if (lastRow < DATA_START_ROW) return;
  var values = sheet.getRange(DATA_START_ROW, 1, lastRow - DATA_START_ROW + 1, COL.VIEWER_HASH).getValues();
  for (var i = values.length - 1; i >= 0; i--) {
    var rowOwnerHash  = values[i][COL.OWNER_HASH - 1];
    var rowViewerHash = values[i][COL.VIEWER_HASH - 1];
    if (rowOwnerHash === ownerHash && !rowViewerHash) {
      sheet.deleteRow(DATA_START_ROW + i);
    }
  }
}


/* ------------------------------------------------------------
   閲覧（共有リンクを開いたとき）
   アクセス制御:
   ・本人（ownerHash と一致） → 常に許可
   ・viewerHash が未登録      → この人を初回閲覧者として登録し許可
   ・viewerHash が登録済み    → 一致すれば許可、不一致なら拒否
   ------------------------------------------------------------ */
function handleView(id, viewerHash) {
  if (!id) return jsonResponse({ ok: false, reason: 'invalid_params' });
  if (!viewerHash) return jsonResponse({ ok: false, reason: 'login_required' });

  var lock = LockService.getScriptLock();
  lock.waitLock(30000);
  try {
    var sheet = getSheet();
    var rowIndex = findRowById(sheet, id);
    if (!rowIndex) return jsonResponse({ ok: false, reason: 'not_found' });

    var row = sheet.getRange(rowIndex, 1, 1, COL.VIEW_COUNT).getValues()[0];
    var cipherText         = row[COL.CIPHER_TEXT - 1];
    var ownerHash           = row[COL.OWNER_HASH - 1];
    var existingViewerHash  = row[COL.VIEWER_HASH - 1];
    var status              = row[COL.STATUS - 1];

    if (status !== 'active') {
      return jsonResponse({ ok: false, reason: status === 'active' ? 'not_found' : status });
    }

    var now = new Date();
    var allowed = false;

    if (viewerHash === ownerHash) {
      allowed = true;
    } else if (!existingViewerHash) {
      allowed = true;
      sheet.getRange(rowIndex, COL.VIEWER_HASH).setValue(viewerHash);
      sheet.getRange(rowIndex, COL.FIRST_VIEWED_AT).setValue(now);
    } else if (existingViewerHash === viewerHash) {
      allowed = true;
    } else {
      allowed = false;
    }

    if (!allowed) return jsonResponse({ ok: false, reason: 'forbidden' });

    sheet.getRange(rowIndex, COL.LAST_VIEWED_AT).setValue(now);
    var viewCountCell = sheet.getRange(rowIndex, COL.VIEW_COUNT);
    viewCountCell.setValue((Number(viewCountCell.getValue()) || 0) + 1);

    return jsonResponse({ ok: true, cipherText: cipherText });
  } finally {
    lock.releaseLock();
  }
}

/* id (A列) からデータ行番号を探す。見つからなければ null */
function findRowById(sheet, id) {
  var lastRow = sheet.getLastRow();
  if (lastRow < DATA_START_ROW) return null;
  var ids = sheet.getRange(DATA_START_ROW, 1, lastRow - DATA_START_ROW + 1, 1).getValues();
  for (var i = 0; i < ids.length; i++) {
    if (ids[i][0] === id) return DATA_START_ROW + i;
  }
  return null;
}
