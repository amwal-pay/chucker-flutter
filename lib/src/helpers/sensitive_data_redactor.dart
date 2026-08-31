import 'package:chucker_flutter/src/models/api_response.dart';

/// Defense-in-depth redaction applied before an inspected exchange is written
/// to local storage. Producers must still avoid attaching card, PIN, key, or
/// identity material to an HTTP-inspection record.
class SensitiveDataRedactor {
  const SensitiveDataRedactor._();

  /// Replacement used when sensitive material is removed.
  static const String redacted = '[REDACTED]';

  static const Set<String> _sensitiveKeys = <String>{
    'authorization',
    'proxyauthorization',
    'cookie',
    'setcookie',
    'token',
    'accesstoken',
    'refreshtoken',
    'sessiontoken',
    'apikey',
    'password',
    'passcode',
    'pin',
    'pinblock',
    'cvv',
    'cvc',
    'pan',
    'cardnumber',
    'track1',
    'track2',
    'track2data',
    'expiry',
    'expirydate',
    'cardholdername',
    'carddata',
    'iccdata',
    'emvdata',
    'tlv',
    'tmk',
    'tpk',
    'key',
    'cipherkey',
    'ciphertext',
    'nonceiv',
    'authenticationtag',
    'privatekey',
    'publickey',
    'secret',
    'signature',
    'hmac',
    'mac',
    'ksn',
    'dukpt',
    'securehash',
    'serialnumber',
    'simserial',
    'merchantid',
    'terminalid',
    'transactionid',
    'sessionid',
    'workflowid',
    'userid',
    'customerid',
    'operatorid',
    'tenantid',
    'accountid',
    'deviceid',
    'merchantreference',
    'orderid',
    'invoiceid',
    'rrn',
    'stan',
    'authcode',
    'approvalcode',
    'batchid',
    'batchnumber',
    'amount',
    'payload',
    'requestbody',
    'responsedata',
    'receipt',
    'receiptdata',
    'terminalactionqueueid',
    'terminalactionhistoryid',
    'merchantmenupassword',
    'email',
    'phone',
    'phonenumber',
    'latitude',
    'longitude',
    'location',
    // Keys the live request/response models carry that the list missed.
    'dateexpiration',
    'expiration',
    'otp',
    'otpcode',
    'mobile',
    'mobilenumber',
    'customertokenid',
    'paymentdata',
    'applepaypaymentdata',
    'samsungpaydata',
    'googlepaydata',
    'deviceinformation',
    'clientmail',
    'ordercustomeremail',
    'track1data',
    'track3',
    'track3data',
    'emv',
    'encryptedpin',
  };

  /// Returns a storage-safe copy of an inspected exchange.
  static ApiResponse redactApiResponse(ApiResponse value) {
    return ApiResponse(
      body: redact(value.body),
      baseUrl: redactText(value.baseUrl),
      path: redactText(value.path),
      method: value.method,
      statusCode: value.statusCode,
      connectionTimeout: value.connectionTimeout,
      contentType: value.contentType,
      headers: redactMap(value.headers),
      responseHeaders: redactMap(value.responseHeaders),
      queryParameters: redactMap(value.queryParameters),
      receiveTimeout: value.receiveTimeout,
      request: redact(value.request),
      encryptedRequest: redact(value.encryptedRequest),
      requestSize: value.requestSize,
      requestTime: value.requestTime,
      responseSize: value.responseSize,
      responseTime: value.responseTime,
      responseType: value.responseType,
      sendTimeout: value.sendTimeout,
      checked: value.checked,
      clientLibrary: value.clientLibrary,
    );
  }

  /// Recursively redacts values whose map keys identify sensitive material.
  static Map<String, dynamic> redactMap(Map<String, dynamic> value) {
    return <String, dynamic>{
      for (final entry in value.entries)
        entry.key: redact(entry.value, key: entry.key),
    };
  }

  /// Produces a safe scalar, collection, or map for local diagnostics.
  static Object? redact(Object? value, {String? key}) {
    if (key != null && _isSensitiveKey(key)) return redacted;
    if (value == null || value is num || value is bool) return value;
    if (value is String) return redactText(value);
    if (value is Map) {
      return <String, dynamic>{
        for (final entry in value.entries)
          entry.key.toString(): redact(
            entry.value,
            key: entry.key.toString(),
          ),
      };
    }
    if (value is Iterable) {
      return value.map<Object?>(redact).toList(growable: false);
    }
    return redactText(value.toString());
  }

  /// Removes embedded credentials, card data, identifiers, and key material.
  static String redactText(String input) {
    var output = input;
    output = output.replaceAll(
      RegExp(
        r'-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----',
        caseSensitive: false,
      ),
      '[REDACTED_PEM]',
    );
    output = output.replaceAllMapped(
      RegExp(r'\bBearer\s+[A-Za-z0-9._~+\-/]+=*', caseSensitive: false),
      (_) => 'Bearer $redacted',
    );
    output = output.replaceAllMapped(
      RegExp(
        r'\b(password|passcode|pin(?:block)?|cvv2?|cvc2?|pan|card[_ -]?(?:number|data)|track[12](?:data)?|expiry(?:date)?|tmk|tpk|private[_ -]?key|public[_ -]?key|secret|(?:access|refresh|session)?[_ -]?token|api[_ -]?key|authorization|signature|hmac|secure[_ -]?hash|serial[_ -]?number|merchant[_ -]?id|terminal[_ -]?id|transaction[_ -]?id|session[_ -]?id|workflow[_ -]?id|user[_ -]?id|customer[_ -]?id|operator[_ -]?id|tenant[_ -]?id|account[_ -]?id|device[_ -]?id|merchant[_ -]?reference|order[_ -]?id|invoice[_ -]?id|rrn|stan|auth[_ -]?code|approval[_ -]?code|batch[_ -]?(?:id|number)|amount|payload|request[_ -]?body|response[_ -]?data|receipt(?:[_ -]?data)?|cipher[_ -]?(?:text|key)|nonce|authentication[_ -]?tag|ksn|dukpt|emv[_ -]?data|icc[_ -]?data|tlv)\s*[:=]\s*[^,;&\s]+',
        caseSensitive: false,
      ),
      (match) => '${match.group(1)}=$redacted',
    );
    output = output.replaceAllMapped(
      RegExp(
        r'\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b',
        caseSensitive: false,
      ),
      (_) => '[REDACTED_UUID]',
    );
    output = output.replaceAllMapped(
      RegExp(r'(?:\d[ -]?){12,18}\d'),
      (_) => '[REDACTED_CARD_OR_IDENTIFIER]',
    );
    output = output.replaceAllMapped(
      RegExp(
        r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b',
        caseSensitive: false,
      ),
      (_) => '[REDACTED_EMAIL]',
    );
    output = output.replaceAllMapped(
      RegExp(r'\b[A-Za-z0-9+/=_-]{64,}\b'),
      (_) => '[REDACTED_ENCODED_VALUE]',
    );
    return output;
  }

  static bool _isSensitiveKey(String key) {
    final normalized = key.toLowerCase().replaceAll(RegExp('[^a-z0-9]'), '');
    if (_sensitiveKeys.contains(normalized)) return true;
    return _sensitiveKeys.any(
      (sensitive) =>
          normalized.endsWith(sensitive) || normalized.startsWith(sensitive),
    );
  }
}
