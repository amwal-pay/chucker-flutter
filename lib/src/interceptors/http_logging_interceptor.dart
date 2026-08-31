import 'dart:async';

import 'package:chopper/chopper.dart';
import 'package:chucker_flutter/src/helpers/sensitive_data_redactor.dart';
import 'package:chucker_flutter/src/loggers/logger.dart';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

///Logs http request and response data
///
///Console output is a debug-only convenience: it is skipped entirely outside
///debug builds, and every header and body passes through the same redactor
///that guards the persisted inspection store, so credentials and card data
///never reach logcat/stdout verbatim.
class ChuckerHttpLoggingInterceptor implements Interceptor {
  @override
  FutureOr<Response<BodyType>> intercept<BodyType>(
    Chain<BodyType> chain,
  ) async {
    if (!kDebugMode) return chain.proceed(chain.request);

    final requestBase = await chain.request.toBaseRequest();
    final requestUrl = SensitiveDataRedactor.redactText('${requestBase.url}');
    Logger.request('${requestBase.method} $requestUrl');
    requestBase.headers.forEach(
      (k, v) =>
          Logger.request('$k: ${SensitiveDataRedactor.redact(v, key: k)}'),
    );

    var bytes = '';
    if (requestBase is http.Request) {
      // ignore: unnecessary_cast - Cast is required for http 1.6.0+ compatibility
      final req = requestBase as http.Request;
      final body = req.body;
      if (body.isNotEmpty) {
        Logger.json(SensitiveDataRedactor.redactText(body), isRequest: true);
        bytes = ' (${req.bodyBytes.length}-byte body)';
      }
    }

    Logger.request('END ${requestBase.method}$bytes');

    final response = await chain.proceed(chain.request);

    final base = response.base.request;
    final responseUrl = SensitiveDataRedactor.redactText('${base!.url}');
    Logger.response('${response.statusCode} $responseUrl');

    response.base.headers.forEach(
      (k, v) =>
          Logger.response('$k: ${SensitiveDataRedactor.redact(v, key: k)}'),
    );

    var responseBytes = '';
    if (response.base is http.Response) {
      final resp = response.base as http.Response;
      if (resp.body.isNotEmpty) {
        Logger.json(SensitiveDataRedactor.redactText(resp.body));
        responseBytes = ' (${response.bodyBytes.length}-byte body)';
      }
    }

    Logger.response('END ${base.method}$responseBytes');
    return response;
  }
}
