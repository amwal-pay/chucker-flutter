import 'package:flutter/material.dart';

class _NoTransitionsBuilder extends PageTransitionsBuilder {
  const _NoTransitionsBuilder();

  @override
  Widget buildTransitions<T>(
    PageRoute<T> route,
    BuildContext context,
    Animation<double> animation,
    Animation<double> secondaryAnimation,
    Widget child,
  ) {
    return child;
  }
}

Map<TargetPlatform, PageTransitionsBuilder> _allPlatformsNoTransition() {
  const builder = _NoTransitionsBuilder();
  return {for (final p in TargetPlatform.values) p: builder};
}

ThemeData applyChuckerExamplePerformanceTheme(ThemeData theme) {
  return theme.copyWith(
    pageTransitionsTheme: PageTransitionsTheme(
      builders: _allPlatformsNoTransition(),
    ),
    splashFactory: NoSplash.splashFactory,
  );
}

Widget chuckerExamplePerformanceBuilder(BuildContext context, Widget? child) {
  return MediaQuery(
    data: MediaQuery.of(context).copyWith(disableAnimations: true),
    child: child ?? const SizedBox.shrink(),
  );
}
