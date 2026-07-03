import 'package:bitpiggy_control/main.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('renders BitPiggy shell', (WidgetTester tester) async {
    await tester.pumpWidget(const BitPiggyApp());
    await tester.pump();

    expect(find.text('BitPiggy'), findsOneWidget);
    expect(find.text('Review'), findsOneWidget);
  });
}
