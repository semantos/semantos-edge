import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

void main() {
  runApp(const BitPiggyApp());
}

class PiggyColors {
  static const paper = Color(0xfffffaf3);
  static const paper2 = Color(0xfff7efe1);
  static const paper3 = Color(0xffede2cf);
  static const ink = Color(0xff1f2a24);
  static const ink2 = Color(0xff2a4a3a);
  static const ink3 = Color(0xff4a5d52);
  static const ink4 = Color(0xff7d8a82);
  static const line = Color(0xffd9cdb5);
  static const peach = Color(0xffe8a87c);
  static const peachDeep = Color(0xffd97559);
  static const leaf = Color(0xff6e8a6a);
  static const sky = Color(0xff8aa9b5);
  static const gold = Color(0xffd9b070);
}

class BitPiggyApp extends StatelessWidget {
  const BitPiggyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'BitPiggy',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        scaffoldBackgroundColor: PiggyColors.paper,
        colorScheme: ColorScheme.fromSeed(
          seedColor: PiggyColors.leaf,
          brightness: Brightness.light,
          surface: PiggyColors.paper,
        ),
        textTheme: Theme.of(context).textTheme.apply(
          bodyColor: PiggyColors.ink,
          displayColor: PiggyColors.ink,
        ),
      ),
      home: const ControlHome(),
    );
  }
}

class DeckClaim {
  const DeckClaim({
    required this.index,
    required this.claimId,
    required this.child,
    required this.chore,
    required this.device,
    required this.payCents,
    required this.counter,
  });

  factory DeckClaim.fromJson(Map<String, dynamic> json) {
    return DeckClaim(
      index: (json['index'] as num?)?.toInt() ?? 0,
      claimId: json['claimId'] as String? ?? '',
      child: json['child'] as String? ?? 'Child',
      chore: json['chore'] as String? ?? 'Chore',
      device: json['device'] as String? ?? 'BitPiggy',
      payCents: (json['payCents'] as num?)?.toInt() ?? 0,
      counter: (json['counter'] as num?)?.toInt() ?? 0,
    );
  }

  final int index;
  final String claimId;
  final String child;
  final String chore;
  final String device;
  final int payCents;
  final int counter;

  String get shortId => claimId.length >= 8 ? claimId.substring(0, 8) : claimId;
}

class HistoryItem {
  const HistoryItem({
    required this.id,
    required this.kind,
    required this.text,
    required this.atMs,
  });

  factory HistoryItem.fromJson(Map<String, dynamic> json) {
    return HistoryItem(
      id: json['id'] as String? ?? '',
      kind: json['kind'] as String? ?? 'bridge',
      text: json['text'] as String? ?? '',
      atMs: (json['atMs'] as num?)?.toInt() ?? 0,
    );
  }

  final String id;
  final String kind;
  final String text;
  final int atMs;
}

class BridgeState {
  const BridgeState({
    required this.serialPort,
    required this.noSerial,
    required this.deviceName,
    required this.childName,
    required this.online,
    required this.lastSeenMs,
    required this.pendingClaim,
    required this.deckClaims,
    required this.history,
    required this.recentLines,
  });

  factory BridgeState.fromJson(Map<String, dynamic> json) {
    final bridge = (json['bridge'] as Map?)?.cast<String, dynamic>() ?? {};
    final device = (json['device'] as Map?)?.cast<String, dynamic>() ?? {};
    final pending = json['pendingClaim'];
    return BridgeState(
      serialPort: bridge['serialPort'] as String? ?? '',
      noSerial: bridge['noSerial'] as bool? ?? false,
      deviceName: device['name'] as String? ?? 'BitPiggy',
      childName: device['child'] as String? ?? 'Child',
      online: device['online'] as bool? ?? false,
      lastSeenMs: (device['lastSeenMs'] as num?)?.toInt(),
      pendingClaim: pending is Map
          ? DeckClaim.fromJson(pending.cast<String, dynamic>())
          : null,
      deckClaims: (json['deckClaims'] as List? ?? const [])
          .whereType<Map>()
          .map((e) => DeckClaim.fromJson(e.cast<String, dynamic>()))
          .toList(),
      history: (json['history'] as List? ?? const [])
          .whereType<Map>()
          .map((e) => HistoryItem.fromJson(e.cast<String, dynamic>()))
          .toList(),
      recentLines: (json['recentLines'] as List? ?? const [])
          .map((e) => '$e')
          .toList(),
    );
  }

  final String serialPort;
  final bool noSerial;
  final String deviceName;
  final String childName;
  final bool online;
  final int? lastSeenMs;
  final DeckClaim? pendingClaim;
  final List<DeckClaim> deckClaims;
  final List<HistoryItem> history;
  final List<String> recentLines;
}

class BitPiggyApi {
  BitPiggyApi(this.baseUrl);

  final String baseUrl;

  Uri uri(String path) => Uri.parse('$baseUrl$path');

  Future<BridgeState> fetchState() async {
    final res = await http.get(uri('/api/state'));
    if (res.statusCode >= 400) {
      throw Exception('Bridge ${res.statusCode}');
    }
    return BridgeState.fromJson(jsonDecode(res.body) as Map<String, dynamic>);
  }

  Future<BridgeState> simulateClaim() async {
    final res = await http.post(uri('/api/simulate-claim'));
    if (res.statusCode >= 400) {
      throw Exception(_error(res.body));
    }
    final body = jsonDecode(res.body) as Map<String, dynamic>;
    return BridgeState.fromJson(body['state'] as Map<String, dynamic>? ?? body);
  }

  Future<BridgeState> decide({
    required String action,
    required DeckClaim claim,
    required String note,
    int? payCents,
  }) async {
    final requestBody = <String, Object?>{
      'action': action,
      'claimId': claim.claimId,
      'note': note,
    };
    if (payCents != null) requestBody['payCents'] = payCents;
    final res = await http.post(
      uri('/api/decision'),
      headers: const {'content-type': 'application/json'},
      body: jsonEncode(requestBody),
    );
    if (res.statusCode >= 400) {
      throw Exception(_error(res.body));
    }
    final responseBody = jsonDecode(res.body) as Map<String, dynamic>;
    return BridgeState.fromJson(responseBody['state'] as Map<String, dynamic>);
  }

  String _error(String body) {
    try {
      return (jsonDecode(body) as Map<String, dynamic>)['error'] as String;
    } catch (_) {
      return body;
    }
  }
}

class ControlHome extends StatefulWidget {
  const ControlHome({super.key});

  @override
  State<ControlHome> createState() => _ControlHomeState();
}

class _ControlHomeState extends State<ControlHome> {
  late final BitPiggyApi api;
  Timer? poller;
  BridgeState? state;
  String? error;
  bool loading = true;
  bool busy = false;
  int tab = 0;
  final note = TextEditingController();

  @override
  void initState() {
    super.initState();
    api = BitPiggyApi(_defaultBridgeBase());
    refresh();
    poller = Timer.periodic(
      const Duration(seconds: 2),
      (_) => refresh(silent: true),
    );
  }

  @override
  void dispose() {
    poller?.cancel();
    note.dispose();
    super.dispose();
  }

  String _defaultBridgeBase() {
    final bridge = Uri.base.queryParameters['bridge'];
    if (bridge != null && bridge.isNotEmpty) return bridge;
    if (Uri.base.port == 4050 || Uri.base.path.startsWith('/app')) {
      return Uri.base.origin;
    }
    return 'http://localhost:4050';
  }

  Future<void> refresh({bool silent = false}) async {
    if (!silent) setState(() => loading = true);
    try {
      final next = await api.fetchState();
      if (!mounted) return;
      setState(() {
        state = next;
        error = null;
        loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        error = e.toString().replaceFirst('Exception: ', '');
        loading = false;
      });
    }
  }

  Future<void> simulateClaim() async {
    await _run(() async {
      state = await api.simulateClaim();
      tab = 0;
    });
  }

  Future<void> decide(String action, DeckClaim claim) async {
    await _run(() async {
      state = await api.decide(
        action: action,
        claim: claim,
        note: note.text.trim(),
        payCents: claim.payCents,
      );
      note.clear();
      tab = 0;
    });
  }

  Future<void> _run(Future<void> Function() task) async {
    setState(() {
      busy = true;
      error = null;
    });
    try {
      await task();
    } catch (e) {
      error = e.toString().replaceFirst('Exception: ', '');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final s = state;
    return Scaffold(
      body: SafeArea(
        child: Column(
          children: [
            Header(state: s, baseUrl: api.baseUrl, onRefresh: () => refresh()),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 4, 16, 10),
              child: SegmentedButton<int>(
                segments: const [
                  ButtonSegment(
                    value: 0,
                    icon: Icon(Icons.fact_check_outlined),
                    label: Text('Review'),
                  ),
                  ButtonSegment(
                    value: 1,
                    icon: Icon(Icons.child_care),
                    label: Text('Children'),
                  ),
                  ButtonSegment(
                    value: 2,
                    icon: Icon(Icons.developer_board),
                    label: Text('Device'),
                  ),
                ],
                selected: {tab},
                onSelectionChanged: (v) => setState(() => tab = v.first),
                style: ButtonStyle(
                  visualDensity: VisualDensity.compact,
                  backgroundColor: WidgetStateProperty.resolveWith((states) {
                    return states.contains(WidgetState.selected)
                        ? PiggyColors.paper
                        : PiggyColors.paper2;
                  }),
                ),
              ),
            ),
            if (error != null)
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
                child: ErrorStrip(error: error!),
              ),
            Expanded(
              child: loading && s == null
                  ? const Center(child: CircularProgressIndicator())
                  : IndexedStack(
                      index: tab,
                      children: [
                        ReviewView(
                          state: s,
                          busy: busy,
                          note: note,
                          onApprove: (claim) => decide('approve', claim),
                          onReject: (claim) => decide('reject', claim),
                          onSimulate: simulateClaim,
                        ),
                        ChildrenView(state: s),
                        DeviceView(state: s, onSimulate: simulateClaim),
                      ],
                    ),
            ),
          ],
        ),
      ),
    );
  }
}

class Header extends StatelessWidget {
  const Header({
    super.key,
    required this.state,
    required this.baseUrl,
    required this.onRefresh,
  });

  final BridgeState? state;
  final String baseUrl;
  final VoidCallback onRefresh;

  @override
  Widget build(BuildContext context) {
    final s = state;
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 14, 16, 10),
      child: Row(
        children: [
          const PiggyGlyph(size: 34),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'BitPiggy',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.w800),
                ),
                Text(
                  s == null ? baseUrl : '${s.childName} household control',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(color: PiggyColors.ink3, fontSize: 12),
                ),
              ],
            ),
          ),
          StatusPill(
            icon: s?.online == true
                ? Icons.wifi_tethering
                : Icons.wifi_tethering_off,
            label: s?.online == true
                ? 'live'
                : (s?.noSerial == true ? 'dry' : 'quiet'),
            tone: s?.online == true ? PiggyColors.leaf : PiggyColors.peachDeep,
          ),
          const SizedBox(width: 8),
          IconButton.filledTonal(
            onPressed: onRefresh,
            tooltip: 'Refresh',
            icon: const Icon(Icons.refresh),
          ),
        ],
      ),
    );
  }
}

class ReviewView extends StatelessWidget {
  const ReviewView({
    super.key,
    required this.state,
    required this.busy,
    required this.note,
    required this.onApprove,
    required this.onReject,
    required this.onSimulate,
  });

  final BridgeState? state;
  final bool busy;
  final TextEditingController note;
  final ValueChanged<DeckClaim> onApprove;
  final ValueChanged<DeckClaim> onReject;
  final VoidCallback onSimulate;

  @override
  Widget build(BuildContext context) {
    final s = state;
    final claim = s?.pendingClaim;
    return LayoutBuilder(
      builder: (context, constraints) {
        final wide = constraints.maxWidth >= 900;
        final pending = PendingPanel(
          claim: claim,
          busy: busy,
          note: note,
          onApprove: onApprove,
          onReject: onReject,
          onSimulate: onSimulate,
        );
        final mirror = DeviceMirror(state: s, claim: claim);
        return SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(16, 0, 16, 24),
          child: wide
              ? Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Expanded(flex: 6, child: pending),
                    const SizedBox(width: 18),
                    Expanded(flex: 4, child: mirror),
                  ],
                )
              : Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [pending, const SizedBox(height: 18), mirror],
                ),
        );
      },
    );
  }
}

class PendingPanel extends StatelessWidget {
  const PendingPanel({
    super.key,
    required this.claim,
    required this.busy,
    required this.note,
    required this.onApprove,
    required this.onReject,
    required this.onSimulate,
  });

  final DeckClaim? claim;
  final bool busy;
  final TextEditingController note;
  final ValueChanged<DeckClaim> onApprove;
  final ValueChanged<DeckClaim> onReject;
  final VoidCallback onSimulate;

  @override
  Widget build(BuildContext context) {
    final c = claim;
    return Surface(
      child: c == null
          ? SizedBox(
              height: 360,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Eyebrow('Queue'),
                  const SizedBox(height: 10),
                  const Text(
                    'All caught up.',
                    style: TextStyle(fontSize: 30, fontWeight: FontWeight.w800),
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    'No pending BitPiggy claims are waiting.',
                    style: TextStyle(color: PiggyColors.ink3),
                  ),
                  const Spacer(),
                  FilledButton.icon(
                    onPressed: busy ? null : onSimulate,
                    icon: const Icon(Icons.bolt),
                    label: const Text('Simulate claim'),
                  ),
                ],
              ),
            )
          : Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    const Eyebrow('Pending review'),
                    const Spacer(),
                    StatusPill(
                      icon: Icons.key,
                      label: c.shortId,
                      tone: PiggyColors.sky,
                    ),
                  ],
                ),
                const SizedBox(height: 18),
                KidChip(name: c.child),
                const SizedBox(height: 12),
                Text(
                  c.chore,
                  style: const TextStyle(
                    fontSize: 36,
                    fontWeight: FontWeight.w900,
                  ),
                ),
                const SizedBox(height: 10),
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    MetricPill(
                      icon: Icons.savings,
                      label: money(c.payCents),
                      sub: 'pocket',
                    ),
                    MetricPill(
                      icon: Icons.numbers,
                      label: '#${c.counter}',
                      sub: 'claim',
                    ),
                    MetricPill(
                      icon: Icons.memory,
                      label: c.device,
                      sub: 'device',
                    ),
                  ],
                ),
                const SizedBox(height: 18),
                TextField(
                  controller: note,
                  minLines: 2,
                  maxLines: 3,
                  decoration: InputDecoration(
                    hintText: 'Optional note',
                    filled: true,
                    fillColor: PiggyColors.paper2,
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(8),
                      borderSide: const BorderSide(color: PiggyColors.line),
                    ),
                  ),
                ),
                const SizedBox(height: 14),
                Wrap(
                  spacing: 10,
                  runSpacing: 10,
                  children: [
                    FilledButton.icon(
                      onPressed: busy ? null : () => onApprove(c),
                      icon: busy ? const BusyIcon() : const Icon(Icons.check),
                      label: const Text('Approve'),
                    ),
                    OutlinedButton.icon(
                      onPressed: busy ? null : () => onReject(c),
                      icon: const Icon(Icons.undo),
                      label: const Text('Not yet'),
                    ),
                  ],
                ),
              ],
            ),
    );
  }
}

class DeviceMirror extends StatelessWidget {
  const DeviceMirror({super.key, required this.state, required this.claim});

  final BridgeState? state;
  final DeckClaim? claim;

  @override
  Widget build(BuildContext context) {
    final s = state;
    final status = s?.online == true
        ? 'on Wi-Fi'
        : (s?.noSerial == true ? 'dry run' : 'serial quiet');
    return Surface(
      padding: const EdgeInsets.fromLTRB(18, 16, 18, 18),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              const Eyebrow('Live mirror'),
              const Spacer(),
              StatusPill(
                icon: Icons.circle,
                label: status,
                tone: s?.online == true ? PiggyColors.leaf : PiggyColors.ink4,
              ),
            ],
          ),
          const SizedBox(height: 18),
          Center(
            child: BitPiggyDevice(
              childName: claim?.child ?? s?.childName ?? 'Theo',
              line1: claim == null ? 'Pocket' : 'Waiting for Sam',
              line2: claim?.chore ?? money(_approvedCents(s)),
              line3: claim == null ? 'BitPiggy balance' : 'sent just now',
            ),
          ),
          const SizedBox(height: 18),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              MetricPill(
                icon: Icons.inventory_2_outlined,
                label: '${s?.deckClaims.length ?? 0}',
                sub: 'deck',
              ),
              MetricPill(
                icon: Icons.history,
                label: '${s?.history.length ?? 0}',
                sub: 'events',
              ),
            ],
          ),
        ],
      ),
    );
  }

  int _approvedCents(BridgeState? state) {
    final s = state;
    if (s == null) return 0;
    return s.history.where((h) => h.kind == 'approval').length * 100;
  }
}

class ChildrenView extends StatelessWidget {
  const ChildrenView({super.key, required this.state});

  final BridgeState? state;

  @override
  Widget build(BuildContext context) {
    final s = state;
    final child = s?.childName ?? 'Theo';
    final approvals = s?.history.where((h) => h.kind == 'approval').length ?? 0;
    final pending = s?.pendingClaim;
    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(16, 0, 16, 24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Surface(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                KidChip(name: child),
                const SizedBox(height: 18),
                Wrap(
                  spacing: 10,
                  runSpacing: 10,
                  children: [
                    MetricPill(
                      icon: Icons.account_balance_wallet,
                      label: money(approvals * 100),
                      sub: 'approved',
                    ),
                    MetricPill(
                      icon: Icons.timelapse,
                      label: pending == null ? '0' : '1',
                      sub: 'waiting',
                    ),
                    MetricPill(
                      icon: Icons.flag,
                      label: 'Sticker book',
                      sub: 'goal',
                    ),
                  ],
                ),
              ],
            ),
          ),
          const SizedBox(height: 14),
          Surface(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Eyebrow('Deck claims'),
                const SizedBox(height: 10),
                ...(s?.deckClaims ?? const <DeckClaim>[]).map(
                  (c) => ListTile(
                    dense: true,
                    contentPadding: EdgeInsets.zero,
                    leading: const Icon(
                      Icons.task_alt,
                      color: PiggyColors.leaf,
                    ),
                    title: Text(c.chore),
                    subtitle: Text('${c.device} . ${c.shortId}'),
                    trailing: Text(money(c.payCents)),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class DeviceView extends StatelessWidget {
  const DeviceView({super.key, required this.state, required this.onSimulate});

  final BridgeState? state;
  final VoidCallback onSimulate;

  @override
  Widget build(BuildContext context) {
    final s = state;
    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(16, 0, 16, 24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Surface(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Eyebrow('Bridge'),
                const SizedBox(height: 10),
                Text(
                  s?.serialPort ?? 'not connected',
                  style: const TextStyle(fontWeight: FontWeight.w700),
                ),
                const SizedBox(height: 12),
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    StatusPill(
                      icon: s?.online == true
                          ? Icons.check_circle
                          : Icons.pause_circle,
                      label: s?.online == true ? 'online' : 'quiet',
                      tone: s?.online == true
                          ? PiggyColors.leaf
                          : PiggyColors.peachDeep,
                    ),
                    StatusPill(
                      icon: Icons.usb,
                      label: s?.noSerial == true ? 'dry' : 'serial',
                      tone: PiggyColors.sky,
                    ),
                  ],
                ),
                const SizedBox(height: 14),
                OutlinedButton.icon(
                  onPressed: onSimulate,
                  icon: const Icon(Icons.bolt),
                  label: const Text('Simulate claim'),
                ),
              ],
            ),
          ),
          const SizedBox(height: 14),
          Surface(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Eyebrow('History'),
                const SizedBox(height: 8),
                ...(s?.history ?? const <HistoryItem>[])
                    .take(12)
                    .map(
                      (h) => ListTile(
                        dense: true,
                        contentPadding: EdgeInsets.zero,
                        leading: Icon(
                          _historyIcon(h.kind),
                          color: _historyColor(h.kind),
                        ),
                        title: Text(h.text),
                        subtitle: Text(h.kind),
                      ),
                    ),
              ],
            ),
          ),
          const SizedBox(height: 14),
          Surface(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Eyebrow('Serial'),
                const SizedBox(height: 8),
                Container(
                  constraints: const BoxConstraints(
                    minHeight: 180,
                    maxHeight: 340,
                  ),
                  decoration: BoxDecoration(
                    color: const Color(0xff181511),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  padding: const EdgeInsets.all(12),
                  child: SingleChildScrollView(
                    reverse: true,
                    child: Text(
                      (s?.recentLines ?? const <String>[]).take(60).join('\n'),
                      style: const TextStyle(
                        fontFamily: 'monospace',
                        color: Color(0xffeadfca),
                        fontSize: 11,
                        height: 1.35,
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  IconData _historyIcon(String kind) {
    return switch (kind) {
      'approval' => Icons.check_circle,
      'rejection' => Icons.undo,
      'claim' => Icons.task_alt,
      _ => Icons.notes,
    };
  }

  Color _historyColor(String kind) {
    return switch (kind) {
      'approval' => PiggyColors.leaf,
      'rejection' => PiggyColors.peachDeep,
      'claim' => PiggyColors.sky,
      _ => PiggyColors.ink4,
    };
  }
}

class Surface extends StatelessWidget {
  const Surface({
    super.key,
    required this.child,
    this.padding = const EdgeInsets.all(18),
  });

  final Widget child;
  final EdgeInsets padding;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: padding,
      decoration: BoxDecoration(
        color: PiggyColors.paper,
        border: Border.all(color: PiggyColors.line),
        borderRadius: BorderRadius.circular(8),
        boxShadow: [
          BoxShadow(
            color: PiggyColors.ink.withValues(alpha: 0.08),
            blurRadius: 18,
            offset: const Offset(0, 8),
          ),
        ],
      ),
      child: child,
    );
  }
}

class BitPiggyDevice extends StatelessWidget {
  const BitPiggyDevice({
    super.key,
    required this.childName,
    required this.line1,
    required this.line2,
    required this.line3,
  });

  final String childName;
  final String line1;
  final String line2;
  final String line3;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: 250,
      height: 310,
      child: Stack(
        alignment: Alignment.center,
        children: [
          Positioned.fill(child: CustomPaint(painter: DevicePainter())),
          Positioned(
            top: 48,
            child: Container(
              width: 178,
              height: 178,
              decoration: const BoxDecoration(
                shape: BoxShape.circle,
                color: Color(0xff14110f),
              ),
              padding: const EdgeInsets.all(18),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Text(
                    line1,
                    textAlign: TextAlign.center,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(
                      color: PiggyColors.peach,
                      fontSize: 12,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    line2,
                    textAlign: TextAlign.center,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(
                      color: PiggyColors.paper,
                      fontSize: 24,
                      fontWeight: FontWeight.w900,
                      height: 1.05,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    '$line3 . $childName',
                    textAlign: TextAlign.center,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(
                      color: PiggyColors.ink4,
                      fontSize: 11,
                    ),
                  ),
                ],
              ),
            ),
          ),
          Positioned(
            bottom: 38,
            child: Container(
              width: 42,
              height: 42,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: PiggyColors.peach,
                border: Border.all(
                  color: PiggyColors.ink.withValues(alpha: 0.16),
                  width: 3,
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class DevicePainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final body = Paint()..color = PiggyColors.ink2;
    final shadow = Paint()
      ..color = Colors.black.withValues(alpha: 0.16)
      ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 20);
    final rect = Rect.fromLTWH(22, 16, size.width - 44, size.height - 40);
    canvas.drawRRect(
      RRect.fromRectAndRadius(
        rect.shift(const Offset(0, 10)),
        const Radius.circular(96),
      ),
      shadow,
    );
    canvas.drawRRect(
      RRect.fromRectAndRadius(rect, const Radius.circular(96)),
      body,
    );

    final ear = Paint()..color = PiggyColors.ink2;
    canvas.drawCircle(const Offset(70, 58), 26, ear);
    canvas.drawCircle(Offset(size.width - 70, 58), 26, ear);

    final foot = Paint()..color = const Color(0xff18241d);
    canvas.drawRRect(
      RRect.fromRectAndRadius(
        Rect.fromLTWH(70, size.height - 40, 110, 18),
        const Radius.circular(12),
      ),
      foot,
    );
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}

class PiggyGlyph extends StatelessWidget {
  const PiggyGlyph({super.key, required this.size});

  final double size;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        color: PiggyColors.ink2,
        borderRadius: BorderRadius.circular(8),
      ),
      alignment: Alignment.center,
      child: Container(
        width: size * 0.42,
        height: size * 0.42,
        decoration: const BoxDecoration(
          color: PiggyColors.peach,
          shape: BoxShape.circle,
        ),
      ),
    );
  }
}

class KidChip extends StatelessWidget {
  const KidChip({super.key, required this.name});

  final String name;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
      decoration: BoxDecoration(
        color: PiggyColors.paper2,
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: PiggyColors.line),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          CircleAvatar(
            radius: 14,
            backgroundColor: PiggyColors.peach,
            child: Text(
              name.isEmpty ? '?' : name[0],
              style: const TextStyle(
                color: PiggyColors.paper,
                fontWeight: FontWeight.w800,
              ),
            ),
          ),
          const SizedBox(width: 8),
          Text(name, style: const TextStyle(fontWeight: FontWeight.w800)),
        ],
      ),
    );
  }
}

class MetricPill extends StatelessWidget {
  const MetricPill({
    super.key,
    required this.icon,
    required this.label,
    required this.sub,
  });

  final IconData icon;
  final String label;
  final String sub;

  @override
  Widget build(BuildContext context) {
    return Container(
      constraints: const BoxConstraints(minWidth: 112, minHeight: 58),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: PiggyColors.paper2,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: PiggyColors.line),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 18, color: PiggyColors.ink3),
          const SizedBox(width: 8),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(label, style: const TextStyle(fontWeight: FontWeight.w900)),
              Text(
                sub,
                style: const TextStyle(color: PiggyColors.ink4, fontSize: 11),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class StatusPill extends StatelessWidget {
  const StatusPill({
    super.key,
    required this.icon,
    required this.label,
    required this.tone,
  });

  final IconData icon;
  final String label;
  final Color tone;

  @override
  Widget build(BuildContext context) {
    return Container(
      constraints: const BoxConstraints(minHeight: 34),
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
      decoration: BoxDecoration(
        color: tone.withValues(alpha: 0.14),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: tone.withValues(alpha: 0.35)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, color: tone, size: 15),
          const SizedBox(width: 6),
          Text(
            label,
            style: TextStyle(
              color: tone,
              fontSize: 12,
              fontWeight: FontWeight.w800,
            ),
          ),
        ],
      ),
    );
  }
}

class Eyebrow extends StatelessWidget {
  const Eyebrow(this.text, {super.key});

  final String text;

  @override
  Widget build(BuildContext context) {
    return Text(
      text.toUpperCase(),
      style: const TextStyle(
        color: PiggyColors.ink4,
        fontSize: 11,
        fontWeight: FontWeight.w800,
      ),
    );
  }
}

class ErrorStrip extends StatelessWidget {
  const ErrorStrip({super.key, required this.error});

  final String error;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: PiggyColors.peachDeep.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: PiggyColors.peachDeep.withValues(alpha: 0.35),
        ),
      ),
      child: Row(
        children: [
          const Icon(
            Icons.error_outline,
            color: PiggyColors.peachDeep,
            size: 18,
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              error,
              style: const TextStyle(color: PiggyColors.peachDeep),
            ),
          ),
        ],
      ),
    );
  }
}

class BusyIcon extends StatelessWidget {
  const BusyIcon({super.key});

  @override
  Widget build(BuildContext context) {
    return const SizedBox(
      width: 16,
      height: 16,
      child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
    );
  }
}

String money(int cents) {
  if (cents.abs() < 100) return '${cents}c';
  return '\$${(cents / 100).toStringAsFixed(2)}';
}
