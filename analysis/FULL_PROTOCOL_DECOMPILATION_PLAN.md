# План полной декомпиляции протокола OpenConnect/AnyConnect

> Цель: создание полностью совместимого VPN-сервера (ioguard) с улучшениями.
> Дополнение к существующему анализу ocproto-research (85% v5.1).
> Правовая основа: DMCA §1201(f) — обратная инженерия для обеспечения интероперабельности.

---

## 1. Аудит текущего покрытия

### Что уже есть (ocproto-research)

| Область | Документ | Покрытие | Глубина |
|---------|----------|----------|---------|
| X-CSTP заголовки | ANALYSIS_SUMMARY.md | 14/14 | Строки + семантика |
| TLS/DTLS шифрование | CRYPTO_ANALYSIS.md | 90% | CiscoSSL → wolfSSL маппинг |
| DPD + таймеры | DPD_AND_TIMERS.md | 95% | RFC 3706, три туннеля, state machine |
| OTP/TOTP/MFA | OTP_IMPLEMENTATION.md | 85% | AggAuth, RSA SecurID, RFC 6238 |
| Сертификаты | CERTIFICATE_AUTH.md | 70% | Multi-cert, AD template OID |
| Split DNS | DNS_BEHAVIOR.md | 80% | NRPT, resolv.conf, SCDynamicStore |
| RADIUS | RADIUS_INTEGRATION.md | 60% | Cisco VSA, Framed-IP |
| Версии 5.0→5.1 | VERSION_DIFFERENCES.md | 88 фич | Dynamic split tunnel, IKEv2 PPK |
| Деплой клиента | DEPLOYMENT_GUIDE.md | 70% | predeploy/webdeploy/cloud |
| NVM/телеметрия | NVM_TELEMETRY.md | 60% | IPFIX/nvzFlow |
| Бинарный анализ | ADVANCED_BINARY_ANALYSIS.md | 127 функций | Ghidra (vpnagentd), Reko (libvpnapi) |
| Скрипт хуки | SCRIPT_HOOKS.md | 90% | OnConnect/OnDisconnect |
| OGS | OPTIMAL_GATEWAY_SELECTION.md | 70% | RTT probing |

### Критические пробелы для ioguard

| # | Пробел | Приоритет | Влияние на ioguard |
|---|--------|-----------|---------------------|
| G1 | **CSTP wire format** (бинарный фрейминг, не HTTP) | P0 | src/network/cstp.c — формат пакета после CONNECT |
| G2 | **DTLS handshake bootstrap** (реальный X-DTLS-* flow) | P0 | src/network/dtls.c — как master secret → DTLS |
| G3 | **AggAuth XML полный цикл** (все ветки) | P0 | src/auth/ — все сценарии MFA |
| G4 | **Session cookie** формат, подпись, TTL | P0 | src/core/session.c — совместимость |
| G5 | **DTLS rekey** (in-band renegotiation) | P1 | src/network/dtls.c — ротация ключей |
| G6 | **Compression negotiation** (LZS/LZ4 handshake) | P1 | src/network/compress.c |
| G7 | **Reconnect token** (X-CSTP-Reconnect-Token?) | P1 | src/core/worker.c — "Waiting to Resume" |
| G8 | **SAML/SSO через external browser** | P1 | src/auth/ — S7+ |
| G9 | **HostScan/Posture (DAP)** | P2 | Не в MVP, но для enterprise |
| G10 | **Management Tunnel (SBL)** | P2 | Windows-only, не в ioguard MVP |
| G11 | **Dynamic split tunneling** (5.1.2.42+) | P2 | src/network/dns.c |
| G12 | **IKEv2 + Post-Quantum** (5.1.8+) | P3 | Будущее, не OpenConnect |
| G13 | **NVM/eBPF телеметрия** (5.1.11+) | P3 | Prometheus в ioguard — другой подход |
| G14 | **External SSO / SAML browser flow** | P1 | src/auth/ — external-sso.pkg flow |
| G15 | **On-Demand / Always-On / TND** | P1 | Клиентский engine + серверный профиль |
| G16 | **Per-App VPN / Application Routing** | P2 | acsockd eBPF cgroup + server config |
| G17 | **Certificate Auth (cert-only + multi-cert)** | P1 | TLS client cert → group mapping |
| G18 | **VPN Profile XML schema** | P1 | Полная XSD для VPN + On-Demand + DAP |
| G19 | **VPNAPI SDK (3rd-party VPN integration)** | P2 | libvpnapi.a public API surface |
| G20 | **Post-Quantum TLS (ML-KEM/ML-DSA)** | P3 | oqsprovider.so + CiscoSSL PQ |
| G21 | **MST Transforms (install customization)** | P3 | 9 MST файлов — lockdown, FIPS, SBL |

---

## 2. План декомпиляции по фазам

### Фаза 0: Подготовка среды (1 день)

**Задачи:**
- Извлечь `vpnagentd`, `libvpnapi.so`, `libacciscossl.so`, `libvpncommoncrypt.so` из всех 4 версий (4.9, 4.10, 5.0, 5.1)
- Загрузить все 4 версии `vpnagentd` в IDA Pro 9.3 на oel-lab-gui
- Создать BinDiff-проект для всех пар версий (delta analysis)
- Настроить Wireshark с профилем DTLS + CSTP dissector (pcap с `SSLKEYLOGFILE`)
- Подготовить тестовый стенд: ASAv 9.19 (VMID 710, PLRv2 licensed) + Cisco Secure Client 5.1

**Инструменты:**
```bash
rehelp pipeline static-c     # IDA + Ghidra + radare2 + BinDiff
rehelp hint wireshark         # DTLS/TLS dissection
rehelp hint frida             # Runtime hooking
```

**Результат:** IDB-файлы с автоанализом для Stage 1, pcap-шаблоны.

---

### Фаза 1: CSTP Wire Format (P0, 2 недели)

**Цель:** полная спецификация бинарного фрейминга CSTP после HTTP CONNECT.

**Текущее состояние:** HTTP-заголовки задокументированы, но формат данных внутри туннеля — нет.

#### 1.1 Статический анализ vpnagentd

**Бинарии:** `vpnagentd` (5.1.12.146, Linux x86_64)

**Точки входа:**
- `SSL_read()` → обработчик raw bytes после HTTP CONNECT
- Строка `"STF"` (Session-Tunnel-Frame?) — предполагаемый magic
- Строки `CSTP_CONNECTED`, `CSTP_DATA`, `CSTP_DPD_REQ`, `CSTP_DPD_RESP`, `CSTP_DISCONNECT`, `CSTP_KEEPALIVE`

**Методика:**
1. IDA Pro: xref на `SSL_read` в vpnagentd → найти функцию-обработчик фреймов
2. Восстановить `cstp_frame_t` через Reko struct recovery
3. Определить: заголовок фрейма (magic + type + length), payload, padding

**Ожидаемый формат (гипотеза, из ocserv/openconnect):**
```c
struct cstp_frame {
    uint8_t  type;      // DATA=0x00, DPD_REQ=0x03, DPD_RESP=0x04,
                        // DISCONNECT=0x05, KEEPALIVE=0x07, COMPRESSED=0x08
    uint8_t  reserved[3];
    uint16_t length;    // big-endian, payload length
    uint8_t  payload[];
};
```

**Валидация:**
- Wireshark capture: ASAv 9.19 ↔ CSC 5.1 (SSLKEYLOGFILE для расшифровки TLS)
- Frida hook на `SSL_read`/`SSL_write` в vpnagentd: hex dump первых 16 байт каждого фрейма
- Сравнить с исходниками openconnect (`cstp.c`, `oncp.c`)

**Связь с ioguard:** `src/network/cstp.h` / `cstp.c` — структуры `iog_cstp_frame_t`, функции `iog_cstp_parse_frame()`, `iog_cstp_build_frame()`

#### 1.2 HTTP CONNECT handshake (server side)

**Точки входа:**
- ASA lina: строки `CONNECT /CSCOSSLC/tunnel`, `X-CSTP-`, `X-DTLS-`
- vpnagentd: строки `HTTP/1.1 200`, `X-CSTP-Protocol`

**Задачи:**
1. Полный список заголовков ответа сервера (все `X-CSTP-*`, `X-DTLS-*`)
2. Порядок заголовков (клиент может зависеть от порядка)
3. Формат `X-DTLS-Session-ID` и `X-DTLS-Master-Secret` (hex? base64? длина?)
4. Есть ли заголовки, которые клиент парсит, но нет в документации?

**Методика:**
- Ghidra: decompile функцию обработки CONNECT в ASA lina (0x55710b820000 + offset)
- Альтернатива: `strings lina | grep -i 'x-cstp\|x-dtls' | sort -u` + xref в IDA
- Wireshark capture для верификации

**Результат:** RFC-style документ `CSTP_WIRE_FORMAT.md` со всеми полями, типами, примерами.

---

### Фаза 2: DTLS Bootstrap и Rekey (P0/P1, 2 недели)

**Цель:** как CSTP-сессия bootstraps DTLS, и как происходит rekey.

#### 2.1 DTLS Session Setup

**Текущее знание:** X-DTLS-Session-ID + X-DTLS-Master-Secret передаются в CSTP CONNECT response.

**Неизвестно:**
- Как именно клиент использует master_secret? (PSK? PRF seed? TLS session import?)
- Поддерживается ли DTLS 1.3 в CSC 5.1? (строки есть, реализация?)
- Cookie format для DTLS ClientHello
- Fallback при DTLS failure — таймауты, retry, переключение на CSTP only

**Бинарии:** `libacciscossl.so` (CiscoSSL — OpenSSL fork)

**Точки входа:**
- `DTLS_client_method`, `DTLS_server_method` — xref в libacciscossl
- `SSL_set_session_id_context`, `SSL_SESSION_set1_master_key` — как устанавливается master
- `BIO_new_dgram` — создание UDP BIO

**Методика:**
1. IDA Pro: decompile DTLS setup path в libacciscossl
2. angr: symbolic execution — найти все пути от `DTLS_client_method()` до `SSL_read()`
3. Wireshark: DTLS capture с ASAv → подтвердить cipher suites, session ID format
4. Frida: hook `SSL_set_session()` и dump параметров

**Связь с ioguard:** `src/network/dtls.c` — `iog_dtls_setup()`, bootstrap из CSTP headers. wolfSSL API: `wolfSSL_set_session_id()`, `wolfSSL_UseSNI()`

#### 2.2 DTLS Rekey

**Текущее знание:** DTLS rekey упоминается в VERSION_DIFFERENCES.md, но механизм не задокументирован.

**Вопросы:**
- In-band renegotiation или новый handshake?
- Как сервер инициирует rekey? (через CSTP control message? X-DTLS-Rekey header?)
- Интервал rekey (по времени? по объему данных?)
- Совместимость DTLS 1.2 renegotiation с wolfSSL

**Методика:**
1. Долгая VPN-сессия (24h+) с Wireshark → поймать момент rekey
2. IDA: xref на `SSL_renegotiate` в libacciscossl
3. Frida: timestamp hook на `SSL_do_handshake` в контексте DTLS

**Результат:** `DTLS_BOOTSTRAP_REKEY.md`

---

### Фаза 3: AggAuth — полный цикл аутентификации (P0, 2 недели)

**Цель:** все ветки XML-аутентификации, включая multi-step MFA.

#### 3.1 AggAuth XML Schema

**Текущее знание:** базовый auth-request/complete задокументирован в OTP_IMPLEMENTATION.md и ocprotocol skill.

**Пробелы:**
- Полная XML schema (все элементы, атрибуты, namespace)
- Все `type` values: `auth-request`, `auth-reply`, `complete`, `init`, `logout`, `?`
- Формат `<opaque>` блока (token refresh, session persistence)
- Порядок challenge/response при PAM + TOTP (двойной пароль)
- SAML redirect flow (external browser, callback URL)
- Cert-only auth (нет password, есть client cert)
- Guest access (нет auth, redirect)
- Group selection flow (`<group-select>`, `<group-access>`)
- Ответ при lockout/ban (формат ошибки)
- `aggregate-auth-version` values (1, 2, 3?)

**Бинарии:** `libvpnapi.so`, `vpnagentd`, `acwebhelper`

**Точки входа:**
- Строки `config-auth`, `auth-request`, `auth-reply`, `aggregate-auth-version`
- `libxml2` API calls: `xmlNewDoc`, `xmlNewNode`, `xmlNewProp` — восстановить XML construction
- `X-Aggregate-Auth` HTTP header

**Методика:**
1. IDA: decompile XML builder functions в libvpnapi → восстановить полную schema
2. Wireshark: pcap всех сценариев auth:
   - user/pass only
   - user/pass + TOTP
   - cert only
   - cert + password
   - SAML redirect
   - failed auth (3x → lockout)
   - group selection
3. acwebhelper: decompile для понимания SAML callback mechanism
4. Сравнить с openconnect исходниками (`auth-globalprotect.c`, `auth-juniper.c` — для контраста)

**Связь с ioguard:**
- `src/auth/` — PAM, RADIUS, LDAP, TOTP (S2/S6/S7)
- XML form exchange: `src/network/http.c` → iohttpparser для парсинга, yyjson/cJSON для response
- AggAuth: `src/core/secmod.c` → auth-mod process

#### 3.2 Session Cookie

**Вопросы:**
- Формат cookie value: random? HMAC-signed? encrypted?
- TTL: configurable? из X-CSTP-Session-Timeout?
- Reconnect: тот же cookie или новый?
- Формат `webvpn` cookie (ASA specific) vs openconnect generic

**Методика:**
1. Множественные сессии → собрать 20+ cookies → анализ энтропии
2. IDA: xref на `Set-Cookie` в vpnagentd/lina → функция генерации
3. Frida: hook cookie generation

**Результат:** `AGGAUTH_FULL_SPEC.md`, `SESSION_COOKIE_FORMAT.md`

---

### Фаза 4: Compression Negotiation (P1, 1 неделя)

**Цель:** полная механика согласования и использования LZS/LZ4/deflate.

**Текущее знание:** X-CSTP-Accept-Encoding, LZS documented в DPD_AND_TIMERS.md.

**Пробелы:**
- Какой именно frame type для compressed data? (CSTP type 0x08?)
- LZ4 в CSC 5.1 — поддерживается? (в ocserv есть)
- Серверная сторона: когда compress, когда нет? (MTU threshold? content type?)
- Deflate: raw или zlib wrapper?
- Per-packet compression или stream?
- Порядок: encrypt(compress(data)) или compress(encrypt(data))?

**Бинарии:** `vpnagentd`, `libvpncommoncrypt.so`

**Методика:**
1. IDA: xref `lzs_compress`, `lzs_decompress`, `LZ4_compress`, `deflate` в vpnagentd
2. Wireshark: сессия с forced compression → hex анализ compressed frames
3. Compare compressed/uncompressed frame headers

**Связь с ioguard:** `src/network/compress.c` — `iog_compress_lzs()`, `iog_compress_lz4()` (S4 done)

**Результат:** Раздел в `CSTP_WIRE_FORMAT.md`

---

### Фаза 5: Reconnect и Session Persistence (P1, 1 неделя)

**Цель:** механизм "Waiting to Resume", reconnect token, session migration.

**Текущее знание:** Parent-Tunnel concept из DPD_AND_TIMERS.md.

**Пробелы:**
- Reconnect HTTP request: тот же CONNECT или новый POST /auth?
- `X-CSTP-Session-Token` vs session cookie — одно и то же?
- Таймаут reconnect: client-side (disconnect-timeout) vs server-side (idle-timeout)?
- При reconnect: новый IP или сохраняется?
- DTLS при reconnect: новый bootstrap или cached?
- Graceful vs ungraceful disconnect: какой CSTP frame type?

**Бинарии:** `vpnagentd`

**Методика:**
1. IDA: xref `reconnect`, `resume`, `session-token` строки
2. Тестовый сценарий: VPN connect → kill network → restore → capture reconnect flow
3. Frida: hook HTTP request builder при reconnect

**Связь с ioguard:** `src/core/worker.c` — reconnect handler, `src/core/session.c` — session persistence в libmdbx

**Результат:** `RECONNECT_PROTOCOL.md`

---

### Фаза 6: SAML/SSO External Browser (P1, 2 недели)

**Цель:** полный flow SAML-аутентификации через внешний браузер.

**Текущее знание:** acwebhelper упоминается, но flow не задокументирован.

**Пробелы:**
- Как acwebhelper получает callback URL?
- Loopback listener (localhost:port)? Named pipe? D-Bus?
- Формат SAML assertion → session cookie mapping
- Timeout для browser flow
- Fallback при отсутствии браузера

**Бинарии:** `acwebhelper` (Linux), `acwebhelper.exe` (Windows)

**Методика:**
1. IDA: decompile acwebhelper main → найти socket/pipe listener
2. strace acwebhelper при реальном SAML auth
3. Wireshark: весь HTTP flow между client, IdP, ASA

**Связь с ioguard:** S7+ SAML — не в MVP, но архитектурно важно для auth plugin API (`dlopen`)

**Результат:** `SAML_SSO_FLOW.md`

---

### Фаза 7: Dynamic Split Tunnel (P2, 1 неделя)

**Цель:** протокол обновления split tunnel routes в runtime.

**Текущее знание:** VERSION_DIFFERENCES.md — появилось в 5.1.2.42.

**Пробелы:**
- In-band CSTP control message для route update?
- Или периодический HTTP polling?
- Формат обновления: full replace или incremental?
- DNS-triggered route addition

**Бинарии:** `vpnagentd` (5.1.12.146 vs 5.0)

**Методика:**
1. BinDiff: 5.0 vs 5.1 vpnagentd → найти новые функции
2. IDA: xref `split-include`, `split-exclude`, `dynamic` строки в 5.1-only functions
3. Тестовый pcap с dynamic split tunnel enabled

**Связь с ioguard:** `src/network/dns.c` (split DNS), будущий `src/network/route.c`

**Результат:** Раздел в `VERSION_DIFFERENCES.md`

---

### Фаза 8: Posture/HostScan (P2, 1 неделя)

**Цель:** протокол проверки состояния клиента (DAP — Dynamic Access Policy).

**Пробелы:**
- Какие данные клиент отправляет? (OS version, AV status, firewall, disk encryption)
- HTTP endpoint для posture data: `/+CSCOE+/sdesktop/` ?
- XML format posture report
- Как сервер принимает решение (match criteria)

**Бинарии:** `cscan` (Cisco Secure Firewall Posture), `hostscan_4.9*.pkg`

**Методика:**
1. IDA: decompile cscan → найти data collection functions
2. Wireshark: posture check flow

**Связь с ioguard:** Не в MVP. Будущий plugin API для posture assessment.

**Результат:** `POSTURE_DAP.md`

---

### Фаза 9: VPN API SDK (P2, 1 неделя)

**Цель:** публичный API libvpnapi для программного управления VPN.

**Текущее знание:** Reko восстановил 84 функции, 68 структур.

**Пробелы:**
- Полный API surface: все экспортированные функции с сигнатурами
- Callback model: event-driven или polling?
- Thread safety
- Error codes

**Бинарии:** `libvpnapi.so` (Linux), headers из VPN API SDK package

**Методика:**
1. `nm -D libvpnapi.so | grep ' T '` → export list
2. Reko: восстановить все exported function signatures
3. SDK package: есть ли .h headers? (в VPNAPI archives)

**Связь с ioguard:** Не прямая — это клиентский API. Но полезно для понимания event model.

**Результат:** `VPNAPI_REFERENCE.md`

---

## 3. Маппинг декомпиляции → ioguard

### Прямые результаты для реализации

| Фаза | Результат декомпиляции | Файл в ioguard | Спринт |
|------|------------------------|-----------------|--------|
| Ф1 | CSTP frame format | src/network/cstp.{h,c} | S3 (done, verify) |
| Ф1 | CONNECT response headers | src/network/http.{h,c} | S7 (iohttpparser) |
| Ф2 | DTLS bootstrap | src/network/dtls.{h,c} | S4 (done, verify) |
| Ф2 | DTLS rekey | src/network/dtls.c | S7+ |
| Ф3 | AggAuth XML full | src/auth/ + src/core/secmod.c | S7 (RADIUS/LDAP) |
| Ф3 | Session cookie | src/core/session.c | S6 (done, verify) |
| Ф4 | Compression negotiation | src/network/compress.c | S4 (done, verify) |
| Ф5 | Reconnect protocol | src/core/worker.c | S3 (done, extend) |
| Ф6 | SAML/SSO | src/auth/saml.c (new) | S7+ |
| Ф7 | Dynamic split tunnel | src/network/dns.c, route.c | S9+ |
| Ф8 | Posture/DAP | plugin API | Future |
| Ф10 | External SSO/SAML | src/auth/saml.c | S7+ |
| Ф11 | On-Demand/TND | profile push в AggAuth | S7+ |
| Ф12 | Per-App VPN | reference (client eBPF) | Future |
| Ф13 | Certificate Auth | src/auth/cert.c (new) | S7 |
| Ф14 | VPN Profile schema | docs/profile-schema.xsd | S7 |
| Ф15 | VPNAPI SDK | reference only | — |

### Улучшения ioguard над Cisco ASA/ocserv

| Область | Cisco ASA | ocserv | ioguard (улучшение) |
|---------|-----------|--------|---------------------|
| I/O model | select()/poll() | epoll | **io_uring** (zero-copy, multishot) |
| TLS | OpenSSL 1.1.x | GnuTLS | **wolfSSL 5.8+** (TLS 1.3, DTLS 1.3, FIPS) |
| DTLS | 1.0/1.2 | 1.2 | **1.2 + 1.3** (RFC 9147) |
| Auth | RADIUS/LDAP | PAM/RADIUS/LDAP | PAM/RADIUS/LDAP + **TOTP vault** + plugin API |
| Storage | файл-конфиг | файл-конфиг | **libmdbx** (ns latency) + SQLite WAL |
| Security | — | seccomp | seccomp + **Landlock** + **wolfSentry IDPS** + nftables |
| Compression | LZS only | LZS/LZ4 | LZS + **LZ4** |
| Process model | monolith (lina) | fork per connection | **privilege separation** (Main + secmod + Workers) |
| Memory | system malloc | system malloc | **mimalloc** (MI_SECURE, per-worker heaps) |
| Admin API | ASDM (Java) | — | **REST API** (iohttp, mTLS) + iogctl CLI |
| Metrics | SNMP | — | **Prometheus** (native text exposition) |
| HTTP parser | hand-rolled | http-parser | **iohttpparser** (SIMD, zero-copy) |
| Config | CLI/ASDM | ocserv.conf | **TOML** (typed, nested, validated) |
| Logging | syslog | syslog | **stumpless** (RFC 5424, structured, async io_uring) |
| Sandbox | — | chroot | seccomp BPF + Landlock + **IORING_REGISTER_RESTRICTIONS** |
| Cert auth | basic | basic | **Microsoft AD template OID filtering** (S7) |

---

## 4. Тестовый стенд

### Инфраструктура

```
┌─────────────────────┐     ┌──────────────────────┐
│  pve-netlab          │     │  oel-lab-gui          │
│  ┌───────────────┐  │     │  IDA Pro 9.3          │
│  │ ASAv 9.19     │  │     │  Ghidra 12.0.4        │
│  │ VMID 710      │  │     │  JEB 5.38             │
│  │ PLRv2 licensed│──│────▶│  Frida 16.x           │
│  └───────────────┘  │     │  radare2/rizin         │
│  ┌───────────────┐  │     │  Wireshark             │
│  │ Linux client  │  │     │  angr                  │
│  │ CSC 5.1.17    │  │     └──────────────────────┘
│  └───────────────┘  │
└─────────────────────┘
```

### Методика capture

1. **TLS decryption:** `SSLKEYLOGFILE` на клиенте → Wireshark dissector
2. **Frida на клиенте:** hook `SSL_read`/`SSL_write` → hex dump фреймов
3. **Frida на ASA lina:** hook `lina_ssl_read`/`lina_ssl_write` (если ASLR stable)
4. **strace:** syscall trace vpnagentd для socket activity, timer fd

### Сценарии тестирования

| # | Сценарий | Что собираем |
|---|----------|-------------|
| T1 | Clean connect (user/pass) | Full HTTP + CSTP + DTLS |
| T2 | Connect + TOTP | AggAuth XML multi-step |
| T3 | Connect + cert only | TLS client cert flow |
| T4 | Connect → kill network → resume | Reconnect protocol |
| T5 | 24h session | DTLS rekey, DPD, keepalive |
| T6 | Connect with compression=on | Compressed frame format |
| T7 | Failed auth (3x lockout) | Error XML format |
| T8 | DTLS failure → fallback to CSTP | Tunnel switch mechanism |
| T9 | Split tunnel + DNS | Route/DNS push headers |
| T10 | Graceful disconnect | CSTP DISCONNECT frame |

---

## 4.1 CSC 5.1.17 — полная инвентаризация пакетов

> Источник: `/share/secure-firewall-asa/Cisco Secure Client 5.x/5.1.17.3394/`

### Пакеты webdeploy (push с ASA/FTD на клиент)

| Пакет | Платформы | Размер | Назначение |
|-------|-----------|--------|-----------|
| `cisco-secure-client-*-webdeploy-k9.pkg` | win/macos/linux64/linux-arm64/win-arm64 | 112-188MB | Основной VPN-клиент + модули |
| `external-sso-5.1.17.3394-webdeploy-k9.pkg` | кросс-платформ | 5.7KB | External Browser SAML/SSO |

### External SSO (.pkg) — **полностью реверсирован**

Минимальный ZIP (5.7KB) с двумя файлами:
- `headinfo.txt`: `package-version=1`, `sso-start-url=index.html`, `content-security-allow=http://localhost:5885`
- `index.html`: JS-приложение (minified bundle.js), реализующее SSO token relay

**Протокол External SSO:**
1. ASA/FTD пушит external-sso.pkg → клиент извлекает и открывает `index.html` в браузере
2. Браузер проходит SAML-аутентификацию, получает token в cookie `acSamlv2Token`
3. JS читает token из cookie (или из `{{AC_SAML_TOKEN}}` template substitution)
4. Platform routing:
   - **iOS/macOS (CSC <4.10.5000):** custom URI `anyconnectsso://externalsso?token=TOKEN`
   - **Android/ChromeOS:** custom URI `anyconnect://externalsso?token=TOKEN`
   - **Desktop (Win/Mac/Linux):** HTTP redirect → `http://localhost:29786/api/sso/TOKEN?return=URL`
5. Версия клиента определяется из cookie `acvers` (default `5.0.0`)
6. Localhost порт: **29786** (hardcoded в `ExternalSSOApi.httpPort`)
7. Completion signal: URL parameter `?done=1` → "You can close this tab"

**Для ioguard:** серверу нужно (a) push external-sso.pkg через headend/webdeploy, (b) принимать token через AggAuth SAML callback, (c) опционально иметь свой SSO HTML. Можно упростить — единый HTML без pkg.

### Profile Editor (MSI)

`tools-cisco-secure-client-win-5.1.17.3394-profileeditor-k9.msi` (14MB) — Windows-only GUI для создания VPN Profile XML. Содержит полную XML schema (XSD) для On-Demand, Always-On, TND, cert selection, server list, и прочих настроек. **Приоритетный артефакт для G18.**

### MST Transforms

`tools-cisco-secure-client-win-5.1.17.3394-transforms.zip` (79KB) — 9 MST файлов для кастомизации установки:

| MST файл | Назначение |
|----------|-----------|
| `anyconnect-win-disable-customer-experience-feedback.mst` | Отключить телеметрию |
| `anyconnect-win-enablefips.mst` | Включить FIPS mode |
| `anyconnect-win-gui-desktop-shortcut.mst` | Ярлык на рабочем столе |
| `anyconnect-win-reset-adapter-mtu.mst` | Сброс MTU адаптера |
| `anyconnect-win-strict-cert-policy.mst` | Строгая валидация сертификатов |
| `sbl_secure-client-win-reboot-reallysuppress.mst` | Подавить перезагрузку (SBL) |
| `_secure-client-win-hide-addremove.mst` | Скрыть из "Programs" |
| `_secure-client-win-lockdown.mst` | Запретить отключение VPN |
| `_secure-client-win-reboot-reallysuppress.mst` | Подавить перезагрузку |

**Для ioguard:** MST-файлы определяют конфигурационные ключи, которые ioguard клиент должен поддерживать (FIPS mode, lockdown, strict cert policy).

### VPNAPI SDK

`cisco-secure-client-*-vpnapi.{zip,tgz}` (18-129MB по платформам) — публичный SDK для написания 3rd-party VPN клиентов.

**Состав:**
- `include/`: 15 заголовков (api.h, ClientIfc.h, ConnectPromptInfo.h, Preference.h, VPNStats.h и др.)
- `lib/`: статические библиотеки (libvpnapi.a, libvpncommon.a, libvpncommoncrypt.a) + OpenSSL-форк (libacciscossl.so, libacciscocrypto.so)
- `examples/cli/`: полный CLI VPN-клиент (CLIClientMain.cpp, Makefile)
- `doc/`: Doxygen HTML документация
- **1.3M символов** в .symbols файлах (374K vpnapi + 797K vpncommon + 132K vpncommoncrypt)

**Post-Quantum (oqsprovider.so, 2.5MB):**
CSC 5.1.17 включает CiscoSSL OQS provider с поддержкой:
- **KEM:** ML-KEM-512/768/1024, Kyber512/768/1024, BIKE-L1/L3/L5, HQC-128/192/256, FrodoKEM
- **Hybrid KEM:** SecP256r1+ML-KEM-768, X25519+ML-KEM-768
- **Signatures:** ML-DSA-44/65/87, Falcon-512/1024, SPHINCS+
- Build path: `ciscossl-3.3.5.8.3.63/ciscoqs_provider/`

**Для ioguard:** VPNAPI SDK — эталонный API surface. CLI example показывает минимальный client flow. PQ crypto определяет cipher suites для будущей совместимости.

---

## 4.2 Новые фазы декомпиляции (G14-G21)

### Фаза 10: External SSO / SAML browser flow (G14, 1 неделя)

**Статус: 80% DONE** (клиентская сторона полностью из index.html JS)

**Оставшееся:**
1. Серверная сторона в lina: как ASA генерирует SAML redirect URL, где хранит `acSamlv2Token`
2. AggAuth XML: `<saml-auth-method>`, `<saml-redirect-url>` элементы (в P2-A scope)
3. Localhost listener в vpnagentd: `/api/sso/{token}` endpoint (port 29786)
4. Cookie security: `acSamlv2Token` + `acvers` — HttpOnly? Secure? SameSite?

**Бинарии:** lina (server), vpnagentd (client localhost listener)
**Результат:** `SAML_SSO_FLOW.md` (обновить существующий draft)

### Фаза 11: On-Demand / Always-On / TND (G15, 2 недели)

**Источники:**
- VPNAPI SDK `api.h`: PreferenceId enum — AutomaticVPNPolicy, TrustedNetworkPolicy, TrustedDNSDomains/Servers, TrustedHttpsServerList, AlwaysOn, ConnectFailurePolicy
- Profile Editor MSI: полная XSD для VPN Profile XML
- vpnagentd: TND engine implementation

**Задачи:**
1. Извлечь XML schema из Profile Editor MSI (msiextract/7z → .xsd файлы)
2. Декомпилировать TND engine в vpnagentd: DNS resolution + HTTPS probe logic
3. Captive Portal detection: `CanRemediateCaptivePortal()` алгоритм
4. ConnectFailurePolicy=Closed: как блокируется сеть (iptables/nftables rules)
5. Серверная сторона: push профиля через `<vpn-profile-manifest>` в AggAuth CONFIG-REQUEST
6. `X-CSTP-Disable-Always-On-VPN` header processing

**Бинарии:** vpnagentd (client TND), lina (server profile push)
**Результат:** `ON_DEMAND_TND.md`, `VPN_PROFILE_SCHEMA.md`

### Фаза 12: Per-App VPN / Application Routing (G16, 2 недели)

**Источники:**
- CSC triage: acsockd (9.47MB) с 10 eBPF программами
- lina strings: zero-trust per-app session tracking, Smart Tunnel

**Задачи:**
1. Извлечь BPF байткод из acsockd (embedded ELF sections)
2. Декомпилировать BPF программы: cgroup/connect4,6, sendmsg4,6, setsockopt (866KB)
3. Реконструировать BPF map layout (cgroup→tunnel mapping)
4. D-Bus IPC: vpnagentd ↔ acsockd — сообщения, формат
5. acsocktool (6.91MB): CLI для конфигурации socket filter правил
6. Серверная сторона: Smart Tunnel applist push, zero-trust session limits

**Бинарии:** acsockd + acsocktool (client), lina (server)
**Результат:** `PER_APP_VPN_EBPF.md`

### Фаза 13: Certificate Auth deep dive (G17, 2 недели)

**Источники:**
- VPNAPI SDK: AutomaticCertSelection, SCEP, PKCS12, CertificatePinning
- lina strings: `certificate-group-map`, `certificate-authentication`, `username-from-certificate`, `DefaultCertificateMap`
- libvpncommoncrypt.so: CCertStore, CCertificate, OCSP, CObfuscationMgr

**Задачи:**
1. Декомпилировать `webvpn__certificate_group_map_cb` в lina — cert → tunnel group mapping
2. `crypto ca certificate map` matching engine — X.509 fields (Subject, Issuer, SAN, EKU, AD template OID)
3. cert-only auth flow в AggAuth INIT (sub_1159B10) — TLS client cert без password
4. Multi-cert selection UI → `ConnectPromptInfo` cert list
5. SCEP proxy: как ASA проксирует SCEP enrollment для клиента
6. OCSP/CRL checking на серверной стороне
7. `ssh authentication method x509-certificate` — SSH x509 auth path

**Бинарии:** lina (server cert engine), libvpncommoncrypt.a (client crypto)
**Результат:** `CERTIFICATE_AUTH_DEEP.md`

### Фаза 14: VPN Profile XML Schema (G18, 1 неделя)

**Задачи:**
1. Извлечь .xsd из Profile Editor MSI (msiextract + binwalk)
2. Документировать полную schema: AnyConnectProfile → ServerList, AutomaticVPNPolicy, CertificateSelection, BackupServerList, AlwaysOn, etc.
3. Сравнить с ocserv profile format
4. Определить extension points для ioguard-specific settings

**Результат:** `VPN_PROFILE_SCHEMA.md`

### Фаза 15: VPNAPI SDK reverse (G19, 1 неделя)

**Задачи:**
1. Полный API surface из include/ headers (15 файлов)
2. Event model: evtSubscribe/evtUnsubscribe, callback flow
3. State machine: vpnState transitions (Connected/Reconnecting/Disconnecting)
4. CLI example analysis: CLIClientMain.cpp → минимальный connect flow
5. Symbol analysis: 1.3M строк в .symbols → public class hierarchy

**Результат:** `VPNAPI_REFERENCE.md`

---

## 5. Таймлайн и ресурсы

### Общий план (12 недель)

| Неделя | Фаза | Задачи | Часы | Инструменты |
|--------|------|--------|------|-------------|
| 1 | Ф0 | Подготовка среды, IDB, pcap templates | 16 | IDA, Wireshark |
| 2-3 | Ф1 | CSTP wire format | 40 | IDA, Reko, Wireshark, Frida |
| 4-5 | Ф2 | DTLS bootstrap + rekey | 40 | IDA, angr, Wireshark |
| 6-7 | Ф3 | AggAuth полный цикл | 40 | IDA, Ghidra, Wireshark |
| 8 | Ф4 | Compression negotiation | 20 | IDA, Wireshark |
| 9 | Ф5 | Reconnect + session persistence | 20 | IDA, Frida, Wireshark |
| 10-11 | Ф10 | External SSO (SAML) — серверная сторона | 16 | IDA, strace, Wireshark |
| 12 | Ф11 | On-Demand / TND — profile + engine | 30 | IDA, msiextract, vpnagentd |
| 13-14 | Ф12 | Per-App VPN — eBPF + D-Bus | 40 | IDA, llvm-objcopy, bpftool |
| 15-16 | Ф13 | Certificate Auth deep dive | 40 | IDA, Ghidra |
| 17 | Ф14 | VPN Profile XML schema | 16 | msiextract, xmllint |
| 18 | Ф15 | VPNAPI SDK reverse | 16 | nm, c++filt, Doxygen |
| 19 | Ф7-Ф9 | Dynamic split, posture, VPN API | 24 | IDA, BinDiff, Reko |

**Итого: ~358 часов** (~18 недель @ 20h/нед)

### Приоритет доставки для ioguard

**Batch 1 (Ф1-Ф3, недели 1-7):** критично для верификации S3-S6 и подготовки S7.
- CSTP wire format → проверить `src/network/cstp.c` (S3)
- DTLS bootstrap → проверить `src/network/dtls.c` (S4)
- AggAuth → дизайн auth plugin API для S7

**Batch 2 (Ф4-Ф5, недели 8-9):** улучшение reliability.
- Compression → проверить `src/network/compress.c` (S4)
- Reconnect → расширить `src/core/worker.c` (S3)

**Batch 3 (Ф10-Ф11, недели 10-12):** auth + connectivity features.
- External SSO → серверная генерация SAML redirect, token валидация
- On-Demand/TND → VPN Profile schema, серверный push профиля

**Batch 4 (Ф12-Ф13, недели 13-16):** enterprise features.
- Per-App VPN → eBPF программы из acsockd, cgroup routing architecture
- Certificate Auth → cert-group-map, multi-cert selection, SCEP proxy

**Batch 5 (Ф14-Ф15, недели 17-18):** SDK + schema.
- VPN Profile XML schema → полная XSD из Profile Editor MSI
- VPNAPI SDK → public API, event model, CLI example flow

**Batch 6 (Ф7-Ф9, неделя 19):** legacy features, deferred.

---

## 6. Deliverables

### Документы (в ocproto-research/analysis/)

| Документ | Фаза | Формат |
|----------|------|--------|
| `CSTP_WIRE_FORMAT.md` | Ф1 | RFC-style спецификация с hex примерами |
| `DTLS_BOOTSTRAP_REKEY.md` | Ф2 | Протокол + state machine |
| `AGGAUTH_FULL_SPEC.md` | Ф3 | Полная XML schema + примеры |
| `SESSION_COOKIE_FORMAT.md` | Ф3 | Формат, энтропия, TTL |
| `RECONNECT_PROTOCOL.md` | Ф5 | Flow + таймауты |
| `SAML_SSO_FLOW.md` | Ф6 | External browser flow |
| `POSTURE_DAP.md` | Ф8 | Posture check protocol |
| `VPNAPI_REFERENCE.md` | Ф15 | SDK API surface |
| `EXTERNAL_SSO_FLOW.md` | Ф10 | SAML external browser — клиент+сервер |
| `ON_DEMAND_TND.md` | Ф11 | On-Demand, Always-On, TND engine |
| `VPN_PROFILE_SCHEMA.md` | Ф14 | Полная XML schema (из Profile Editor) |
| `PER_APP_VPN_EBPF.md` | Ф12 | acsockd eBPF architecture |
| `CERTIFICATE_AUTH_DEEP.md` | Ф13 | Server cert mapping + client cert selection |
| `CSC_PACKAGE_INVENTORY.md` | — | Инвентаризация всех CSC 5.1.17 пакетов |

### Артефакты (в ocproto-research/scripts/)

| Артефакт | Назначение |
|----------|-----------|
| `frida-cstp-dump.js` | Dump CSTP frames в runtime |
| `frida-dtls-bootstrap.js` | Dump DTLS session params |
| `frida-aggauth-xml.js` | Dump XML auth exchange |
| `ida-cstp-annotate.py` | IDA script для аннотации CSTP functions |
| `wireshark-cstp.lua` | Custom CSTP dissector для Wireshark |
| `pcap-scenarios/` | Reference pcaps для всех T1-T10 |

### Обновления в ioguard

| Файл | Обновление | Когда |
|------|-----------|-------|
| `.claude/skills/ocprotocol/SKILL.md` | Расширить AggAuth, reconnect, compression | После Batch 1 |
| `docs/architecture/CISCO_COMPATIBILITY_GUIDE.md` | Полная таблица совместимости | После Batch 2 |
| `tests/integration/` | E2E тесты по pcap-сценариям | S9 |

---

## 7. Критерии завершения

### Per-Phase

- [ ] Каждая фаза имеет .md документ в `ocproto-research/analysis/`
- [ ] Каждый протокольный элемент подтвержден pcap capture (не только статика)
- [ ] Каждая восстановленная структура имеет C23 typedef в документе
- [ ] Несоответствия с openconnect/ocserv source code задокументированы
- [ ] Frida/IDA скрипты коммитнуты и работают

### Общие

- [ ] Все 21 пробел (G1-G21) закрыты или обоснованно отложены
- [ ] CSTP wire format покрыт на 100% (все frame types)
- [ ] AggAuth покрыт на 100% (все auth paths)
- [ ] DTLS bootstrap верифицирован на wolfSSL (ioguard dev build)
- [ ] Не менее 10 pcap reference captures (T1-T10)
- [ ] `ioguard` skill `ocprotocol/SKILL.md` обновлен с полной spec

---

## 8. Риски

| Риск | Вероятность | Mitigation |
|------|-------------|------------|
| CSC 5.1 использует TLS 1.3 early data, которую wolfSSL не поддерживает | Средняя | Проверить: wolfSSL 5.8 поддерживает 0-RTT. Fallback to 1-RTT |
| DTLS master secret format несовместим с wolfSSL session import API | Низкая | Использовать `wolfSSL_set_session()` + raw key injection |
| ASAv 9.19 слишком старая для dynamic split tunnel features | Высокая | Добавить ASAv 9.24 в тестовый стенд |
| Frida crashes lina (monolith, 113MB) | Средняя | Использовать GDB + breakpoints вместо Frida для lina |
| AggAuth имеет undocumented Cisco-proprietary extensions | Средняя | Тестировать каждую ветку, документировать неизвестные элементы |
| Profile Editor MSI может не содержать XSD напрямую | Средняя | Альтернатива: strings из PE-файлов Profile Editor, binwalk |
| acsockd BPF программы обфусцированы или packed | Низкая | bpftool prog dump, llvm-objdump для BPF bytecode |
| oqsprovider.so PQ suites не поддержаны в wolfSSL | Высокая | wolfSSL 5.8 имеет ML-KEM. Использовать liboqs standalone для остальных |
| D-Bus IPC между vpnagentd и acsockd может быть закрытый протокол | Средняя | strace + dbus-monitor в runtime |
