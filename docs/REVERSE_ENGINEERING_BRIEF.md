# Задача: Анализ протокола Cisco Secure Client для совместимости с ocserv

## Контекст проекта
Ты работаешь над проектом ocserv-modern - современной реализацией OpenConnect VPN сервера на Go. 
Цель: обеспечить полную совместимость с официальным клиентом Cisco Secure Client (AnyConnect).

Репозиторий: https://github.com/dantte-lp/ocserv-modern
Документ для дополнения: `docs/architecture/PROTOCOL_REFERENCE.md`

## Доступные артефакты
- Исполняемые файлы Cisco Secure Client (/opt/projects/repositories/cisco-secure-client) для:
  - Windows (vpnagent.exe, vpnui.exe, acwebhelper.exe)
  - Linux (vpnagentd, vpnui)
  - macOS (Cisco Secure Client.app)
- Конфигурационные файлы клиента (пример /opt/projects/repositories/cisco-secure-client/vpn.example.com.xml)
- Логи сетевого взаимодействия (если предоставлены)

## Инструменты и методология

### Статический анализ
1. **Дизассемблирование**:
   - Использовать Ghidra/IDA или другие утилиты (последние версии) для анализа бинарников
   - Идентифицировать функции работы с протоколом
   - Найти константы, magic bytes, версии протокола
   - Используй podman-compose или podman для тестирования
   - Для Linux используй образ oraclelinux:10
   - Для Windows используй один из подходящих (https://mcr.microsoft.com/en-us/artifact/mar/windows/server/tags, https://mcr.microsoft.com/en-us/artifact/mar/windows/tags, https://mcr.microsoft.com/en-us/artifact/mar/windows/servercore/tags)

2. **Анализ строк**:
````bash
   strings vpnagent.exe | grep -i "xml\|http\|dtls\|protocol"
````

3. **Анализ импортов**:
   - OpenSSL/Crypto функции
   - Network API (WinSock, BSD sockets)
   - XML парсеры

### Динамический анализ
1. **Перехват трафика**:
   - Настроить Wireshark с фильтрами для HTTPS/DTLS
   - Использовать SSL/TLS key logging для расшифровки
   - Анализировать XML-структуры в HTTP телах

2. **Debugging**:
   - x64dbg/gdb для трассировки выполнения
   - Breakpoints на критичных функциях (connect, send, recv, SSL_*)

3. **Системные вызовы**:
   - strace/ltrace (Linux)
   - Process Monitor (Windows)
   - dtruss (macOS)

## Целевые области для документирования

### 1. Фаза аутентификации
````
Документировать:
- Формат XML-запросов auth-init, auth-request
- Механизмы MFA (TOTP, SMS, Duo)
- Session token generation
- Cookie management
````

### 2. Tunnel establishment
````
Определить:
- DTLS handshake особенности
- Cipher suites preferences
- MTU negotiation
- Keepalive механизмы
````

### 3. Дополнительные возможности
````
Reverse engineer:
- Split DNS configuration
- Client profiles (XML структуры)
- Automatic reconnection logic
- Local LAN access rules
- Always-On VPN механизм
- SAML authentication flow
- Certificate pinning
````

### 4. Protocol extensions
````
Найти недокументированное:
- Custom HTTP headers
- Proprietary XML namespaces
- Extended attributes в конфигурации
- Telemetry endpoints
````

## Структура документации

Для каждого найденного элемента протокола добавь в PROTOCOL_REFERENCE.md:
````markdown
### [Название функции/этапа]

**Версия протокола**: [если известна]
**Клиентская версия**: [Cisco Secure Client 5.x]

#### Описание
[Краткое описание назначения]

#### Формат запроса
[HTTP метод, endpoint, headers]
```xml
[Пример XML payload]
```

#### Формат ответа
```xml
[Пример XML response]
```

#### Особенности реализации
- [Важные детали]
- [Edge cases]
- [Версионные различия]

#### Ссылки на код
- Cisco Client: [offset/функция в бинарнике]
- ocserv: [где нужно реализовать]
````

## Этические и юридические рамки

⚠️ **ВАЖНО**:
1. Реверс-инжиниринг проводится ИСКЛЮЧИТЕЛЬНО для обеспечения интероперабельности
2. Документируй всё
3. Обходи механизмы защиты или лицензирования
4. Цель - создание совместимого решения

## Приоритеты

1. **High Priority**:
   - SAML/SSO authentication flows
   - Modern MFA mechanisms (TOTP, Push)
   - Always-On VPN configuration
   - Split DNS/routing rules

2. **Medium Priority**:
   - Client profiles format
   - Automatic reconnection logic
   - Telemetry/analytics endpoints

3. **Low Priority**:
   - UI-specific features
   - Client update mechanisms
   - Statistics collection

## Формат отчета

После анализа создай структурированный отчет:

1. **Executive Summary** - краткое резюме находок
2. **Protocol Flow Diagram** - диаграмма последовательности
3. **Message Formats** - детальные спецификации
4. **Implementation Notes** - заметки для разработки
5. **Test Cases** - тестовые сценарии для валидации
6. **Open Questions** - нерешенные вопросы

## Команды для начала работы
````bash
# Подготовка окружения
mkdir -p analysis/{windows,linux,macos}/{static,dynamic}

# Извлечение строк с контекстом
strings -n 8 vpnagent.exe > analysis/windows/static/strings.txt

# Запуск Wireshark с автоматическим key logging
export SSLKEYLOGFILE=./analysis/ssl-keys.log
wireshark -i any -k -f "host vpn.example.com"

# Мониторинг системных вызовов
strace -f -e trace=network -o analysis/linux/dynamic/strace.log ./vpnagentd
````

## Итеративный процесс

1. Начни с перехвата трафика реального подключения
2. Идентифицируй неизвестные XML-структуры
3. Найди в бинарнике функции, формирующие эти структуры
4. Документируй в PROTOCOL_REFERENCE.md
5. Создай proof-of-concept в Go
6. Повтори для следующего элемента протокола

