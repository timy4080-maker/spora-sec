# Контракт реальной криптографии

## Границы

Это новый SEC-01 client, использующий C-01 deterministic CBOR и C-03 Relay API. Его нельзя открыть старым synthetic Client. Wire suite `SPORA_LIBSIGNAL_0_108_V1`; outer magic `SPSEC001`. Ни fallback на synthetic, ни автоматическое обновление identity, ни TOFU не реализованы. Тестовый заголовок Relay характеризует лабораторный deployment; он не является идентификатором E2EE suite.

Identity: случайные device UUID и generation UUID, Signal identity pair. ProtocolAddress = `device:generation`, Signal DeviceId=1: уникальность устройства обеспечивает полный address. Fingerprint = SHA-256 JSON tuple `(suite, domain, device, generation, public identity)`. Пользователь сверяет отпечаток другим доверенным каналом. Self-signature приглашения сама по себе не аутентифицирует человека.

Приглашение адресуется конкретному fingerprint, подписывает suite/version, устройство, получателя, expiry, регистрацию, prekeys и все маршруты. Один request ID повторно экспортирует то же приглашение. Новый request выделяет новые EC, signed EC и одноразовый Kyber1024 key. Каждый prekey закрепляется за получателем приглашения; используется отдельная криптосессия для каждого устройства. Приглашение содержит capability и wrapping keys, поэтому передавать его следует конфиденциально. Проверенные отпечатки и общий conversation ID обмениваются до обмена сообщениями; присутствие получателя во время отправки не нужно.

Управление списком устройств пока ручное: отдельное приглашение и fingerprint каждого устройства. Автоматическая авторизация нового устройства старым, revocation и смена identity не заявляются.

## Полный PreparedPlan

`src/signal.rs` реализует IdentityKeyStore, SessionStore, PreKeyStore, SignedPreKeyStore, KyberPreKeyStore. Все записи — сериализованные upstream records. Callback работает с клоном полного состояния и не имеет доступа к сети/SQLite. Неизвестная или изменённая identity отклоняется в Sending/Receiving, включая archived session callback.

В одном sealed State находятся identities/trust, sessions/archived sessions/SPQR, prekey records и их владельцы, выделение ключей, routes, источники, курсоры, sender sequence, запросы/idempotency, история, dedup, outbox и receipt intents. `Prepared` содержит весь этот snapshot, profile ID и исходную глобальную revision. Любое изменение, даже trust/route/read-only prerequisite, меняет revision; SQLite CAS отклоняет весь устаревший plan. Частичного commit API нет. Это консервативная реализация полного read/write set: конкурентность ограничена одним профилем.

SQLite: WAL, synchronous=FULL, busy timeout 5 s, foreign_keys, один UPDATE в IMMEDIATE transaction. Outbox и исходная операция сохраняются вместе с библиотекой. Любой SQL/IO отказ возвращается без дополнительной попытки сохранить диагностику. Лимит serialized State 32 MiB; автоматического удаления неприменённых сообщений нет. Это прототип, не масштабируемая схема БД: на каждое изменение перезаписывается весь зашифрованный snapshot.

## Приём и подтверждения

1. TX1 проверяет C-03 page/receipt/digest, сохраняет ciphertext, consumption intent и cursor. Только после COMMIT возможен consume.
2. Consume независимо повторяется после перезапуска. Его успех не означает применения сообщения.
3. TX2 выполняет staged decrypt. Bad crypto оставляет библиотеку неизменной, конверт хранится в quarantine. Crypto-valid/application-invalid сохраняет изменения библиотеки, помечает rejected, не резервирует logical message ID и не создаёт receipt. Валидный Text сохраняется с receipt intent.
4. Worker receipt intents готовит зашифрованное подтверждение и state/outbox одним commit. При ошибке intent остаётся. Подтверждения сами не подтверждаются.
5. Только аутентифицированный Receipt от ожидаемого recipient device в нужной conversation меняет processed_by. Relay receipt хранит только факт принятия сервером.

Retry повторяет неизменные envelope/delivery ID/expiry, сохраняет backoff и retry-after, использует jitter, максимум 16 ошибок до attention. Ошибка одного transport source не останавливает остальные; SQL failure останавливает работу, чтобы не продолжать без durable state. `retry-attention` — явное действие оператора. Expired outbox и quarantine сохраняются; expiry не является разрешением потерять локальное сообщение.

## Управляющие сообщения и размер

У закреплённого libsignal нет отдельного callback, отправляющего control frame в сеть. PQXDH prekey header и SPQR updates встроены в результат `message_encrypt`. Подтверждение, зашифрованное обратной стороной, одновременно позволяет библиотеке снять unacknowledged initiation. До ответа следующие исходящие могут повторять prekey header; операция содержит весь обязательный криптографический материал. State после encrypt и **точные** полученные байты сохраняются вместе.

Основание: [session_management.rs](https://github.com/signalapp/libsignal/blob/8be00c282001caa3585d18de0f044c6d500348ab/rust/protocol/src/session_management.rs), [triple_ratchet.rs](https://github.com/signalapp/libsignal/blob/8be00c282001caa3585d18de0f044c6d500348ab/rust/protocol/src/triple_ratchet.rs), [SPQR v1.7.0](https://github.com/signalapp/SparsePostQuantumRatchet/tree/v1.7.0). SPQR передаёт крупные логические PQ-обновления небольшими частями между сообщениями. Поэтому максимум одной части не равен суммарной стоимости rekey.

Безопасно выкинуть PQ/control-часть или считать Relay ACK выполнением криптографической зависимости нельзя. Дополнительный dependency DAG для других провайдеров здесь не реализован: у выбранного API эти данные неотделимы от ciphertext. Если весь envelope превышает IP limit, весь plan отклоняется. Радиопередача ещё не подключена; измерение попадания в 4096 байт не является RADIO acceptance. Приглашение и bundle могут требовать отдельной фрагментации.

## Обёртка и защита локальных данных

Один inner ciphertext для устройства можно доставлять несколькими маршрутами. Каждый маршрут получает новый nonce и XChaCha20-Poly1305 wrapper, свой delivery ID и digest. AAD связывает suite, route ID/version, destination device/generation, service/queue/generation. Outer содержит magic, 24-byte nonce и ciphertext+tag, без общего session/message ID. Inner packet = sender UUID (16), recipient UUID (16), type (1), libsignal ciphertext. AEAD overhead 48, всего поверх libsignal 81 байт. Relay всё ещё видит очереди, IP, время, объём и credentials; traffic analysis не предотвращён.

Полный serialized State шифруется XChaCha20-Poly1305, AAD включает profile ID, suite и revision. Windows: случайная 256-bit KEK защищена CurrentUser DPAPI с UI_FORBIDDEN. Отсутствующий/неподходящий key store, повреждение ciphertext/schema — fail closed; ключ не регенерируется. Отдельный plaintext test-key режим включается явным флагом и нужен Linux CI. Он не является production keystore. В БД/WAL остаются открытыми только schema/profile ID/revision/размеры. Это не SQLCipher и не защита от процесса с правами пользователя. Полного стирания всех копий ключей из памяти upstream/Rust allocator не обещаем.

`create` атомарно создаёт новый каталог; `open` не создаёт отсутствующую БД. Прерывание init оставляет неполный профиль закрытым. Recovery такого незапущенного профиля выполняется вручную с новой identity; автоматически продолжать непонятную инициализацию нельзя.

## SEC-02

Старую копию профиля запрещено запускать как действующую криптосессию. API backup/restore/import state отсутствует. DPAPI, AAD revision и CAS **не обнаруживают согласованный rollback всего профиля** на той же машине/учётной записи. Нет утверждения, что копирование db+KEK невозможно: ОС/оператор входят в доверенную границу этого spike. Перенос, rollback witness, clone detection, архивная история и безопасное создание новой session generation — отдельная работа SEC-02. Любая процедура восстановления должна создавать новое устройство/ключи и не оживлять старый ratchet. Этот запрет и ограничение детектора должны быть проверены внешним reviewer.
