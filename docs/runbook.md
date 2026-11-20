# Сборка и запуск SEC-01

Нужны Rust 1.100.0, C compiler, protobuf compiler 36.2; Python 3 и OpenSSL нужны для TLS-стенда. `Cargo.lock` обязателен. Windows helper `cargo-local.ps1` использует установленный LLVM-MinGW/gnullvm и protoc из локального каталога инструментов, при их отсутствии — обычный Cargo. На другой Windows-машине используйте MSVC toolchain и PROTOC environment.

```powershell
.\cargo-local.ps1 -CargoArgs @('test','--locked')
.\cargo-local.ps1 -CargoArgs @('clippy','--locked','--all-targets','--','-D','warnings')
```

Обычный Cargo:

```sh
cargo build --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all --check
```

## Воспроизводимый TLS-стенд

Relay — закреплённый исправленный RELAY-01. Можно собрать binary отдельно:

```sh
cargo install --git https://github.com/timy4080-maker/spora-relay.git --rev 97d5b5c02ebc719f86d9d192aa42e1a25c913797 --locked --root .local/relay-tools --bin spora-relay spora-relay
python3 scripts/internet_lab.py --client-bin target/debug/spora-sec --relay-bin .local/relay-tools/bin/spora-relay --output .local/tls-lab.json
```

На Windows добавьте `.exe`, используйте `python` и при необходимости `--openssl 'C:\Program Files\Git\usr\bin\openssl.exe'`. Скрипт создаёт временную CA, два отдельных Relay, Alice и два устройства Bob, проверяет сбои, завершает процессы и удаляет временные данные. Все адреса loopback, сертификаты проверяются. Это проверка интернет-протокола через TLS, не развёртывание на внешних хостах.

## Ручной сценарий

Каждый запуск CLI открывает существующий профиль без создания нового. Для обычного Windows-профиля запускайте CLI без `--allow-test-key`. Ключ профиля защищает DPAPI. На Linux системная служба systemd получает 32-байтовый ключ `spora-wrapping-key` в своём каталоге `/run/credentials/<unit>`. Клиент находит каталог через `CREDENTIALS_DIRECTORY` и принимает доступ по ACL службы. Один и тот же credential требуется при каждом запуске этого профиля. Для systemd используйте `LoadCredentialEncrypted=` и ciphertext, созданный `systemd-creds encrypt --name=spora-wrapping-key --with-key=host`. Рабочий пример есть в шаге Linux host-encrypted service credential в CI. На OpenWrt интеграцию с менеджером секретов конкретного устройства предстоит проверить.

1. `spora-sec --profile alice init`, то же для bob. Запишите fingerprint и device.id. Каталоги должны быть новыми, их родитель уже существует.
2. Для каждого профиля: `--ca ca.pem queue --endpoint https://127.0.0.1:7780 --provisioning-token-file token.txt`. Token file содержит только capability provisioning. При потере ответа используйте `--existing-queue <queue-id>`: он возвращает уже сохранённые credentials вместо создания новых. Для просмотра очередей используйте `queues`.
3. Выберите общий conversation UUID в виде 32 lowercase hex без дефисов. Сверьте fingerprints отдельным доверенным каналом.
4. Alice: `invite --request <uuid> --for-fingerprint <bob-fingerprint> --output alice-to-bob.invitation.json`. Bob делает адресное приглашение для Alice. Приватно передайте файлы друг другу.
5. Alice: `import --invitation bob-to-alice.invitation.json --expected-fingerprint <bob-fingerprint> --conversation <uuid>`; Bob симметрично. Для второго устройства Bob повторите с его собственным fingerprint и тем же conversation.
6. Alice: `send --request <uuid> --peers <bob-id>,<bob2-id> --text 'artificial test'`; затем `dispatch` с CA. Повтор request с тем же содержимым возвращает тот же message ID.
7. Bob: `fetch`, затем `consume`. Можно завершить процессы/перезапустить Relay. `apply` расшифровывает уже сохранённый локальный конверт, `receipts` создаёт исходящий receipt, `dispatch` доставляет его.
8. Alice: `fetch`, `consume`, `apply`; `messages` показывает `processed_by`. До этого `status.relay_stored` подтверждает только Relay acceptance.

`tick` выполняет fetch → consume → apply → receipts → dispatch. Рабочий цикл можно вызывать повторно; транспортные ошибки сохраняют next-attempt, retry-after и budget. `status.attention_required` указывает на постоянную ошибку, исчерпание бюджета или expiry. После устранения причины `retry-attention` повторно разрешает попытки и обработку quarantine. Не используйте это как механизм принятия чужой identity.

## Ограничения эксплуатации

Не запускайте копии старой БД/KEK как live profile. Нет restore, identity rotation, автоматического re-establishment, migration или profile cloning API. Новое устройство требует новых ключей и повторной верификации. Не удаляйте key.kek у действующего профиля: open после этого откажет, init не заменит профиль. Незавершённая первая инициализация требует ручного разбора и создания нового профиля.

Invitation JSON и команда `messages` содержат чувствительные данные по назначению. Не публикуйте их, локальные DB, токены и KEK. `--text` передаёт искусственный текст через аргумент процесса; UI/секретный ввод — отдельная работа. Публичный сервер, пользовательские данные и production-рекомендация ожидают внешнее ревью.

### Обновление и обслуживание

Обновляйте исходный остановленный профиль на его устройстве. Первое успешное изменение атомарно переводит схему v1 в v2. Identity, установленные сессии, история, неизменные задания и прежняя верхняя граница sender_seq сохраняются. Оба участника сверяют новые отпечатки для новых приглашений. Файлы приглашений v1, оставшиеся до сопряжения, замените приглашениями v2 с новыми request IDs. Выбирайте очереди адресата через `invite --queues <id1>,<id2>`. Если очередей больше четырёх, выбор обязателен. Пересылайте файл по конфиденциальному каналу.

При отказе в приёме по объёму запустите `gc`, проверьте свободное место и попробуйте `fetch --limit 1`. Команда `gc --prune-expired-history` явно разрешает удаление истории по окончании срока сообщения и окна дедупликации. Обработка и отправка уже принятых конвертов используют отдельный резерв. Неразобранный карантин можно повторно обработать после устранения причины. Если источник остановлен с CONFLICTING_REPLAY, посмотрите его queue, endpoint и cursor через `queues`. Сверьте журнал Relay и восстановите согласованную страницу. Затем выполните `resume-source --queue <id>`. Клиент снова проверит ответ с сохранённого курсора.

### Потеря действующей сессии

1. Остановите повреждённый профиль и доставку на его старые очереди. Отзовите или приостановите их у администратора Relay. При подозрении на компрометацию приостановите обмен с этой identity на всех связанных устройствах.
2. Создайте профиль в новом каталоге, новые очереди и capabilities. Запишите новые device ID, generation и fingerprint. Согласуйте с собеседником оба новых отпечатка и conversation ID по доверенному каналу.
3. Обменяйтесь адресными приглашениями v2. Явно выберите новые устройства при отправке. Проверьте доставку искусственного сообщения и обратного E2EE receipt.
4. Старую историю оставьте в изолированном архиве. Эта процедура начинает новую сессию. Восстановление истории, противодействие клонированию и автоматическое отозвание старого доверия относятся к SEC-02. Если нужна гарантия отзыва скомпрометированной identity, держите старый профиль выключенным и используйте новые профили на обеих сторонах.
