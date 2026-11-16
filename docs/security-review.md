# Пакет внешнего security review

**Статус: PENDING. M2 OPEN.** Владелец явно требует ревью внешним специалистом. В этой сессии внешний специалист не привлекался и заключение не получено. Самопроверка реализации, тесты и анализ upstream API не подменяют это требование.

## Что передать reviewer

Передавайте commit hash опубликованного репозитория вместе с Cargo.lock, этой запиской, [решением по библиотеке](library-decision.md), [контрактом](integration.md), [проверками](verification.md) и [инвентарём лицензий](evidence/dependency-licenses.json). Рабочие секреты/профили для ревью не нужны: `scripts/internet_lab.py` создаёт новые. Зафиксируйте SHA до начала проверки и повторите тесты после исправлений.

| Поверхность | Файлы | Вопросы проверки |
|---|---|---|
| Bootstrap/authentication | src/model.rs, src/provider.rs | Signature domain/encoding, explicit OOB fingerprint, recipient targeting, identity/device/generation/route binding, prekey ownership and single use, invitation replay/expiry |
| Library port | src/signal.rs, src/provider.rs | Все callbacks/archived sessions, strict trust, EC/PQ deletion, clone staging, failed decrypt, simultaneous initiation, version downgrade |
| Atomicity | src/client.rs | Global read/write CAS, request idempotency, multi-device all-or-nothing, no library mutation outside plan, failure/SQLITE_FULL, two-process contention |
| Receive/delivery | src/client.rs, src/transport.rs | TX1 before consume, TX2 before receipt, crypto-valid/application-invalid, replay bounds, source binding, malformed Relay response, permanent vs retryable failures |
| Crypto wrappers/storage | src/vault.rs, src/model.rs | AEAD contexts, nonce source, DPAPI and key lifecycle, file creation, plaintext in WAL/logs, memory copies, source queue exposure |
| Operations | src/main.rs, scripts/internet_lab.py | CLI secret handling, TLS roots/redirect/proxy policy, network limits, dependency/build supply chain, test-only isolation |

## Threat model

Атакующий может читать/менять/повторять/переставлять/терять сетевой трафик, контролировать Relay, передавать поддельные invitations и иметь собственную доверенную сессию. Relay не считается доверенным источником личности или device-applied. Ожидаем конфиденциальность/аутентичность содержимого между явно проверенными устройствами и безопасную фиксацию state при обычном process crash.

Компрометация процесса/ОС текущего пользователя, кража памяти, согласованный rollback DB+KEK, социальная подмена OOB fingerprint, denial of service и traffic analysis не устранены данным spike. Reviewer должен подтвердить, что ограничения не противоречат заявленному продукту. Посткомпромиссные гарантии upstream протокола не переносятся автоматически на историю/локальные snapshots Spora.

## Особое внимание

- Invitation protocol и route wrapper — новая интеграционная поверхность поверх библиотеки, не часть аудита Signal.
- Upstream Rust API не имеет гарантий стабильности для стороннего клиента. Dependency advisories и релизные изменения должны быть отдельно проверены на дату внешнего ревью; cargo-audit в этой сессии не заявляется выполненным.
- Global encrypted snapshot даёт простой CAS, но увеличивает write amplification/размер WAL. Лимит 32 MiB требует operator action; eviction запрещён.
- Старые sessions/prekeys хранятся в рамках upstream и профильного лимита. Automatic refresh/rotation/revocation отсутствует. Unacknowledged session может перестать отправлять по upstream policy; это ошибка с сохранением исходных данных, не повод сбрасывать identity.
- SEC-02: нет полного anti-rollback/clone witness. AAD revision защищает от несогласованной правки, а не от возврата старого согласованного состояния. Восстановление как live session запрещено.
- Production Linux keystore, безопасный пользовательский ввод, публичный multi-host deployment, load/DoS/fuzz campaigns и радио остаются отдельными задачами. Лабораторный plaintext test key допускается только явно.
- У предыдущих first-party компонентов Spora не объявлены LICENSE. Нужно отдельное решение владельца до распространения объединённого продукта; этот репозиторий не меняет их лицензии.

## Условия принятия M2

1. Внешний специалист выдаёт письменное заключение с именем/организацией, датой, проверенным SHA/lockfile, методами, finding IDs и тяжестью.
2. Для findings сохраняются исправления, regression evidence и повторная проверка reviewer; не закрываем критические/high без её подтверждения.
3. Reviewer явно оценивает перечисленные ограничения и достаточность scope для M2; остаточные риски принимает владелец.
4. Повторяется reproducible TLS обмен на согласованном интернет-стенде. Здесь выполнен loopback TLS lab; публичное многомашинное развёртывание и его проверка пока не выполнены.
5. Только после этого gate-record ниже заменяется реальным заключением. Никакой тест или автоматический агент не переводит его в passed.

```json
{
  "gate": "M2 / SEC-01 external specialist review",
  "status": "pending",
  "reviewer": null,
  "reviewed_commit": null,
  "report_url": null,
  "findings": [],
  "acceptance": null
}
```

После выбора специалиста ему можно передать этот пакет. Контакт с внешними людьми и отправка материалов в этой работе не выполнялись.
