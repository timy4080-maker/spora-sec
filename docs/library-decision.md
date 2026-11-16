# SEC-01: выбор библиотеки, 16 ноября 2026

Владелец разрешил AGPL-3.0 для открытого клиента. Выбран libsignal: он соответствует исходному Rust spike и парным сессиям устройств, включает асинхронное начало через prekey bundle и постквантовые механизмы. Выбор подтверждён работающим адаптером; внешний security review интеграции ещё не выполнен.

| Кандидат | Конкретная версия / commit | Лицензия | Соответствие и цена интеграции |
|---|---|---|---|
| [libsignal](https://github.com/signalapp/libsignal/tree/v0.108.0) | v0.108.0 / `8be00c282001caa3585d18de0f044c6d500348ab` | [AGPL-3.0-only](https://github.com/signalapp/libsignal/blob/v0.108.0/Cargo.toml) | Выбран. Rust storage callbacks позволяют подготовить изменения в памяти. PQXDH и Triple Ratchet с SPQR. Third-party use не поддерживается upstream; Rust API внутренний, обновления требуют повторной проверки. |
| [vodozemac](https://github.com/matrix-org/vodozemac/tree/0.11.2) | 0.11.2 / `fb4a9980a1038c646824ea7e64567eec28bf582e` | [Apache-2.0](https://github.com/matrix-org/vodozemac/blob/0.11.2/LICENSE) | Rust Olm/Megolm; компактная альтернатива для парных сессий. Не выбран: другой протокол и отсутствие заявленного PQXDH/SPQR в этом API. Исторический аудит upstream не проверяет нашу обвязку. |
| [OpenMLS](https://github.com/openmls/openmls/tree/openmls-v0.9.0) | openmls-v0.9.0 / `3a3e35de3feeca8f6605143c464d5452ae584d43` | [MIT](https://github.com/openmls/openmls/blob/openmls-v0.9.0/LICENSE) | RFC 9420 MLS: KeyPackages, группы, epochs/commits. Возможен асинхронный обмен, но потребуется другой контракт control/dependencies и групповой модели. В текущем парном прототипе не выбран. |
| [SimpleX Chat](https://github.com/simplex-chat/simplex-chat/tree/v7.1.3) | v7.1.3 / `19889b1a0ee11b6071c41146b6549f46e2b5b6af` | [AGPL-3.0](https://github.com/simplex-chat/simplex-chat/blob/v7.1.3/LICENSE) | Полный стек со своими агентом, хранилищем и транспортом. Рассматривался как альтернатива архитектуре, а не готовый drop-in Rust provider. Эта версия не собиралась в spike. |

Версии и LICENSE проверены по официальным репозиториям. Для невыбранных библиотек выполнено документальное сравнение; сравнительный benchmark и аудит всех кандидатов не проводились. Вывод о цене интеграции — инженерная оценка требований Spora.

## Закрепление сборки

Cargo.lock фиксирует весь граф. `libsignal-protocol` внутри upstream имеет package version 0.1.0; это **не** номер релиза libsignal. Идентификатор интеграции определяется release v0.108.0 и полным Git SHA. SPQR: v1.7.0, точный commit в Cargo.lock; libcrux-ml-kem 0.0.10. Нельзя обновлять их независимо без повторения spike.

У upstream rust-toolchain = 1.98.1; здесь закреплён Rust 1.100.0. Локальная проверка: Windows x86_64-pc-windows-gnullvm, LLVM-MinGW 20261104. Protoc 36.2; checksum Windows zip `f0c128dc0d8492eceece83bb459a4c0e316764b929ffbf1aa416357fd644edd3`. CI также проверяет Linux и Windows MSVC.

База C-01/03: spora-client `60804711d61290a0b973435bb776d330db313438`, Relay `97d5b5c02ebc719f86d9d192aa42e1a25c913797`. Исправленные commits опубликованы в ветках `codex/sec01-reviewed-base`; main предыдущих проектов не изменялся. В production-графе нет зависимости spora-synthetic; из spora-core используются формат операции, модели C-03 и ошибки. Старый Client/CryptoProvider не используется.

## Лицензионный учёт

[Инвентарь](evidence/dependency-licenses.json) сформирован из `cargo metadata --locked`, включая build/dev/target dependencies. Он фиксирует declared licenses и не заменяет юридическое заключение. Код spora-core и spora-relay принадлежит этому же проекту, но в их manifest LICENSE не объявлена; прежнее решение владельца не менять эти репозитории сохранено. Перед распространением объединённого продукта нужно оформить права на эти компоненты. Новый код spora-sec и libsignal распространяются с AGPL-3.0-only; соответствующие исходники и закреплённые версии доступны.

Обновление: отдельная ветка, review upstream changes/совместимости storage и wire, новый lockfile, повтор negative/crash/TLS/size tests, сравнение лицензий и advisory scan, затем внешнее ревью затронутой поверхности. Автоматическое обновление криптографического графа не включено.
