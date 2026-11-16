# Проверка SEC-01, 16 ноября 2026

Локально пройдены Rust tests, fmt и clippy с `-D warnings`, а также отдельный TLS-стенд. Полные результаты в [rust-tests.txt](evidence/rust-tests.txt), [tls-lab.json](evidence/tls-lab.json), [sizes.json](evidence/sizes.json). GitHub Actions дополнительно проверяет Ubuntu и Windows MSVC; конкретный remote run нужно сверять по Actions, наличие workflow само по себе не означает успешного CI.

## Покрытие

20 Rust-тестов на Windows (19 на Linux, где нет DPAPI): независимые устройства/сессии и маршруты, recipient offline, сериализация/reopen, process exit до/после COMMIT, CAS stale plan и другой профиль, SQLITE_FULL, потерянный PUT/consume response, outage/backoff после restart, retry-after и остановка после 16 ошибок, повтор request, переупорядочение, изоляция источника с конфликтным replay, invitation tampering/fingerprint/suite/device binding, prekey ownership, неизвестная identity, bad inner ciphertext, replay, неверный route AAD, rejected application с обязательным сохранением ratchet/prekeys, отсутствие ложного receipt/dedup reservation, защита БД/WAL от plaintext, отсутствующая/заменённая KEK и DPAPI round-trip.

Интеграционные тесты используют настоящий Store из закреплённого spora-relay. Fault transport только теряет ответы/отключает доступ; E2EE выполняет libsignal. Отдельный Python-стенд использует настоящие процессы Relay и HTTP/TLS adapter, три client profiles, две очереди на устройство, kill/restart и применение после удаления серверных копий. Все временные секреты удаляются; evidence содержит только счётчики и размеры.

## Измерения

1024 сообщения, 512 двусторонних обменов, текст 32 bytes, C-01 operation 124–126 bytes. Периодический serialize/reload State. Значения — конкретный прогон, не верхняя граница протокола.

| Сценарий | libsignal ciphertext | Полный envelope | Base64url |
|---|---:|---:|---:|
| Первое сообщение, PQXDH | 1873 | 1954 | 2606 |
| Первый ответ | 185 | 266 | 355 |
| Обычные сообщения в выборке | 185–218 | 266–299 | 355–399 |
| Подтверждение обработки в измеренной фазе | 218 | 299 | 399 |
| Первое сообщение новому устройству | 1873 | 1954 | 2606 |
| Следующее сообщение до обратного ответа | 1873 | 1954 | 2606 |
| Новое установление с fresh bundle, library-only probe | 1873 | 1954 | 2606 |

Отдельно: EC public key 33 bytes; signed EC public+signature 97; Kyber public+signature 1633. Подписанное приглашение в текущем JSON около 7.7 KiB (точный размер в evidence), больше будущего бюджета 4096. CLI pretty JSON может быть ещё больше. Это отдельный формат конфиденциального bootstrap, а не радиокадр.

Максимальная отдельная SPQR часть в выборке — 37 bytes; суммарно 33070 bytes на 1024 сообщения. SPQR распределяет логическое PQ-обновление по сообщениям. Здесь не утверждается, что полный rekey стоит 37 bytes, и не доказывается worst-case. Radio overhead, fragmentation/reassembly, дополнительные retries и приглашения не учтены. Радиоканал не подключён.

Library-only re-establishment использует свежие prekeys и очищает initiator session **только внутри тестового spike**. Он проверяет upstream способность принять новую сессию; пользовательский restore/refresh API не добавлен. SEC-02 по-прежнему отдельная работа.

## Ограничение доказательств

Тесты доказывают наблюдаемое поведение прототипа в указанных сценариях. Они не являются криптоанализом, независимым аудитом, power-loss испытанием диска/контроллера или доказательством защиты от согласованного rollback. Tests delivery, CI и этот отчёт не закрывают M2.
