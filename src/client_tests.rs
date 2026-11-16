use super::*;

fn setup() -> Result<(tempfile::TempDir, Client, Client)> {
    let dir = tempfile::tempdir()?;
    let mut a = Client::create(&dir.path().join("a"), true)?;
    let mut b = Client::create(&dir.path().join("b"), true)?;
    a.add_source(&new_id(), "http://127.0.0.1:7001")?;
    b.add_source(&new_id(), "http://127.0.0.1:7002")?;
    let ai = a.invite(&new_id(), &b.device()?.fingerprint(), spora_core::now_ms())?;
    let bi = b.invite(&new_id(), &a.device()?.fingerprint(), spora_core::now_ms())?;
    let conversation = new_id();
    a.import(
        bi,
        &b.device()?.fingerprint(),
        &conversation,
        spora_core::now_ms(),
    )?;
    b.import(
        ai,
        &a.device()?.fingerprint(),
        &conversation,
        spora_core::now_ms(),
    )?;
    Ok((dir, a, b))
}
fn inject(a: &mut Client, b: &mut Client, plain: &[u8]) -> Result<()> {
    let mut p = a.load()?;
    let peer = b.device()?.id;
    let packet = p.state.encrypt(&peer, plain, spora_core::now_ms())?;
    a.commit(p)?;
    b.modify(|s| {
        let local = s.sources.values().next().unwrap();
        let source = local.source.queue_id.clone();
        let envelope = local.secure.wrap(&packet)?;
        let delivery = new_id();
        let r = StorageReceipt {
            service_id: local.source.service_id.clone(),
            queue_id: source.clone(),
            generation: local.source.generation.clone(),
            delivery_id: delivery.clone(),
            seq: "1".into(),
            envelope_sha256: digest(&envelope),
            accepted_at_ms: spora_core::now_ms(),
            expires_at_ms: spora_core::now_ms() + 60000,
        };
        s.inbox.insert(
            inbox_key(&source, &delivery),
            Incoming {
                source,
                entry: PageEntry {
                    receipt: r,
                    envelope_b64url: to_b64(&envelope),
                },
                status: "pending".into(),
                consumed: true,
                next_consume_ms: 0,
                attempts: 0,
                consume_attention: None,
            },
        );
        Ok(())
    })
}
#[test]
fn crypto_valid_application_invalid_commits_ratchet_and_prekey_deletion() -> Result<()> {
    let (_dir, mut a, mut b) = setup()?;
    inject(
        &mut a,
        &mut b,
        b"not deterministic ApplicationOperation CBOR",
    )?;
    assert_eq!(b.apply(spora_core::now_ms())?, 0);
    let s = b.status()?;
    assert_eq!(s.sessions, 1);
    assert_eq!(s.ec_prekeys, 0);
    assert_eq!(s.kem_prekeys, 0);
    assert_eq!(s.message_count, 0);
    assert_eq!(s.pending_receipts, 0);
    assert_eq!(s.quarantined, 1);
    let mut p = a.load()?;
    let conv = p.state.peers[&b.device()?.id].conversation.clone();
    let op = p.state.operation(
        conv,
        Content::Text("after rejected operation".into()),
        spora_core::now_ms(),
    )?;
    inject(&mut a, &mut b, &encode_operation(&op)?)?;
    assert_eq!(b.apply(spora_core::now_ms())?, 1);
    assert_eq!(b.status()?.pending_receipts, 1);
    Ok(())
}
#[test]
fn wrong_receipt_and_application_device_binding_do_not_reserve_message_id() -> Result<()> {
    let (_dir, mut a, mut b) = setup()?;
    let mut p = a.load()?;
    let conv = p.state.peers[&b.device()?.id].conversation.clone();
    let mut op = p.state.operation(
        conv,
        Content::Receipt {
            original_message_id: new_id(),
            read: false,
        },
        spora_core::now_ms(),
    )?;
    inject(&mut a, &mut b, &encode_operation(&op)?)?;
    assert_eq!(b.apply(spora_core::now_ms())?, 0);
    op.content = Content::Text("later valid same application id".into());
    let real = op.sender_device.clone();
    op.sender_device = new_id();
    inject(&mut a, &mut b, &encode_operation(&op)?)?;
    assert_eq!(b.apply(spora_core::now_ms())?, 0);
    op.sender_device = real;
    inject(&mut a, &mut b, &encode_operation(&op)?)?;
    assert_eq!(b.apply(spora_core::now_ms())?, 1);
    Ok(())
}
#[test]
fn full_database_commit_failure_leaves_no_outbox_or_crypto_changes() -> Result<()> {
    let (_dir, mut a, b) = setup()?;
    a.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    let pages: i64 = a
        .conn
        .pragma_query_value(None, "page_count", |r| r.get(0))?;
    a.conn.pragma_update(None, "max_page_count", pages)?;
    let before = a.status()?;
    assert!(
        a.send(
            &new_id(),
            &[b.device()?.id],
            &"x".repeat(8192),
            spora_core::now_ms()
        )
        .is_err()
    );
    assert_eq!(a.status()?.revision, before.revision);
    assert_eq!(a.status()?.sessions, 0);
    assert_eq!(a.status()?.pending_outbox, 0);
    Ok(())
}
#[test]
fn prepared_plan_from_other_profile_is_rejected() -> Result<()> {
    let (_dir, a, mut b) = setup()?;
    let (p, _) = a.prepare_send(
        &new_id(),
        &[b.device()?.id],
        "cross profile",
        spora_core::now_ms(),
    )?;
    assert!(b.commit(p).is_err());
    assert_eq!(b.status()?.sessions, 0);
    Ok(())
}
