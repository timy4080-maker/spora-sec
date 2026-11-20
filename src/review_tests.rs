use super::*;
use crate::client::tests::{inject, setup};

#[test]
fn utf8_limits_and_clock_tolerance_apply_in_both_directions() -> Result<()> {
    let (_dir, mut a, mut b) = setup()?;
    let now = spora_core::now_ms();
    let text = "я".repeat(2048);
    let peers = [b.device()?.id];
    let request = new_id();
    let id = a.send(&request, &peers, &text, now)?;
    assert_eq!(a.send(&request, &peers, &text, now)?, id);
    assert!(
        a.send(&new_id(), &peers, &(text.clone() + "x"), now)
            .is_err()
    );
    let mut state = a.load()?.state;
    let conv = state.peers[&peers[0]].conversation.clone();
    for (body, late, expected) in [
        (text.clone(), 30_000, 1),
        (text.clone() + "x", 0, 0),
        (text, 30_001, 0),
    ] {
        let mut op = state.operation(conv.clone(), Content::Text(body), now)?;
        op.deliver_before_ms = now;
        inject(&mut a, &mut b, &encode_operation(&op)?)?;
        assert_eq!(b.apply(now + late)?, expected);
    }
    let other = state.operation(new_id(), Content::Text("other".into()), now)?;
    assert_eq!(other.sender_seq, 1);
    Ok(())
}
#[test]
fn unchanged_records_survive_cas_replanning_and_cross_record_substitution_fails() -> Result<()> {
    let (dir, mut a, b) = setup()?;
    let now = spora_core::now_ms();
    a.send(&new_id(), &[b.device()?.id], "stable history", now)?;
    let before = a.load()?.manifest;
    let mut concurrent = Client::open(&dir.path().join("a"), true)?;
    let mut attempts = 0;
    a.modify(|s| {
        attempts += 1;
        if attempts == 1 {
            concurrent.add_source(&new_id(), "http://127.0.0.1:7700")?;
        }
        s.add_source(&new_id(), "http://127.0.0.1:7701")
    })?;
    assert_eq!(attempts, 2);
    assert_eq!(a.queues()?.len(), 3);
    let after = a.load()?.manifest;
    for (k, v) in &before {
        assert!(after[k].same_version(v));
    }
    a.conn.execute(
        "UPDATE sealed_records SET payload=(SELECT payload FROM sealed_records LIMIT 1)",
        [],
    )?;
    assert!(a.load().is_err());
    Ok(())
}

#[test]
fn legacy_state_migrates_without_resetting_live_identity_ratchet_or_sequence() -> Result<()> {
    let (dir, mut a, mut b) = setup()?;
    let now = spora_core::now_ms();
    let peer = b.device()?;
    let request = new_id();
    let id = a.send(&request, std::slice::from_ref(&peer.id), "first", now)?;
    let plan = a.load()?;
    let mut legacy = plan.state;
    let identity = legacy.device.identity.clone();
    let first = legacy.outbox.values().next().unwrap();
    let route = &b.load()?.state.sources[&first.route.route.queue_id].secure;
    let packet = route.unwrap(&from_b64(&first.put.envelope_b64url)?)?;
    b.modify(|s| s.decrypt(&packet))?;
    legacy.next_sequence = 23;
    legacy.streams.clear();
    for owner in legacy.crypto.owners.values_mut() {
        *owner = peer.legacy_fingerprint();
    }
    // Serialize only the fields present on 69cc002, then install that schema in this fixture.
    let mut raw = serde_json::to_value(&legacy)?;
    let obj = raw.as_object_mut().unwrap();
    for k in ["streams", "retention", "receipt_cache", "replay_after"] {
        obj.remove(k);
    }
    let rev = plan.revision;
    let blob = vault::seal(&a.key, &aad(&a.id, rev), &serde_json::to_vec(&raw)?)?;
    a.conn
        .execute_batch("DROP TABLE sealed_records; PRAGMA user_version=1;")?;
    a.conn.execute("UPDATE profile SET payload=?1", [blob])?;
    drop(a);
    let mut a = Client::open(&dir.path().join("a"), true)?;
    assert_eq!(a.device()?.identity, identity);
    assert_eq!(
        a.send(&request, std::slice::from_ref(&peer.id), "first", now)?,
        id
    );
    let next = a.send(&new_id(), std::slice::from_ref(&peer.id), "second", now)?;
    let s = a.load()?.state;
    assert_eq!(s.messages[&next].operation.sender_seq, 24);
    assert!(s.crypto.owners.values().all(|o| o == &peer.fingerprint()));
    let j = s.outbox.values().find(|j| j.message_id == next).unwrap();
    let packet = route.unwrap(&from_b64(&j.put.envelope_b64url)?)?;
    assert_eq!(
        decode_operation(&b.modify(|s| s.decrypt(&packet))?.1)?.message_id,
        next
    );
    assert_eq!(
        a.conn
            .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))?,
        2
    );
    Ok(())
}

#[test]
fn admission_stops_new_jobs_and_gc_reopens_capacity_preserving_unresolved_input() -> Result<()> {
    let (_dir, mut a, mut b) = setup()?;
    let now = spora_core::now_ms();
    let peer = b.device()?;
    inject(&mut b, &mut a, b"retain pending input")?;
    let id = a.send(&new_id(), std::slice::from_ref(&peer.id), "old", now)?;
    a.modify(|s| {
        let template = s.messages[&id].clone();
        for _ in 0..2000 {
            let mut m = template.clone();
            m.operation.message_id = new_id();
            m.operation.content = Content::Text("A".repeat(4096));
            s.messages.insert(m.operation.message_id.clone(), m);
        }
        Ok(())
    })?;
    let rev = a.status()?.revision;
    assert!(
        a.send(&new_id(), std::slice::from_ref(&peer.id), "full", now)
            .unwrap_err()
            .to_string()
            .contains("admission")
    );
    assert_eq!(a.status()?.revision, rev);
    let past = now + spora_core::RETENTION_MS + spora_core::DEDUP_MS + 1;
    a.gc(past, false)?;
    assert!(a.status()?.message_count > 2000);
    assert_eq!(a.status()?.pending_inbox, 1);
    a.gc(past, true)?;
    assert_eq!(a.status()?.message_count, 0);
    assert_eq!(a.status()?.pending_inbox, 1);
    a.send(&new_id(), &[peer.id], "space reclaimed", past)?;
    Ok(())
}
#[test]
fn duplicate_after_restart_rearms_exact_live_receipt_once() -> Result<()> {
    let (dir, mut a, mut b) = setup()?;
    let now = spora_core::now_ms();
    let mut state = a.load()?.state;
    let conv = state.peers[&b.device()?.id].conversation.clone();
    let op = state.operation(conv, Content::Text("retry receipt".into()), now)?;
    inject(&mut a, &mut b, &encode_operation(&op)?)?;
    assert_eq!(b.apply(now)?, 1);
    b.prepare_receipts(now)?;
    let first = b.outgoing()?.remove(0);
    b.modify(|s| {
        s.outbox.get_mut(&first.delivery_id).unwrap().relay_stored = true;
        Ok(())
    })?;
    drop(b);
    let mut b = Client::open(&dir.path().join("b"), true)?;
    let replay = |s: &mut State| -> Result<()> {
        let mut i = s.inbox.values().next().unwrap().clone();
        i.status = "pending".into();
        s.inbox.insert(new_id(), i);
        Ok(())
    };
    let crypto = serde_json::to_vec(&b.load()?.state.crypto)?;
    b.modify(replay)?;
    b.apply(now)?;
    let again = b.outgoing()?.remove(0);
    assert!(again.replay_pending && again.relay_stored);
    assert_eq!(again.delivery_id, first.delivery_id);
    assert_eq!(again.put.envelope_b64url, first.put.envelope_b64url);
    assert_eq!(again.put.expires_at_ms, first.put.expires_at_ms);
    b.modify(|s| {
        s.outbox.get_mut(&first.delivery_id).unwrap().replay_pending = false;
        replay(s)
    })?;
    b.apply(now + 120_000)?;
    assert!(!b.outgoing()?[0].replay_pending);
    assert_eq!(crypto, serde_json::to_vec(&b.load()?.state.crypto)?);
    Ok(())
}

#[test]
fn bootstrap_bytes_match_independent_cbor_vector() -> Result<()> {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../tests/fixtures/bootstrap-v2.json"))?;
    let mut inv: Invitation = serde_json::from_value(fixture["invitation"].clone())?;
    assert_eq!(
        inv.body.device.fingerprint(),
        fixture["fingerprint"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(inv.signed_bytes()?),
        fixture["signed_cbor_hex"].as_str().unwrap()
    );
    for version in [0, 1, 3, u8::MAX] {
        inv.version = version;
        assert!(inv.signed_bytes().is_err());
    }
    let mut missing = fixture["invitation"].clone();
    missing.as_object_mut().unwrap().remove("version");
    let legacy: Invitation = serde_json::from_value(missing)?;
    assert!(legacy.signed_bytes().is_err());
    Ok(())
}

#[test]
fn invitations_require_recipient_specific_route_selection_when_over_four() -> Result<()> {
    let (_dir, mut a, b) = setup()?;
    let now = spora_core::now_ms();
    let mut selected = vec![];
    for _ in 0..4 {
        selected.push(a.add_source(&new_id(), "http://127.0.0.1:7780")?);
    }
    let req = new_id();
    let fp = b.device()?.fingerprint();
    let before = a.status()?.ec_prekeys;
    assert!(a.invite(&req, &fp, now).is_err());
    assert_eq!(a.status()?.ec_prekeys, before);
    let inv = a.invite_routes(&req, &fp, now, &selected[..1])?;
    assert_eq!(inv.body.routes.len(), 1);
    assert_eq!(inv.body.routes[0].route.queue_id, selected[0]);
    assert!(a.invite_routes(&req, &fp, now, &selected[1..]).is_err());
    Ok(())
}

#[test]
fn old_prekeys_are_retained_only_for_matching_unresolved_work() -> Result<()> {
    let (dir, mut a, mut b) = setup()?;
    let now = spora_core::now_ms();
    let unrelated = b
        .invite(&new_id(), &digest(b"unrelated recipient"), now)?
        .body
        .key_id;
    inject(&mut a, &mut b, b"pending application bytes")?;
    let state = b.load()?.state;
    let item = state.inbox.values().next().unwrap();
    let needed = state.referenced_prekey(item).unwrap();
    assert_ne!(needed, unrelated);
    b.modify(|s| {
        let mut retained = item.clone();
        retained.entry.envelope_b64url = to_b64(b"unrecognized wrapper");
        retained.status = "quarantined".into();
        s.inbox.insert("retained-fixture".into(), retained);
        Ok(())
    })?;
    let late = now + 60 * 86_400_000;
    b.gc(late, true)?;
    drop(b);
    let mut b = Client::open(&dir.path().join("b"), true)?;
    let state = b.load()?.state;
    assert_eq!(state.inbox.len(), 2);
    assert_eq!(state.invitations.len(), 1);
    assert!(state.crypto.prekeys.0.contains_key(&needed));
    assert!(!state.crypto.signed.0.contains_key(&unrelated));
    assert!(!state.crypto.kyber.0.contains_key(&unrelated));
    // libsignal can still process the retained item. Its application body is intentionally invalid.
    assert_eq!(b.apply(late)?, 0);
    assert_eq!(b.status()?.sessions, 1);
    assert_eq!(b.status()?.pending_receipts, 0);
    b.gc(late, true)?;
    let state = b.load()?.state;
    assert!(state.invitations.is_empty());
    assert!(state.crypto.owners.is_empty());
    assert_eq!(state.inbox["retained-fixture"].status, "quarantined");
    Ok(())
}

#[test]
fn shared_and_legacy_queues_keep_a_separate_bounded_reservation() -> Result<()> {
    use crate::model::QueueGrant;
    use crate::retention::admits_unresolved;
    let (_dir, mut a, mut b) = setup()?;
    inject(&mut a, &mut b, b"test fixture")?;
    let mut state = b.load()?.state;
    let entry = state.inbox.values().next().unwrap().clone();
    let mut source = state.sources[&entry.source].clone();
    let mut legacy = serde_json::to_value(&source)?;
    legacy.as_object_mut().unwrap().remove("grant");
    source = serde_json::from_value(legacy)?;
    source.grant.issue("next-recipient");
    assert_eq!(source.grant, QueueGrant::Shared);
    let make_page = |id: &str| {
        let mut new_entry = entry.entry.clone();
        new_entry.receipt.delivery_id = new_id();
        MessagePage {
            queue_id: id.into(),
            generation: source.source.generation.clone(),
            next_after: "2".into(),
            has_more: false,
            items: vec![new_entry],
        }
    };
    let page = make_page(&entry.source);
    state.inbox.clear();
    for n in 0..256 {
        let mut job = entry.clone();
        job.quota_owner = None;
        job.status = "quarantined".into();
        if n >= 64 {
            job.source = format!("other-{}", n / 64);
        }
        state.inbox.insert(n.to_string(), job);
        if n == 63 {
            assert!(!admits_unresolved(&state.inbox, &source, &page));
        }
    }
    source.source.queue_id = new_id();
    assert!(!admits_unresolved(
        &state.inbox,
        &source,
        &make_page(&source.source.queue_id)
    ));
    source.grant = QueueGrant::Exclusive("dedicated".into());
    assert!(admits_unresolved(
        &state.inbox,
        &source,
        &make_page(&source.source.queue_id)
    ));
    source.grant.issue("dedicated");
    assert_eq!(source.grant.owner(), Some("dedicated"));
    // A second queue issued to the same fingerprint shares the reservation across routes.
    for job in state.inbox.values_mut().take(128) {
        job.quota_owner = Some("dedicated".into());
    }
    assert!(!admits_unresolved(
        &state.inbox,
        &source,
        &make_page(&source.source.queue_id)
    ));
    source.grant.issue("additional recipient");
    source.grant.issue("dedicated");
    assert_eq!(source.grant, QueueGrant::Shared);
    Ok(())
}
