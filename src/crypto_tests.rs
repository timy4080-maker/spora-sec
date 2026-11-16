use crate::model::*;
use anyhow::Result;
use libsignal_protocol::{PreKeySignalMessage, SignalMessage};
use spora_core::{Content, Operation, encode_operation, new_id, now_ms, to_b64};

fn pair() -> Result<(State, State)> {
    let mut a = State::new()?;
    let mut b = State::new()?;
    a.add_source(&new_id(), "http://127.0.0.1:7780")?;
    b.add_source(&new_id(), "http://127.0.0.1:7781")?;
    let ai = a.invite(&new_id(), &b.device.fingerprint(), now_ms())?;
    let bi = b.invite(&new_id(), &a.device.fingerprint(), now_ms())?;
    let conv = new_id();
    a.import(bi, &b.device.fingerprint(), &conv, now_ms())?;
    b.import(ai, &a.device.fingerprint(), &conv, now_ms())?;
    Ok((a, b))
}
#[test]
fn authenticated_wrapper_does_not_hide_invalid_signal_ciphertext_or_identity() -> Result<()> {
    let (mut a, mut b) = pair()?;
    let message = a.encrypt(&b.device.id, b"data", now_ms())?;
    let mut packet = Packet::decode(&message)?;
    let last = packet.ciphertext.len() - 1;
    packet.ciphertext[last] ^= 1;
    let before = serde_json::to_vec(&b.crypto)?;
    let mut candidate = b.clone();
    assert!(candidate.decrypt(&packet.encode()?).is_err());
    assert_eq!(before, serde_json::to_vec(&b.crypto)?);
    assert_eq!(b.decrypt(&message)?.1, b"data");
    let before = serde_json::to_vec(&b.crypto)?;
    let mut candidate = b.clone();
    assert!(candidate.decrypt(&message).is_err());
    assert_eq!(before, serde_json::to_vec(&b.crypto)?);
    let reply = b.encrypt(&a.device.id, b"reply", now_ms())?;
    assert_eq!(a.decrypt(&reply)?.1, b"reply");
    b.crypto.identity.trusted.clear();
    let next = a.encrypt(&b.device.id, b"next", now_ms())?;
    assert!(b.decrypt(&next).is_err());
    Ok(())
}
#[test]
fn simultaneous_initiation_device_binding_and_prekey_ownership() -> Result<()> {
    let (mut a, mut b) = pair()?;
    let am = a.encrypt(&b.device.id, b"a", now_ms())?;
    let bm = b.encrypt(&a.device.id, b"b", now_ms())?;
    assert_eq!(a.decrypt(&bm)?.1, b"b");
    assert_eq!(b.decrypt(&am)?.1, b"a");
    for _ in 0..8 {
        let msg = a.encrypt(&b.device.id, b"ab", now_ms())?;
        assert_eq!(b.decrypt(&msg)?.1, b"ab");
        let msg = b.encrypt(&a.device.id, b"ba", now_ms())?;
        assert_eq!(a.decrypt(&msg)?.1, b"ba");
    }
    let (mut a, mut b) = pair()?;
    let msg = a.encrypt(&b.device.id, b"owner", now_ms())?;
    b.crypto
        .owners
        .values_mut()
        .for_each(|owner| *owner = "0".repeat(64));
    assert!(b.decrypt(&msg).is_err());
    let mut wrong = Packet::decode(&msg)?;
    wrong.to = new_id();
    assert!(b.decrypt(&wrong.encode()?).is_err());
    Ok(())
}
#[test]
fn route_wrapping_is_independent_and_context_bound() -> Result<()> {
    let (mut a, b) = pair()?;
    let packet = a.encrypt(&b.device.id, b"route", now_ms())?;
    let route = b.sources.values().next().unwrap().secure.clone();
    let x = route.wrap(&packet)?;
    let y = route.wrap(&packet)?;
    assert_ne!(x, y);
    assert_eq!(&*route.unwrap(&x)?, &packet);
    let mut wrong = route.clone();
    wrong.route.generation = new_id();
    assert!(wrong.unwrap(&x).is_err());
    wrong = route.clone();
    wrong.route.destination_device = new_id();
    assert!(wrong.unwrap(&x).is_err());
    let mut downgraded = x;
    downgraded[0] ^= 1;
    assert!(route.unwrap(&downgraded).is_err());
    Ok(())
}
#[test]
fn measurements_real_signal_and_pq_updates() -> Result<()> {
    let (mut a, mut b) = pair()?;
    let ai = a.invitations.values().next().unwrap();
    let invitation = serde_json::to_vec(ai)?.len();
    let ec = ai.body.prekey.len();
    let signed = ai.body.signed_prekey.len() + ai.body.signed_signature.len();
    let kem = ai.body.kem_prekey.len() + ai.body.kem_signature.len();
    let mut samples = vec![];
    // 512 bidirectional exchanges exercise sparse PQ updates and repeated state reload.
    for n in 0..512 {
        for direction in 0..2 {
            let (sender, receiver) = if direction == 0 {
                (&mut a, &mut b)
            } else {
                (&mut b, &mut a)
            };
            let peer = &sender.peers[&receiver.device.id];
            let op = Operation {
                message_id: new_id(),
                conversation_id: peer.conversation.clone(),
                sender_device: sender.device.id.clone(),
                device_generation: sender.device.generation.clone(),
                sender_seq: n + 1,
                deliver_before_ms: now_ms() + 60000,
                content: Content::Text("x".repeat(32)),
            };
            let plain = encode_operation(&op)?;
            let wire = sender.encrypt(&receiver.device.id, &plain, now_ms())?;
            let packet = Packet::decode(&wire)?;
            let pq = if packet.kind == 3 {
                PreKeySignalMessage::try_from(packet.ciphertext.as_slice())?
                    .message()
                    .pq_ratchet()
                    .len()
            } else {
                SignalMessage::try_from(packet.ciphertext.as_slice())?
                    .pq_ratchet()
                    .len()
            };
            let wrapped = receiver
                .sources
                .values()
                .next()
                .unwrap()
                .secure
                .wrap(&wire)?;
            assert_eq!(receiver.decrypt(&wire)?.1, plain);
            samples.push(serde_json::json!({"exchange":n,"direction":direction,"kind":packet.kind,"application":plain.len(),"signal":packet.ciphertext.len(),"pq":pq,"envelope":wrapped.len(),"base64":to_b64(&wrapped).len()}));
        }
        if n % 32 == 0 {
            a = serde_json::from_slice(&serde_json::to_vec(&a)?)?;
            b = serde_json::from_slice(&serde_json::to_vec(&b)?)?;
        }
    }
    let mut report = serde_json::json!({"suite":crate::SUITE,"libsignal_commit":"8be00c282001caa3585d18de0f044c6d500348ab","plaintext_text_bytes":32,"samples":samples.len(),"invitation_json_bytes":invitation,"one_time_ec_public_bytes":ec,"signed_ec_with_signature_bytes":signed,"kem_public_with_signature_bytes":kem,"initial":samples[0],"first_reply":samples[1],"normal_min_envelope":samples.iter().skip(2).map(|s|s["envelope"].as_u64().unwrap()).min(),"normal_max_envelope":samples.iter().skip(2).map(|s|s["envelope"].as_u64().unwrap()).max(),"max_pq_bytes":samples.iter().map(|s|s["pq"].as_u64().unwrap()).max(),"max_pq_sample":samples.iter().max_by_key(|s|s["pq"].as_u64()).unwrap(),"total_pq_bytes_in_sample":samples.iter().map(|s|s["pq"].as_u64().unwrap()).sum::<u64>(),"radio_4096_exceeded_samples":samples.iter().filter(|s|s["envelope"].as_u64().unwrap()>4096).count(),"note":"Observed sample, not protocol maximum. Re-establishment probe is library-only, not a client restore API (SEC-02)."});
    fn probe(a: &mut State, b: &mut State, content: Content) -> Result<serde_json::Value> {
        let op = Operation {
            message_id: new_id(),
            conversation_id: a.peers[&b.device.id].conversation.clone(),
            sender_device: a.device.id.clone(),
            device_generation: a.device.generation.clone(),
            sender_seq: 1025,
            deliver_before_ms: now_ms() + 60000,
            content,
        };
        let plain = encode_operation(&op)?;
        let wire = a.encrypt(&b.device.id, &plain, now_ms())?;
        let packet = Packet::decode(&wire)?;
        let wrapper = b.sources.values().next().unwrap().secure.wrap(&wire)?;
        assert_eq!(b.decrypt(&wire)?.1, plain);
        Ok(
            serde_json::json!({"application":plain.len(),"signal":packet.ciphertext.len(),"envelope":wrapper.len(),"base64":to_b64(&wrapper).len(),"kind":packet.kind}),
        )
    }
    report["processing_receipt"] = probe(
        &mut b,
        &mut a,
        Content::Receipt {
            original_message_id: new_id(),
            read: false,
        },
    )?;
    let (mut new_a, mut new_b) = pair()?;
    report["new_device_initial"] = probe(&mut new_a, &mut new_b, Content::Text("x".repeat(32)))?;
    report["unacknowledged_second"] = probe(&mut new_a, &mut new_b, Content::Text("x".repeat(32)))?;
    // Deliberately limited to the library spike. The client rejects live refresh/import.
    let fresh = b.invite(&new_id(), &a.device.fingerprint(), now_ms())?;
    a.peers.get_mut(&b.device.id).unwrap().invitation = fresh;
    a.crypto.sessions.0.remove(&b.device.address()?.to_string());
    report["library_only_reestablishment"] = probe(&mut a, &mut b, Content::Text("x".repeat(32)))?;
    if let Ok(path) = std::env::var("SPORA_MEASURE_OUTPUT") {
        std::fs::write(path, serde_json::to_vec_pretty(&report)?)?;
    }
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
