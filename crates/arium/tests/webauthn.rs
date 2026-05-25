//! Engine-level passkey tests.
//!
//! These cover everything reachable without a real authenticator: the relying
//! party builds, the per-user handle is stable, ceremony state serializes
//! through serde (the `danger-allow-state-serialisation` feature — the bit most
//! likely to be misconfigured), and the credential store's list/revoke/count
//! logic. A full register→authenticate round-trip needs a browser or a soft
//! authenticator and is exercised by the manual end-to-end check instead.

#![cfg(feature = "webauthn")]

mod common;

use arium::webauthn;

fn test_webauthn() -> webauthn::Webauthn {
    let origin = url::Url::parse("http://localhost:8080").expect("origin");
    webauthn::build_webauthn("localhost", &origin, "arium test").expect("build webauthn")
}

/// Force two values to the same (inferred) type without naming it — lets us
/// assert a serde round-trip on webauthn-rs state types we don't import.
fn assert_same_type<T>(_a: &T, _b: &T) {}

#[tokio::test]
async fn builds_relying_party() {
    // A bare construction shouldn't fail with a sane rp id / origin.
    let _ = test_webauthn();
}

#[tokio::test]
async fn user_handle_is_minted_once_and_stable() {
    let pool = common::pool().await;
    let user_id = common::make_user(&pool, "handle@example.com", "password123").await;

    let first = webauthn::ensure_user_handle(&pool, user_id)
        .await
        .expect("mint handle");
    let second = webauthn::ensure_user_handle(&pool, user_id)
        .await
        .expect("reuse handle");
    assert_eq!(first, second, "handle must be stable across calls");

    // And it was actually persisted.
    let stored: (Option<String>,) =
        sqlx::query_as("SELECT webauthn_user_handle FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .expect("read handle");
    assert_eq!(stored.0.as_deref(), Some(first.to_string().as_str()));
}

#[tokio::test]
async fn registration_state_round_trips_through_serde() {
    let pool = common::pool().await;
    let user_id = common::make_user(&pool, "reg@example.com", "password123").await;
    let wa = test_webauthn();

    let (challenge, state) = webauthn::start_registration(&pool, &wa, user_id, "reg", "Reg User")
        .await
        .expect("start registration");

    // The challenge must serialize (it's sent to the browser as JSON)...
    let challenge_json = serde_json::to_string(&challenge).expect("serialize challenge");
    assert!(challenge_json.contains("challenge"));

    // ...and the in-progress state must round-trip (it rides the session
    // between the two ceremony calls — this is what the serialisation feature
    // gate buys us).
    let state_json = serde_json::to_string(&state).expect("serialize reg state");
    let restored = serde_json::from_str(&state_json).expect("deserialize reg state");
    assert_same_type(&state, &restored);
}

#[tokio::test]
async fn discoverable_challenge_state_round_trips() {
    let wa = test_webauthn();
    let (challenge, state) = webauthn::start_discoverable(&wa).expect("start discoverable");

    let challenge_json = serde_json::to_string(&challenge).expect("serialize challenge");
    assert!(challenge_json.contains("challenge"));

    let state_json = serde_json::to_string(&state).expect("serialize disco state");
    let restored = serde_json::from_str(&state_json).expect("deserialize disco state");
    assert_same_type(&state, &restored);
}

#[tokio::test]
async fn list_revoke_and_count() {
    let pool = common::pool().await;
    let user_id = common::make_user(&pool, "creds@example.com", "password123").await;

    assert!(
        !webauthn::user_has_passkey(&pool, user_id)
            .await
            .expect("has_passkey empty")
    );
    assert!(
        webauthn::list_credentials(&pool, user_id)
            .await
            .expect("list empty")
            .is_empty()
    );

    // Insert two credential rows directly. list/revoke/count only read the
    // table columns (they never deserialize the blob), so a placeholder
    // passkey_json is fine here.
    for cid in ["cred-aaa", "cred-bbb"] {
        sqlx::query(
            "INSERT INTO webauthn_credentials \
             (user_id, credential_id, passkey_json, nickname, created_at) \
             VALUES ($1, $2, '{}', $3, $4)",
        )
        .bind(user_id)
        .bind(cid)
        .bind(format!("{cid} key"))
        .bind(common::now_secs())
        .execute(&pool)
        .await
        .expect("insert credential");
    }

    let listed = webauthn::list_credentials(&pool, user_id)
        .await
        .expect("list two");
    assert_eq!(listed.len(), 2);
    assert!(webauthn::user_has_passkey(&pool, user_id).await.unwrap());

    // Revoking a real id removes it; a bogus id reports no-op.
    assert!(
        webauthn::revoke_credential(&pool, user_id, "cred-aaa")
            .await
            .expect("revoke real")
    );
    assert!(
        !webauthn::revoke_credential(&pool, user_id, "does-not-exist")
            .await
            .expect("revoke bogus")
    );

    let remaining = webauthn::list_credentials(&pool, user_id)
        .await
        .expect("list one");
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].credential_id, "cred-bbb");
}
