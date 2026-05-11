//! Internal macros for sync/async code unification.
//!
//! These macros allow sharing method bodies between synchronous and asynchronous
//! connection types. The only differences between sync and async are:
//! - `fn` vs `async fn` signatures
//! - `.await` after I/O calls
//! - `Read + Write` vs `AsyncRead + AsyncWrite + Unpin` trait bounds
//!
//! Each I/O method body is captured in a macro that accepts a `$mode` parameter
//! (`sync` or `is_async`) and uses `maybe_await!` to conditionally `.await`.

/// Conditionally `.await` an expression based on sync/async mode.
///
/// - `maybe_await!(sync, expr)` expands to `expr`
/// - `maybe_await!(is_async, expr)` expands to `expr.await`
macro_rules! maybe_await {
    (sync, $e:expr) => {
        $e
    };
    (is_async, $e:expr) => {
        $e.await
    };
}

// =========================================================================
// Shared I/O body macros (used by both TLS 1.3 and TLS 1.2, client + server)
// =========================================================================

/// Body for `fill_buf`: read at least `$min_bytes` from the stream into `read_buf`.
macro_rules! fill_buf_body {
    ($mode:ident, $self:ident, $min_bytes:expr) => {{
        let min = $min_bytes;
        while $self.read_buf.len() < min {
            let mut tmp = [0u8; 16384];
            let n = maybe_await!($mode, $self.stream.read(&mut tmp))
                .map_err(|e| TlsError::RecordError(format!("read error: {e}")))?;
            if n == 0 {
                return Err(TlsError::RecordError("unexpected EOF".into()));
            }
            $self.read_buf.extend_from_slice(&tmp[..n]);
        }
        Ok(())
    }};
}

/// Body for `read_record`: read a single TLS record from the stream.
///
/// **TLS 1.2 / TLCP / DTLS variant.** CCS is a real protocol message in
/// these versions, so no filtering or compliance enforcement is applied
/// here. The TLS 1.3 path uses [`read_record_body_tls13`] instead, which
/// enforces RFC 8446 §5 CCS rules.
macro_rules! read_record_body {
    ($mode:ident, $self:ident) => {{
        loop {
            maybe_await!($mode, $self.fill_buf(5))?;
            let length = u16::from_be_bytes([$self.read_buf[3], $self.read_buf[4]]) as usize;
            maybe_await!($mode, $self.fill_buf(5 + length))?;
            let (ct, plaintext, consumed) = $self.record_layer.open_record(&$self.read_buf)?;
            $self.read_buf.drain(..consumed);
            break Ok((ct, plaintext));
        }
    }};
}

/// Body for `read_record` (TLS 1.3 only). Enforces RFC 8446 §5 / §D.4
/// ChangeCipherSpec compatibility rules (Phase T88):
///
/// - During the handshake (`state == Handshaking`), a CCS that is exactly
///   the single byte `0x01` is silently dropped (standard middlebox-
///   compatibility allowance).
/// - During the handshake, a CCS with **any other payload** (zero-byte,
///   multi-byte, anything but `0x01`) is rejected as an unexpected
///   message — "An implementation which receives any other
///   change_cipher_spec message MUST abort the handshake with an
///   `unexpected_message` alert."
/// - **After** the handshake (`state != Handshaking`), any CCS is
///   rejected — the spec only permits CCS before the peer's Finished.
/// - When the connection has `middlebox_compat == false`, the CCS
///   compatibility carve-out does not apply and any CCS is unexpected.
macro_rules! read_record_body_tls13 {
    ($mode:ident, $self:ident) => {{
        loop {
            maybe_await!($mode, $self.fill_buf(5))?;
            let length = u16::from_be_bytes([$self.read_buf[3], $self.read_buf[4]]) as usize;
            maybe_await!($mode, $self.fill_buf(5 + length))?;
            let (ct, plaintext, consumed) = $self.record_layer.open_record(&$self.read_buf)?;
            $self.read_buf.drain(..consumed);
            if ct == ContentType::ChangeCipherSpec {
                let bad_ccs_reason: Option<String> = if $self.state != ConnectionState::Handshaking
                {
                    Some(
                        "unexpected ChangeCipherSpec after handshake completion \
                         (RFC 8446 §5: alert unexpected_message)"
                            .to_string(),
                    )
                } else if plaintext.len() != 1 || plaintext[0] != 0x01 {
                    Some(format!(
                        "malformed ChangeCipherSpec — TLS 1.3 only accepts a \
                         single 0x01 byte during the handshake (got {} bytes), \
                         RFC 8446 §5: alert unexpected_message",
                        plaintext.len()
                    ))
                } else if !$self.config.middlebox_compat {
                    Some(
                        "ChangeCipherSpec received but middlebox_compat is off \
                         — RFC 8446 §D.4: alert unexpected_message"
                            .to_string(),
                    )
                } else if $self.ccs_seen_in_handshake {
                    // Phase T95 / CVE-2020-25648 hardening — RFC 8446 §5
                    // *permits* multiple CCS during handshake but we
                    // accept exactly one (matches OpenSSL/BoringSSL/NSS).
                    Some(
                        "second ChangeCipherSpec during handshake \
                         (CVE-2020-25648 hardening) — RFC 8446 §5: \
                         alert unexpected_message"
                            .to_string(),
                    )
                } else {
                    None
                };
                if let Some(reason) = bad_ccs_reason {
                    // RFC 8446 §6 — abort with `unexpected_message` alert (10).
                    // The fatal alert send is now centralised in
                    // `send_fatal_alert_for_error_body!` (Phase T89) which
                    // is invoked by the handshake-trait wrapper. Each
                    // `reason` above contains the literal substring
                    // `"unexpected_message"` so `tls_error_to_alert`
                    // maps it to `AlertDescription::UnexpectedMessage`.
                    return Err(TlsError::HandshakeFailed(reason));
                }
                // First (and only) CCS at this handshake round — silently
                // drop, mark seen, continue the read loop. The flag is
                // cleared below when a real handshake message arrives,
                // so the legitimate HRR flow (server sends CCS after
                // HRR AND after SH at the next round) still works.
                $self.ccs_seen_in_handshake = true;
                continue;
            }
            // Non-CCS record received → next handshake "round" begins.
            // Reset the multi-CCS tripwire so a subsequent legitimate
            // CCS at the new round is accepted (HRR-then-SH case).
            // Any back-to-back CCSes WITHIN the same round still get
            // caught (the relevant CVE-2020-25648 attack surface).
            if ct == ContentType::Handshake {
                $self.ccs_seen_in_handshake = false;
            }
            // Phase T103 — RFC 8446 §5.1: "Implementations MUST NOT
            // send zero-length fragments of Handshake or Alert types,
            // even if those fragments contain padding." We refuse
            // empty Alert records here (tlsfuzzer's
            // `test-tls13-empty-alert.py` pins this).
            //
            // Zero-length ApplicationData is explicitly *allowed* by
            // §5.1 ("MAY be sent ... potentially useful as a traffic
            // analysis countermeasure") — the call-site decides
            // whether AppData is acceptable in the current state
            // (e.g. step 5c/6 of the server handshake reject ANY
            // AppData with `unexpected_message`).
            //
            // Empty Handshake fragments are also forbidden by §5.1
            // but legacy peers occasionally emit them during back-
            // to-back fragmentation; we fall through to the existing
            // handshake reassembly path so the upstream parser can
            // decide.
            if plaintext.is_empty() && ct == ContentType::Alert {
                break Err(TlsError::HandshakeFailed(
                    "zero-length Alert record fragment is forbidden by \
                     RFC 8446 §5.1 — alert: unexpected_message"
                        .into(),
                ));
            }
            break Ok((ct, plaintext));
        }
    }};
}

/// Send a fatal alert derived from an internal `TlsError` (Phase T89).
///
/// Best-effort: if the record layer can't seal the alert (e.g. write
/// encryption isn't installed yet) or the stream write fails (peer
/// already gone), we silently swallow — the caller is about to return
/// the original error and close anyway. The point is that under normal
/// circumstances the peer sees a wire-level fatal alert with the
/// description that maps to the failure, instead of a bare TCP close.
///
/// `$err` is taken by reference (`&TlsError`) so the caller can still
/// move/return the original error after we run.
macro_rules! send_fatal_alert_for_error_body {
    ($mode:ident, $self:ident, $err:expr) => {{
        let desc = $crate::alert::tls_error_to_alert($err);
        // Suppress the alert for `CloseNotify` mappings — those are
        // symmetric paths where the peer already closed; sending an
        // alert back is at best redundant, at worst will hit a closed
        // socket.
        if !matches!(desc, $crate::alert::AlertDescription::CloseNotify) {
            let alert_data = [2u8, desc as u8];
            if let Ok(record) = $self
                .record_layer
                .seal_record(ContentType::Alert, &alert_data)
            {
                let _ = maybe_await!($mode, $self.stream.write_all(&record));
            }
        }
    }};
}

/// `?`-like operator that, on `Err`, runs `send_fatal_alert_for_error_body!`
/// before propagating the error (Phase T89). Use this instead of `?` at
/// every read-path call site where the failure mode is one the peer
/// should be told about (record-layer errors, unexpected content type,
/// rejected post-handshake message). For pure plumbing failures (lock
/// poisoning, internal invariant breaks) plain `?` is fine.
macro_rules! try_alert {
    ($mode:ident, $self:ident, $expr:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => {
                send_fatal_alert_for_error_body!($mode, $self, &e);
                $self.state = ConnectionState::Error;
                return Err(e);
            }
        }
    };
}

/// `return Err(e)` with a fatal-alert side effect first. Used for paths
/// that detect an error themselves (no upstream `Result` to propagate).
macro_rules! return_alert_err {
    ($mode:ident, $self:ident, $err:expr) => {{
        let e = $err;
        send_fatal_alert_for_error_body!($mode, $self, &e);
        $self.state = ConnectionState::Error;
        return Err(e);
    }};
}

/// Send a fake ChangeCipherSpec record for middlebox compatibility (RFC 8446 §D.4).
/// The CCS payload is a single byte 0x01, sent as plaintext with legacy version 0x0303.
macro_rules! send_fake_ccs_body {
    ($mode:ident, $self:ident) => {{
        if $self.config.middlebox_compat {
            let ccs_record: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
            maybe_await!($mode, $self.stream.write_all(&ccs_record))
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }
    }};
}

/// Body for `write` trait method (TLS 1.3 + 1.2, client + server).
macro_rules! tls_write_trait_body {
    ($mode:ident, $self:ident, $buf:ident) => {{
        if $self.state != ConnectionState::Connected {
            return Err(TlsError::RecordError(
                "not connected (handshake not done)".into(),
            ));
        }

        if $buf.is_empty() {
            return Ok(0);
        }

        let max_frag = $self.record_layer.max_fragment_size;
        let mut offset = 0;
        while offset < $buf.len() {
            let end = std::cmp::min(offset + max_frag, $buf.len());
            let record = $self
                .record_layer
                .seal_record(ContentType::ApplicationData, &$buf[offset..end])?;
            maybe_await!($mode, $self.stream.write_all(&record))
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
            offset = end;
        }
        Ok($buf.len())
    }};
}

// =========================================================================
// TLS 1.3 client body macros
// =========================================================================

/// Body for TLS 1.3 client `key_update`.
macro_rules! tls13_client_key_update_body {
    ($mode:ident, $self:ident, $request_response:expr) => {{
        if $self.state != ConnectionState::Connected {
            return Err(TlsError::HandshakeFailed(
                "key_update: not connected".into(),
            ));
        }
        let params = $self
            .cipher_params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher params".into()))?
            .clone();
        let ku = KeyUpdateMsg {
            request_update: if $request_response {
                KeyUpdateRequest::UpdateRequested
            } else {
                KeyUpdateRequest::UpdateNotRequested
            },
        };
        let ku_msg = encode_key_update(&ku);
        let record = $self
            .record_layer
            .seal_record(ContentType::Handshake, &ku_msg)?;
        maybe_await!($mode, $self.stream.write_all(&record))
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        let ks = KeySchedule::new(params.clone());
        let new_secret = ks.update_traffic_secret(&$self.client_app_secret)?;
        let new_keys = TrafficKeys::derive(&params, &new_secret)?;
        $self
            .record_layer
            .activate_write_encryption(params.suite, &new_keys)?;
        $self.client_app_secret.zeroize();
        $self.client_app_secret = new_secret;
        Ok(())
    }};
}

/// Body for TLS 1.3 client `handle_key_update`.
macro_rules! tls13_client_handle_key_update_body {
    ($mode:ident, $self:ident, $body:expr) => {{
        $self.key_update_recv_count += 1;
        if $self.key_update_recv_count > 128 {
            return Err(TlsError::HandshakeFailed(
                "too many consecutive KeyUpdate messages without application data".into(),
            ));
        }
        let ku = decode_key_update($body)?;
        let params = $self
            .cipher_params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher params".into()))?
            .clone();
        let ks = KeySchedule::new(params.clone());
        let new_secret = ks.update_traffic_secret(&$self.server_app_secret)?;
        let new_keys = TrafficKeys::derive(&params, &new_secret)?;
        $self
            .record_layer
            .activate_read_decryption(params.suite, &new_keys)?;
        $self.server_app_secret.zeroize();
        $self.server_app_secret = new_secret;
        if ku.request_update == KeyUpdateRequest::UpdateRequested {
            maybe_await!($mode, $self.key_update(false))?;
        }
        Ok(())
    }};
}

/// Body for TLS 1.3 client `handle_post_hs_cert_request`.
macro_rules! tls13_client_handle_post_hs_cert_request_body {
    ($mode:ident, $self:ident, $body:expr, $full_msg:expr) => {{
        use crate::handshake::signing::{select_signature_scheme, sign_certificate_verify};

        if !$self.config.post_handshake_auth {
            return Err(TlsError::HandshakeFailed(
                "received CertificateRequest but post_handshake_auth not offered".into(),
            ));
        }

        let cr = decode_certificate_request($body)?;

        let sig_algs_ext = cr
            .extensions
            .iter()
            .find(|e| e.extension_type == crate::extensions::ExtensionType::SIGNATURE_ALGORITHMS)
            .ok_or_else(|| {
                TlsError::HandshakeFailed("CertificateRequest missing signature_algorithms".into())
            })?;
        let server_sig_algs =
            crate::handshake::extensions_codec::parse_signature_algorithms_ch(&sig_algs_ext.data)?;

        let params = $self
            .cipher_params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher params".into()))?
            .clone();
        let alg = params.hash_alg_id();
        let ks = KeySchedule::new(params.clone());

        let mut hasher = DigestVariant::new(alg);
        hasher.update($full_msg).map_err(TlsError::CryptoError)?;
        let mut cr_hash = [0u8; 64];
        hasher
            .finish(&mut cr_hash[..params.hash_len])
            .map_err(TlsError::CryptoError)?;

        let cert_msg = if $self.config.client_certificate_chain.is_empty() {
            CertificateMsg {
                certificate_request_context: cr.certificate_request_context.clone(),
                certificate_list: vec![],
            }
        } else {
            CertificateMsg {
                certificate_request_context: cr.certificate_request_context.clone(),
                certificate_list: $self
                    .config
                    .client_certificate_chain
                    .iter()
                    .map(|cert_der| CertificateEntry {
                        cert_data: cert_der.clone(),
                        extensions: vec![],
                    })
                    .collect(),
            }
        };
        let cert_encoded = encode_certificate(&cert_msg);

        let mut hasher2 = DigestVariant::new(alg);
        hasher2.update($full_msg).map_err(TlsError::CryptoError)?;
        hasher2
            .update(&cert_encoded)
            .map_err(TlsError::CryptoError)?;

        let cert_record = $self
            .record_layer
            .seal_record(ContentType::Handshake, &cert_encoded)?;
        maybe_await!($mode, $self.stream.write_all(&cert_record))
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        if let Some(ref client_key) = $self.config.client_private_key {
            let scheme = select_signature_scheme(client_key, &server_sig_algs)?;

            let mut cv_hash = [0u8; 64];
            let mut hasher3 = DigestVariant::new(alg);
            hasher3.update($full_msg).map_err(TlsError::CryptoError)?;
            hasher3
                .update(&cert_encoded)
                .map_err(TlsError::CryptoError)?;
            hasher3
                .finish(&mut cv_hash[..params.hash_len])
                .map_err(TlsError::CryptoError)?;

            let signature =
                sign_certificate_verify(client_key, scheme, &cv_hash[..params.hash_len], false)?;
            let cv_msg = encode_certificate_verify(&CertificateVerifyMsg {
                algorithm: scheme,
                signature,
            });

            let cv_record = $self
                .record_layer
                .seal_record(ContentType::Handshake, &cv_msg)?;
            maybe_await!($mode, $self.stream.write_all(&cv_record))
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

            // Finished hash: Hash(CR || Certificate || CertificateVerify)
            let finished_key = ks.derive_finished_key(&$self.client_app_secret)?;
            let mut fin_hash = [0u8; 64];
            let mut hasher4 = DigestVariant::new(alg);
            hasher4.update($full_msg).map_err(TlsError::CryptoError)?;
            hasher4
                .update(&cert_encoded)
                .map_err(TlsError::CryptoError)?;
            hasher4.update(&cv_msg).map_err(TlsError::CryptoError)?;
            hasher4
                .finish(&mut fin_hash[..params.hash_len])
                .map_err(TlsError::CryptoError)?;

            let verify_data =
                ks.compute_finished_verify_data(&finished_key, &fin_hash[..params.hash_len])?;
            let fin_msg = encode_finished(&verify_data);

            let fin_record = $self
                .record_layer
                .seal_record(ContentType::Handshake, &fin_msg)?;
            maybe_await!($mode, $self.stream.write_all(&fin_record))
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        } else {
            // No private key: send Finished without CertificateVerify (RFC 8446 §4.4.2).
            // Finished hash: Hash(CR || Certificate)
            let finished_key = ks.derive_finished_key(&$self.client_app_secret)?;
            let mut fin_hash = [0u8; 64];
            hasher2
                .finish(&mut fin_hash[..params.hash_len])
                .map_err(TlsError::CryptoError)?;

            let verify_data =
                ks.compute_finished_verify_data(&finished_key, &fin_hash[..params.hash_len])?;
            let fin_msg = encode_finished(&verify_data);

            let fin_record = $self
                .record_layer
                .seal_record(ContentType::Handshake, &fin_msg)?;
            maybe_await!($mode, $self.stream.write_all(&fin_record))
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        Ok(())
    }};
}

/// Body for TLS 1.3 client `do_handshake`.
macro_rules! tls13_client_do_handshake_body {
    ($mode:ident, $self:ident) => {{
        // Auto-lookup: if no explicit resumption_session, check cache
        if $self.config.resumption_session.is_none() {
            if let (Some(ref cache_mutex), Some(ref server_name)) =
                (&$self.config.session_cache, &$self.config.server_name)
            {
                if let Ok(cache) = cache_mutex.lock() {
                    if let Some(cached) = cache.get(server_name.as_bytes()) {
                        $self.config.resumption_session = Some(cached.clone());
                    }
                }
            }
        }

        let mut hs = ClientHandshake::new($self.config.clone());

        // Build and send ClientHello
        let ch_msg = hs.build_client_hello()?;
        let ch_record = $self
            .record_layer
            .seal_record(ContentType::Handshake, &ch_msg)?;
        maybe_await!($mode, $self.stream.write_all(&ch_record))
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 0-RTT early data
        let offered_early_data = hs.offered_early_data();
        if offered_early_data && !$self.early_data_queue.is_empty() {
            let params = CipherSuiteParams::from_suite(
                $self
                    .config
                    .resumption_session
                    .as_ref()
                    .map(|s| s.cipher_suite)
                    .unwrap_or(CipherSuite::TLS_AES_128_GCM_SHA256),
            )?;
            let early_keys = TrafficKeys::derive(&params, hs.early_traffic_secret())?;
            $self
                .record_layer
                .activate_write_encryption(params.suite, &early_keys)?;
            let early_data = std::mem::take(&mut $self.early_data_queue);
            let early_record = $self
                .record_layer
                .seal_record(ContentType::ApplicationData, &early_data)?;
            maybe_await!($mode, $self.stream.write_all(&early_record))
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // Read ServerHello (may be HRR)
        let sh_actions = maybe_await!($mode, $self.read_and_process_server_hello(&mut hs))?;

        // RFC 8446 §D.4: client sends fake CCS after ServerHello, before encryption
        send_fake_ccs_body!($mode, $self);

        // Activate handshake read decryption
        $self
            .record_layer
            .activate_read_decryption(sh_actions.suite, &sh_actions.server_hs_keys)?;

        let hs_write_suite = sh_actions.suite;
        let hs_write_keys = sh_actions.client_hs_keys;
        if !offered_early_data {
            $self
                .record_layer
                .activate_write_encryption(hs_write_suite, &hs_write_keys)?;
        }

        // Read encrypted handshake flight
        maybe_await!(
            $mode,
            $self.process_encrypted_flight(
                &mut hs,
                offered_early_data,
                hs_write_suite,
                &hs_write_keys,
            )
        )?;

        $self.client_hs = Some(hs);
        Ok(())
    }};
}

/// Body for TLS 1.3 client `read_and_process_server_hello`.
macro_rules! tls13_client_read_and_process_server_hello_body {
    ($mode:ident, $self:ident, $hs:expr) => {{
        let (ct, sh_data) = maybe_await!($mode, $self.read_record())?;
        if ct != ContentType::Handshake {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Handshake, got {ct:?}"
            )));
        }

        let (hs_type, _, sh_total) = parse_handshake_header(&sh_data)?;
        if hs_type != HandshakeType::ServerHello {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ServerHello, got {hs_type:?}"
            )));
        }
        // RFC 8446 §5.1: handshake messages MUST NOT span a key change.
        // ServerHello marks the transition from initial to handshake read
        // keys; any trailing bytes in this record would belong to a
        // different key epoch.
        if sh_data.len() != sh_total {
            return Err(TlsError::RecordError(
                "TLS 1.3 read key change not on record boundary".into(),
            ));
        }
        let sh_msg = &sh_data[..sh_total];

        match $hs.process_server_hello(sh_msg)? {
            ServerHelloResult::Actions(actions) => Ok(actions),
            ServerHelloResult::RetryNeeded(retry) => {
                // RFC 8446 §D.4: send fake CCS after HRR, before second CH
                send_fake_ccs_body!($mode, $self);

                let ch2_msg = $hs.build_client_hello_retry(&retry)?;
                let ch2_record = $self
                    .record_layer
                    .seal_record(ContentType::Handshake, &ch2_msg)?;
                maybe_await!($mode, $self.stream.write_all(&ch2_record))
                    .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

                let (ct2, sh2_data) = maybe_await!($mode, $self.read_record())?;
                if ct2 != ContentType::Handshake {
                    return Err(TlsError::HandshakeFailed(format!(
                        "expected Handshake after HRR, got {ct2:?}"
                    )));
                }
                let (hs_type2, _, sh2_total) = parse_handshake_header(&sh2_data)?;
                if hs_type2 != HandshakeType::ServerHello {
                    return Err(TlsError::HandshakeFailed(format!(
                        "expected ServerHello after HRR, got {hs_type2:?}"
                    )));
                }
                // RFC 8446 §5.1: ServerHello after HRR must not span a key change.
                if sh2_data.len() != sh2_total {
                    return Err(TlsError::RecordError(
                        "TLS 1.3 read key change not on record boundary".into(),
                    ));
                }
                let sh2_msg = &sh2_data[..sh2_total];

                match $hs.process_server_hello(sh2_msg)? {
                    ServerHelloResult::Actions(actions) => Ok(actions),
                    ServerHelloResult::RetryNeeded(_) => Err(TlsError::HandshakeFailed(
                        "received second HelloRetryRequest".into(),
                    )),
                }
            }
        }
    }};
}

/// Body for TLS 1.3 client `process_encrypted_flight`.
macro_rules! tls13_client_process_encrypted_flight_body {
    ($mode:ident, $self:ident, $hs:expr, $offered_early_data:expr,
     $hs_write_suite:expr, $hs_write_keys:expr) => {{
        let mut hs_buffer: Vec<u8> = Vec::new();

        loop {
            while hs_buffer.len() >= 4 {
                let msg_len = ((hs_buffer[1] as usize) << 16)
                    | ((hs_buffer[2] as usize) << 8)
                    | (hs_buffer[3] as usize);
                let total = 4 + msg_len;
                if hs_buffer.len() < total {
                    break;
                }

                let msg_data = hs_buffer[..total].to_vec();
                hs_buffer.drain(..total);

                match $hs.state() {
                    HandshakeState::WaitEncryptedExtensions => {
                        $hs.process_encrypted_extensions(&msg_data)?;
                        if let Some(limit) = $hs.peer_record_size_limit() {
                            $self.record_layer.max_fragment_size = limit as usize;
                        }
                    }
                    HandshakeState::WaitCertCertReq => {
                        // RFC 8446 §4.3.2: server may insert CertificateRequest
                        // before its own Certificate to ask for client auth.
                        // We stay in WaitCertCertReq after consuming it.
                        if !msg_data.is_empty()
                            && msg_data[0] == HandshakeType::CertificateRequest as u8
                        {
                            $hs.process_in_handshake_certificate_request(&msg_data)?;
                        } else {
                            #[cfg(feature = "cert-compression")]
                            if !msg_data.is_empty()
                                && msg_data[0] == HandshakeType::CompressedCertificate as u8
                            {
                                $hs.process_compressed_certificate(&msg_data)?;
                            } else {
                                $hs.process_certificate(&msg_data)?;
                            }
                            #[cfg(not(feature = "cert-compression"))]
                            $hs.process_certificate(&msg_data)?;
                        }
                    }
                    HandshakeState::WaitCertVerify => {
                        $hs.process_certificate_verify(&msg_data)?;
                    }
                    HandshakeState::WaitFinished => {
                        let fin_actions = $hs.process_finished(&msg_data)?;

                        if let Some(ref eoed_msg) = fin_actions.end_of_early_data_msg {
                            let eoed_record = $self
                                .record_layer
                                .seal_record(ContentType::Handshake, eoed_msg)?;
                            maybe_await!($mode, $self.stream.write_all(&eoed_record))
                                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
                            $self.early_data_accepted = true;
                        }

                        if $offered_early_data {
                            $self
                                .record_layer
                                .activate_write_encryption($hs_write_suite, $hs_write_keys)?;
                        }

                        // RFC 8446 §4.3.2 — emit client Certificate (and
                        // CertificateVerify, when we hold the matching key)
                        // before the client Finished. The transcript was
                        // already advanced inside `process_finished` so the
                        // Finished MAC commits to both messages.
                        if let Some(ref cert_msg) = fin_actions.client_certificate_msg {
                            let cert_record = $self
                                .record_layer
                                .seal_record(ContentType::Handshake, cert_msg)?;
                            maybe_await!($mode, $self.stream.write_all(&cert_record))
                                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
                        }
                        if let Some(ref cv_msg) = fin_actions.client_certificate_verify_msg {
                            let cv_record = $self
                                .record_layer
                                .seal_record(ContentType::Handshake, cv_msg)?;
                            maybe_await!($mode, $self.stream.write_all(&cv_record))
                                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
                        }

                        let fin_record = $self.record_layer.seal_record(
                            ContentType::Handshake,
                            &fin_actions.client_finished_msg,
                        )?;
                        maybe_await!($mode, $self.stream.write_all(&fin_record))
                            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

                        // RFC 8446 §5.1: handshake messages MUST NOT span a
                        // key change. Reject any unconsumed handshake bytes
                        // before switching to application read keys.
                        if !hs_buffer.is_empty() {
                            return Err(TlsError::RecordError(
                                "TLS 1.3 read key change not on record boundary".into(),
                            ));
                        }

                        $self.record_layer.activate_read_decryption(
                            fin_actions.suite,
                            &fin_actions.server_app_keys,
                        )?;
                        $self.record_layer.activate_write_encryption(
                            fin_actions.suite,
                            &fin_actions.client_app_keys,
                        )?;
                        // Wire record padding callback (TLS 1.3)
                        if let Some(ref cb) = $self.config.record_padding_callback {
                            $self.record_layer.set_record_padding_callback(cb.clone());
                        }

                        $self.cipher_params = Some(fin_actions.cipher_params);
                        $self.client_app_secret = fin_actions.client_app_secret;
                        $self.server_app_secret = fin_actions.server_app_secret;
                        $self.resumption_master_secret = fin_actions.resumption_master_secret;
                        $self.exporter_master_secret = fin_actions.exporter_master_secret;
                        $self.early_exporter_master_secret =
                            fin_actions.early_exporter_master_secret;

                        $self.negotiated_suite = Some(fin_actions.suite);
                        $self.negotiated_version = Some(TlsVersion::Tls13);
                        $self.peer_certificates = $hs.server_certs().to_vec();
                        $self.negotiated_alpn = $hs.negotiated_alpn().map(|a| a.to_vec());
                        $self.server_name_used = $self.config.server_name.clone();
                        $self.negotiated_group = $hs.negotiated_group();
                        $self.session_resumed = $hs.is_psk_mode();
                        $self.state = ConnectionState::Connected;
                        return Ok(());
                    }
                    _ => {
                        return Err(TlsError::HandshakeFailed(format!(
                            "unexpected state: {:?}",
                            $hs.state()
                        )));
                    }
                }
            }

            let (ct, plaintext) = maybe_await!($mode, $self.read_record())?;
            match ct {
                ContentType::Handshake => {
                    hs_buffer.extend_from_slice(&plaintext);
                }
                ContentType::Alert => {
                    return Err(TlsError::HandshakeFailed(
                        "received alert during handshake".into(),
                    ));
                }
                _ => {
                    return Err(TlsError::HandshakeFailed(format!(
                        "unexpected content type during handshake: {ct:?}"
                    )));
                }
            }
        }
    }};
}

/// Body for TLS 1.3 client `handshake` trait method.
macro_rules! tls13_client_handshake_trait_body {
    ($mode:ident, $self:ident) => {{
        if $self.state != ConnectionState::Handshaking {
            return Err(TlsError::HandshakeFailed(
                "handshake already completed or failed".into(),
            ));
        }
        match maybe_await!($mode, $self.do_handshake()) {
            Ok(()) => Ok(()),
            Err(e) => {
                // Phase T89 — RFC 8446 §6: send a fatal alert before
                // closing so the peer learns *why* (not just that the
                // socket dropped). Best-effort: if the seal/write fails
                // the original error still propagates.
                send_fatal_alert_for_error_body!($mode, $self, &e);
                $self.state = ConnectionState::Error;
                Err(e)
            }
        }
    }};
}

/// Body for TLS 1.3 client `read` trait method.
macro_rules! tls13_client_read_trait_body {
    ($mode:ident, $self:ident, $buf:ident) => {{
        if $self.state != ConnectionState::Connected {
            return Err(TlsError::RecordError(
                "not connected (handshake not done)".into(),
            ));
        }

        if !$self.app_data_buf.is_empty() {
            let n = std::cmp::min($buf.len(), $self.app_data_buf.len());
            $buf[..n].copy_from_slice(&$self.app_data_buf[..n]);
            $self.app_data_buf.drain(..n);
            return Ok(n);
        }

        loop {
            let (ct, plaintext) =
                try_alert!($mode, $self, maybe_await!($mode, $self.read_record()));
            match ct {
                ContentType::ApplicationData => {
                    $self.key_update_recv_count = 0;
                    let n = std::cmp::min($buf.len(), plaintext.len());
                    $buf[..n].copy_from_slice(&plaintext[..n]);
                    if plaintext.len() > n {
                        $self.app_data_buf.extend_from_slice(&plaintext[n..]);
                    }
                    return Ok(n);
                }
                ContentType::Handshake => {
                    let (hs_type, body, total) =
                        try_alert!($mode, $self, parse_handshake_header(&plaintext));
                    match hs_type {
                        HandshakeType::KeyUpdate => {
                            // Own body to avoid borrow issues across await
                            let body_owned = body.to_vec();
                            try_alert!(
                                $mode,
                                $self,
                                maybe_await!($mode, $self.handle_key_update(&body_owned))
                            );
                            continue;
                        }
                        HandshakeType::NewSessionTicket => {
                            if let Some(ref hs) = $self.client_hs {
                                if let Ok(session) = hs.process_new_session_ticket(
                                    &plaintext[..total],
                                    &$self.resumption_master_secret,
                                ) {
                                    // Auto-store in session cache
                                    if let (Some(ref cache_mutex), Some(ref server_name)) =
                                        (&$self.config.session_cache, &$self.config.server_name)
                                    {
                                        if let Ok(mut cache) = cache_mutex.lock() {
                                            cache.put(server_name.as_bytes(), session.clone());
                                        }
                                    }
                                    $self.received_session = Some(session);
                                }
                            }
                            continue;
                        }
                        HandshakeType::CertificateRequest => {
                            let body_owned = body.to_vec();
                            let full_msg_owned = plaintext[..total].to_vec();
                            try_alert!(
                                $mode,
                                $self,
                                maybe_await!(
                                    $mode,
                                    $self.handle_post_hs_cert_request(&body_owned, &full_msg_owned)
                                )
                            );
                            continue;
                        }
                        _ => {
                            return_alert_err!(
                                $mode,
                                $self,
                                TlsError::HandshakeFailed(format!(
                                    "unexpected post-handshake message: {hs_type:?}"
                                ))
                            );
                        }
                    }
                }
                ContentType::Alert => {
                    if plaintext.len() >= 2 && plaintext[1] == 0 {
                        $self.received_close_notify = true;
                    }
                    $self.state = ConnectionState::Closed;
                    return Ok(0);
                }
                _ => {
                    return_alert_err!(
                        $mode,
                        $self,
                        TlsError::RecordError(format!("unexpected content type: {ct:?}"))
                    );
                }
            }
        }
    }};
}

/// Body for TLS 1.3 client `shutdown` trait method.
macro_rules! tls13_client_shutdown_trait_body {
    ($mode:ident, $self:ident) => {{
        if $self.state == ConnectionState::Closed {
            return Ok(());
        }

        if !$self.config.quiet_shutdown && !$self.sent_close_notify {
            let alert_data = [1u8, 0u8];
            let record = $self
                .record_layer
                .seal_record(ContentType::Alert, &alert_data)?;
            let _ = maybe_await!($mode, $self.stream.write_all(&record));
            $self.sent_close_notify = true;
        }
        $self.state = ConnectionState::Closed;
        Ok(())
    }};
}

/// Non-I/O accessor methods for TLS 1.3 client.
macro_rules! impl_tls13_client_accessors {
    ($Name:ident, $ConnectionState:ident, $($bounds:tt)+) => {
        impl<S: $($bounds)+> $Name<S> {
            /// Take the received session (from NewSessionTicket) for future resumption.
            pub fn take_session(&mut self) -> Option<TlsSession> {
                self.received_session.take()
            }

            /// Queue early data to be sent during the 0-RTT phase of the handshake.
            pub fn queue_early_data(&mut self, data: &[u8]) {
                self.early_data_queue.extend_from_slice(data);
            }

            /// Whether the server accepted 0-RTT early data in this connection.
            pub fn early_data_accepted(&self) -> bool {
                self.early_data_accepted
            }

            /// Export keying material per RFC 8446 §7.5 / RFC 5705.
            pub fn export_keying_material(
                &self,
                label: &[u8],
                context: Option<&[u8]>,
                length: usize,
            ) -> Result<Vec<u8>, TlsError> {
                if self.state != $ConnectionState::Connected {
                    return Err(TlsError::HandshakeFailed(
                        "export_keying_material: not connected".into(),
                    ));
                }
                let params = self
                    .cipher_params
                    .as_ref()
                    .ok_or_else(|| TlsError::HandshakeFailed("no cipher params".into()))?;
                crate::crypt::export::tls13_export_keying_material(
                    params.hash_alg_id(),
                    &self.exporter_master_secret,
                    label,
                    context,
                    length,
                )
            }

            /// Export early keying material per RFC 8446 §7.5 (0-RTT context).
            pub fn export_early_keying_material(
                &self,
                label: &[u8],
                context: Option<&[u8]>,
                length: usize,
            ) -> Result<Vec<u8>, TlsError> {
                if self.early_exporter_master_secret.is_empty() {
                    return Err(TlsError::HandshakeFailed(
                        "export_early_keying_material: no early exporter master secret \
                         (no PSK offered)"
                            .into(),
                    ));
                }
                let params = self
                    .cipher_params
                    .as_ref()
                    .ok_or_else(|| TlsError::HandshakeFailed("no cipher params".into()))?;
                crate::crypt::export::tls13_export_early_keying_material(
                    params.hash_alg_id(),
                    &self.early_exporter_master_secret,
                    label,
                    context,
                    length,
                )
            }

            /// Return a snapshot of the negotiated connection parameters.
            pub fn connection_info(&self) -> Option<ConnectionInfo> {
                self.negotiated_suite.map(|suite| ConnectionInfo {
                    cipher_suite: suite,
                    peer_certificates: self.peer_certificates.clone(),
                    alpn_protocol: self.negotiated_alpn.clone(),
                    server_name: self.server_name_used.clone(),
                    negotiated_group: self.negotiated_group,
                    session_resumed: self.session_resumed,
                    peer_verify_data: Vec::new(),
                    local_verify_data: Vec::new(),
                })
            }

            /// Peer certificates (DER-encoded, leaf first).
            pub fn peer_certificates(&self) -> &[Vec<u8>] {
                &self.peer_certificates
            }

            /// Negotiated ALPN protocol (if any).
            pub fn alpn_protocol(&self) -> Option<&[u8]> {
                self.negotiated_alpn.as_deref()
            }

            /// Server name (SNI) used in this connection.
            pub fn server_name(&self) -> Option<&str> {
                self.server_name_used.as_deref()
            }

            /// Negotiated key exchange group (if applicable).
            pub fn negotiated_group(&self) -> Option<NamedGroup> {
                self.negotiated_group
            }

            /// Whether this connection was resumed from a previous session.
            pub fn is_session_resumed(&self) -> bool {
                self.session_resumed
            }
        }
    };
}

// =========================================================================
// TLS 1.3 server body macros
// =========================================================================

/// Body for TLS 1.3 server `key_update`.
macro_rules! tls13_server_key_update_body {
    ($mode:ident, $self:ident, $request_response:expr) => {{
        if $self.state != ConnectionState::Connected {
            return Err(TlsError::HandshakeFailed(
                "key_update: not connected".into(),
            ));
        }
        let params = $self
            .cipher_params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher params".into()))?
            .clone();
        let ku = KeyUpdateMsg {
            request_update: if $request_response {
                KeyUpdateRequest::UpdateRequested
            } else {
                KeyUpdateRequest::UpdateNotRequested
            },
        };
        let ku_msg = encode_key_update(&ku);
        let record = $self
            .record_layer
            .seal_record(ContentType::Handshake, &ku_msg)?;
        maybe_await!($mode, $self.stream.write_all(&record))
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        // Update write key (server_app_secret for server)
        let ks = KeySchedule::new(params.clone());
        let new_secret = ks.update_traffic_secret(&$self.server_app_secret)?;
        let new_keys = TrafficKeys::derive(&params, &new_secret)?;
        $self
            .record_layer
            .activate_write_encryption(params.suite, &new_keys)?;
        $self.server_app_secret.zeroize();
        $self.server_app_secret = new_secret;
        Ok(())
    }};
}

/// Body for TLS 1.3 server `handle_key_update`.
macro_rules! tls13_server_handle_key_update_body {
    ($mode:ident, $self:ident, $body:expr) => {{
        $self.key_update_recv_count += 1;
        if $self.key_update_recv_count > 128 {
            return Err(TlsError::HandshakeFailed(
                "too many consecutive KeyUpdate messages without application data".into(),
            ));
        }
        let ku = decode_key_update($body)?;
        let params = $self
            .cipher_params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher params".into()))?
            .clone();
        // Update read key (client_app_secret for server)
        let ks = KeySchedule::new(params.clone());
        let new_secret = ks.update_traffic_secret(&$self.client_app_secret)?;
        let new_keys = TrafficKeys::derive(&params, &new_secret)?;
        $self
            .record_layer
            .activate_read_decryption(params.suite, &new_keys)?;
        $self.client_app_secret.zeroize();
        $self.client_app_secret = new_secret;
        if ku.request_update == KeyUpdateRequest::UpdateRequested {
            maybe_await!($mode, $self.key_update(false))?;
        }
        Ok(())
    }};
}

/// Body for TLS 1.3 server `do_handshake`.
macro_rules! tls13_server_do_handshake_body {
    ($mode:ident, $self:ident) => {{
        let mut hs = ServerHandshake::new($self.config.clone());

        // Phase T104 — Step 1: read ClientHello via buffer-and-drain
        // (RFC 8446 §5.1: a single handshake message MAY span multiple
        // records; non-Handshake records MUST NOT be interleaved with
        // it). Pre-T104 we read one record and bailed if the CH didn't
        // fit; tlsfuzzer's `test-tls13-zero-length-data.py` fragments
        // the CH into 2 records and slips an empty AppData record in
        // between to probe the interleave check.
        let mut ch_buf: Vec<u8> = Vec::new();
        let ch_msg_bytes: Vec<u8> = loop {
            if ch_buf.len() >= 4 {
                let body_len = ((ch_buf[1] as usize) << 16)
                    | ((ch_buf[2] as usize) << 8)
                    | (ch_buf[3] as usize);
                let total = 4 + body_len;
                if ch_buf.len() >= total {
                    break ch_buf.drain(..total).collect();
                }
            }
            let (ct, plaintext) = maybe_await!($mode, $self.read_record())?;
            if ct != ContentType::Handshake {
                // RFC 8446 §5.1 — interleave violation. Alert:
                // unexpected_message (when CH read is mid-message)
                // or whatever the alert mapper picks for the
                // got-content-type wording when buffer is empty.
                return Err(TlsError::HandshakeFailed(format!(
                    "expected Handshake for ClientHello, got {ct:?} \
                     (alert: unexpected_message)"
                )));
            }
            ch_buf.extend_from_slice(&plaintext);
        };
        let (hs_type, _, _) = parse_handshake_header(&ch_msg_bytes)?;
        if hs_type != HandshakeType::ClientHello {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ClientHello, got {hs_type:?}"
            )));
        }
        // RFC 8446 §5.1 — handshake messages must end on a record
        // boundary at key-change points; CH is the first message of
        // the handshake, so any trailing bytes after the CH would
        // belong to a subsequent message — possible but the existing
        // server flight is fixed-shape so we don't expect this here.
        if !ch_buf.is_empty() {
            return Err(TlsError::HandshakeFailed(
                "trailing bytes after ClientHello (RFC 8446 §5.1 — \
                 alert: unexpected_message)"
                    .into(),
            ));
        }
        let ch_msg = ch_msg_bytes.as_slice();

        // Step 2: Process ClientHello (may result in HRR)
        let actions = match hs.process_client_hello(ch_msg)? {
            ClientHelloResult::Actions(actions) => *actions,
            ClientHelloResult::HelloRetryRequest(hrr_actions) => {
                let hrr_record = $self
                    .record_layer
                    .seal_record(ContentType::Handshake, &hrr_actions.hrr_msg)?;
                maybe_await!($mode, $self.stream.write_all(&hrr_record))
                    .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

                // RFC 8446 §D.4: server sends fake CCS after HRR
                send_fake_ccs_body!($mode, $self);

                // Phase T104 — Step 1b: same buffer-and-drain for
                // the retried ClientHello (CH2) after HRR.
                let mut ch2_buf: Vec<u8> = Vec::new();
                let ch2_msg_bytes: Vec<u8> = loop {
                    if ch2_buf.len() >= 4 {
                        let body_len = ((ch2_buf[1] as usize) << 16)
                            | ((ch2_buf[2] as usize) << 8)
                            | (ch2_buf[3] as usize);
                        let total = 4 + body_len;
                        if ch2_buf.len() >= total {
                            break ch2_buf.drain(..total).collect();
                        }
                    }
                    let (ct2, plaintext) = maybe_await!($mode, $self.read_record())?;
                    if ct2 != ContentType::Handshake {
                        return Err(TlsError::HandshakeFailed(format!(
                            "expected Handshake after HRR, got {ct2:?} \
                             (alert: unexpected_message)"
                        )));
                    }
                    ch2_buf.extend_from_slice(&plaintext);
                };
                let (hs_type2, _, _) = parse_handshake_header(&ch2_msg_bytes)?;
                if hs_type2 != HandshakeType::ClientHello {
                    return Err(TlsError::HandshakeFailed(format!(
                        "expected ClientHello after HRR, got {hs_type2:?}"
                    )));
                }
                if !ch2_buf.is_empty() {
                    return Err(TlsError::HandshakeFailed(
                        "trailing bytes after retried ClientHello \
                         (RFC 8446 §5.1 — alert: unexpected_message)"
                            .into(),
                    ));
                }
                let ch2_msg = ch2_msg_bytes.as_slice();
                hs.process_client_hello_retry(ch2_msg)?
            }
        };

        // Apply client's record size limit
        if let Some(limit) = hs.client_record_size_limit() {
            $self.record_layer.max_fragment_size = limit.saturating_sub(1) as usize;
        }

        // Step 3: Send ServerHello as plaintext record
        let sh_record = $self
            .record_layer
            .seal_record(ContentType::Handshake, &actions.server_hello_msg)?;
        maybe_await!($mode, $self.stream.write_all(&sh_record))
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // RFC 8446 §D.4: server sends fake CCS after ServerHello, before encryption
        send_fake_ccs_body!($mode, $self);

        // Step 4: Activate handshake write encryption
        $self
            .record_layer
            .activate_write_encryption(actions.suite, &actions.server_hs_keys)?;

        // Step 4b: If 0-RTT accepted, activate early read decryption first
        if actions.early_data_accepted {
            if let Some(ref early_keys) = actions.early_read_keys {
                $self
                    .record_layer
                    .activate_read_decryption(actions.suite, early_keys)?;
            }
        } else {
            $self
                .record_layer
                .activate_read_decryption(actions.suite, &actions.client_hs_keys)?;
        }

        // Step 5: Send EE, [Certificate, CertificateVerify], Finished
        let ee_record = $self
            .record_layer
            .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)?;
        maybe_await!($mode, $self.stream.write_all(&ee_record))
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        if !actions.psk_mode {
            // Phase T97 — emit CertificateRequest before our Certificate
            // when in-handshake mTLS is configured. `certificate_request_msg`
            // is empty when mTLS is off (see `process_client_hello`).
            if !actions.certificate_request_msg.is_empty() {
                let cr_record = $self
                    .record_layer
                    .seal_record(ContentType::Handshake, &actions.certificate_request_msg)?;
                maybe_await!($mode, $self.stream.write_all(&cr_record))
                    .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
            }
            for msg in &[&actions.certificate_msg, &actions.certificate_verify_msg] {
                let record = $self
                    .record_layer
                    .seal_record(ContentType::Handshake, msg)?;
                maybe_await!($mode, $self.stream.write_all(&record))
                    .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
            }
        }

        let sfin_record = $self
            .record_layer
            .seal_record(ContentType::Handshake, &actions.server_finished_msg)?;
        maybe_await!($mode, $self.stream.write_all(&sfin_record))
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // RFC 8446 §A.1 / §4.6.1: after sending its Finished, the server's
        // *write* keys switch to `server_application_traffic_secret_0`.
        // This must happen before any subsequent server write (including
        // alerts sent in response to a malformed client message arriving
        // before client Finished), or the peer will fail to decrypt them.
        $self
            .record_layer
            .activate_write_encryption(actions.suite, &actions.server_app_keys)?;

        // Step 5b: If 0-RTT accepted, read early data + EndOfEarlyData
        if actions.early_data_accepted {
            loop {
                let (ct, data) = maybe_await!($mode, $self.read_record())?;
                match ct {
                    ContentType::ApplicationData => {
                        $self.app_data_buf.extend_from_slice(&data);
                    }
                    ContentType::Handshake => {
                        let (hs_type, _, total) = parse_handshake_header(&data)?;
                        if hs_type == HandshakeType::EndOfEarlyData {
                            hs.process_end_of_early_data(&data[..total])?;
                            break;
                        } else {
                            return Err(TlsError::HandshakeFailed(format!(
                                "expected EndOfEarlyData, got {hs_type:?}"
                            )));
                        }
                    }
                    _ => {
                        return Err(TlsError::HandshakeFailed(format!(
                            "unexpected content type during 0-RTT: {ct:?}"
                        )));
                    }
                }
            }
            $self
                .record_layer
                .activate_read_decryption(actions.suite, &actions.client_hs_keys)?;
        }

        // Phase T101 — accumulate plaintext from `Handshake` content-type
        // records into a single buffer, then carve out one complete
        // handshake message at a time. RFC 8446 §5.1 explicitly allows
        // (a) packing multiple handshake messages into one record and
        // (b) fragmenting a single handshake message across multiple
        // records — both must work even though our server-side flight
        // is fixed-shape (Cert / CV / Finished). The drain loop is
        // inlined per-step rather than pulled into a helper macro
        // because closures can't compose with `maybe_await!` in our
        // sync+async-shared macro body.
        let mut hs_buffer: Vec<u8> = Vec::new();

        // Phase T97 — Step 5c: when mTLS is in-handshake, read the
        // client's Certificate and CertificateVerify before Finished.
        // The transcript includes them; client Finished's MAC is over
        // the resulting transcript hash.
        if hs.expecting_client_cert {
            // Drain or refill until a complete client Certificate is
            // available (≥4 bytes header → header.body_len bytes body).
            let c_msg = loop {
                if hs_buffer.len() >= 4 {
                    let body_len = ((hs_buffer[1] as usize) << 16)
                        | ((hs_buffer[2] as usize) << 8)
                        | (hs_buffer[3] as usize);
                    let total = 4 + body_len;
                    if hs_buffer.len() >= total {
                        break hs_buffer.drain(..total).collect::<Vec<u8>>();
                    }
                }
                let (ct, plaintext) = maybe_await!($mode, $self.read_record())?;
                if ct != ContentType::Handshake {
                    // RFC 8446 §5.1 — non-Handshake record interleaved
                    // with a fragmented handshake message. Alert:
                    // unexpected_message.
                    return Err(TlsError::HandshakeFailed(format!(
                        "expected Handshake for client Certificate, got {ct:?} \
                         (alert: unexpected_message)"
                    )));
                }
                hs_buffer.extend_from_slice(&plaintext);
            };
            let (hs_type, _, _) = parse_handshake_header(&c_msg)?;
            if hs_type != HandshakeType::Certificate {
                return Err(TlsError::HandshakeFailed(format!(
                    "expected client Certificate, got {hs_type:?}"
                )));
            }
            hs.process_client_certificate(&c_msg)?;

            // CertificateVerify is required when the client sent at
            // least one certificate; if the client sent an empty
            // Certificate (no chain), it skips CV and we proceed
            // straight to Finished.
            if hs.client_sent_certificates() {
                let cv_msg = loop {
                    if hs_buffer.len() >= 4 {
                        let body_len = ((hs_buffer[1] as usize) << 16)
                            | ((hs_buffer[2] as usize) << 8)
                            | (hs_buffer[3] as usize);
                        let total = 4 + body_len;
                        if hs_buffer.len() >= total {
                            break hs_buffer.drain(..total).collect::<Vec<u8>>();
                        }
                    }
                    let (ct, plaintext) = maybe_await!($mode, $self.read_record())?;
                    if ct != ContentType::Handshake {
                        return Err(TlsError::HandshakeFailed(format!(
                            "expected Handshake for client CertificateVerify, \
                             got {ct:?} (alert: unexpected_message)"
                        )));
                    }
                    hs_buffer.extend_from_slice(&plaintext);
                };
                let (hs_type, _, _) = parse_handshake_header(&cv_msg)?;
                if hs_type != HandshakeType::CertificateVerify {
                    return Err(TlsError::HandshakeFailed(format!(
                        "expected client CertificateVerify, got {hs_type:?}"
                    )));
                }
                hs.process_client_certificate_verify(&cv_msg)?;
            } else if $self.config.require_client_cert {
                // Client sent an empty Certificate but server REQUIRES
                // a cert → reject (RFC 8446 §4.4.2).
                return Err(TlsError::HandshakeFailed(
                    "client sent empty Certificate but server requires \
                     client cert (alert: certificate_required)"
                        .into(),
                ));
            }
        }

        // Step 6: Read client Finished — same buffer, may already
        // contain the bytes if the client packed Finished into the
        // Cert+CV record (RFC 8446 §5.1 allows this; tlsfuzzer's
        // padded-Finished tests rely on the fragmentation direction).
        let fin_msg = loop {
            if hs_buffer.len() >= 4 {
                let body_len = ((hs_buffer[1] as usize) << 16)
                    | ((hs_buffer[2] as usize) << 8)
                    | (hs_buffer[3] as usize);
                let total = 4 + body_len;
                if hs_buffer.len() >= total {
                    break hs_buffer.drain(..total).collect::<Vec<u8>>();
                }
            }
            let (ct, plaintext) = maybe_await!($mode, $self.read_record())?;
            if ct != ContentType::Handshake {
                return Err(TlsError::HandshakeFailed(format!(
                    "expected Handshake for client Finished, got {ct:?} \
                     (alert: unexpected_message)"
                )));
            }
            hs_buffer.extend_from_slice(&plaintext);
        };
        let (hs_type, _, _) = parse_handshake_header(&fin_msg)?;
        if hs_type != HandshakeType::Finished {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Finished, got {hs_type:?}"
            )));
        }
        // RFC 8446 §5.1: handshake messages MUST NOT span a key change.
        // After consuming Finished the buffer must be empty; any
        // leftover bytes would belong to the next (application) read
        // key epoch.
        if !hs_buffer.is_empty() {
            return Err(TlsError::RecordError(
                "TLS 1.3 read key change not on record boundary".into(),
            ));
        }
        let fin_msg = fin_msg.as_slice();

        // Step 7: Verify client Finished
        let fin_actions = hs.process_client_finished(fin_msg)?;

        // Step 8: Activate application read key.
        // (Write was already switched to server_app_keys right after sending
        // Finished, per RFC 8446 §A.1 — see Step 5 above.)
        $self
            .record_layer
            .activate_read_decryption(actions.suite, &actions.client_app_keys)?;
        // Wire record padding callback (TLS 1.3)
        if let Some(ref cb) = $self.config.record_padding_callback {
            $self.record_layer.set_record_padding_callback(cb.clone());
        }

        // Step 9: Send NewSessionTicket(s)
        for nst_msg in &fin_actions.new_session_ticket_msgs {
            let nst_record = $self
                .record_layer
                .seal_record(ContentType::Handshake, nst_msg)?;
            maybe_await!($mode, $self.stream.write_all(&nst_record))
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // Save secrets for key updates and export
        $self.cipher_params = Some(actions.cipher_params);
        $self.client_app_secret = actions.client_app_secret;
        $self.server_app_secret = actions.server_app_secret;
        $self.exporter_master_secret = actions.exporter_master_secret;
        $self.early_exporter_master_secret = actions.early_exporter_master_secret;

        $self.negotiated_suite = Some(actions.suite);
        $self.negotiated_version = Some(TlsVersion::Tls13);

        // Populate connection info from handshake state
        $self.peer_certificates = hs.client_certs().to_vec();
        $self.negotiated_alpn = hs.negotiated_alpn().map(|a| a.to_vec());
        $self.client_server_name = hs.client_server_name().map(|s| s.to_string());
        $self.negotiated_group = hs.negotiated_group();

        $self.state = ConnectionState::Connected;
        Ok(())
    }};
}

/// Body for TLS 1.3 server `handshake` trait method.
macro_rules! tls13_server_handshake_trait_body {
    ($mode:ident, $self:ident) => {{
        if $self.state != ConnectionState::Handshaking {
            return Err(TlsError::HandshakeFailed(
                "handshake already completed or failed".into(),
            ));
        }
        match maybe_await!($mode, $self.do_handshake()) {
            Ok(()) => Ok(()),
            Err(e) => {
                // Phase T89 — see `tls13_client_handshake_trait_body!`
                // for the rationale.
                send_fatal_alert_for_error_body!($mode, $self, &e);
                $self.state = ConnectionState::Error;
                Err(e)
            }
        }
    }};
}

/// Body for TLS 1.3 server `read` trait method.
macro_rules! tls13_server_read_trait_body {
    ($mode:ident, $self:ident, $buf:ident) => {{
        if $self.state != ConnectionState::Connected {
            return Err(TlsError::RecordError(
                "not connected (handshake not done)".into(),
            ));
        }

        if !$self.app_data_buf.is_empty() {
            let n = std::cmp::min($buf.len(), $self.app_data_buf.len());
            $buf[..n].copy_from_slice(&$self.app_data_buf[..n]);
            $self.app_data_buf.drain(..n);
            return Ok(n);
        }

        loop {
            // Phase T101 — drain any complete handshake messages that
            // are already buffered. This handles two RFC 8446 §5.1
            // cases that pre-T101 silently dropped post-handshake data:
            //   * multiple handshake messages packed into a single
            //     record's plaintext (e.g. two back-to-back KeyUpdates),
            //   * a single handshake message split across multiple
            //     records (e.g. fragmented KeyUpdate).
            while $self.post_hs_buffer.len() >= 4 {
                let body_len = ((($self.post_hs_buffer[1] as usize) << 16)
                    | (($self.post_hs_buffer[2] as usize) << 8)
                    | ($self.post_hs_buffer[3] as usize));
                let total = 4 + body_len;
                if $self.post_hs_buffer.len() < total {
                    break; // wait for more bytes
                }
                let msg_bytes: Vec<u8> = $self.post_hs_buffer.drain(..total).collect();
                let (hs_type, body, _) =
                    try_alert!($mode, $self, parse_handshake_header(&msg_bytes));
                match hs_type {
                    HandshakeType::KeyUpdate => {
                        let body_owned = body.to_vec();
                        try_alert!(
                            $mode,
                            $self,
                            maybe_await!($mode, $self.handle_key_update(&body_owned))
                        );
                    }
                    _ => {
                        return_alert_err!(
                            $mode,
                            $self,
                            TlsError::HandshakeFailed(format!(
                                "unexpected post-handshake message: {hs_type:?}"
                            ))
                        );
                    }
                }
            }

            let (ct, plaintext) =
                try_alert!($mode, $self, maybe_await!($mode, $self.read_record()));
            match ct {
                ContentType::ApplicationData => {
                    // RFC 8446 §5.1 — handshake messages MUST NOT be
                    // interleaved with other record types. If we are
                    // still mid-message in the post-handshake buffer
                    // when AppData arrives, that's a protocol violation.
                    if !$self.post_hs_buffer.is_empty() {
                        return_alert_err!(
                            $mode,
                            $self,
                            TlsError::HandshakeFailed(
                                "unexpected_message: AppData interleaved with \
                                 fragmented post-handshake handshake message \
                                 (RFC 8446 §5.1)"
                                    .into(),
                            )
                        );
                    }
                    $self.key_update_recv_count = 0;
                    // Phase T103 — RFC 8446 §5.1 explicitly permits
                    // zero-length AppData fragments ("MAY be sent ...
                    // potentially useful as a traffic analysis
                    // countermeasure"). Surface them as "no data, keep
                    // reading" rather than as `read() == 0` (which the
                    // caller would interpret as EOF and close).
                    if plaintext.is_empty() {
                        continue;
                    }
                    let n = std::cmp::min($buf.len(), plaintext.len());
                    $buf[..n].copy_from_slice(&plaintext[..n]);
                    if plaintext.len() > n {
                        $self.app_data_buf.extend_from_slice(&plaintext[n..]);
                    }
                    return Ok(n);
                }
                ContentType::Handshake => {
                    $self.post_hs_buffer.extend_from_slice(&plaintext);
                    // Loop back to drain the buffer.
                }
                ContentType::Alert => {
                    if !$self.post_hs_buffer.is_empty() {
                        return_alert_err!(
                            $mode,
                            $self,
                            TlsError::HandshakeFailed(
                                "unexpected_message: Alert interleaved with \
                                 fragmented post-handshake handshake message \
                                 (RFC 8446 §5.1)"
                                    .into(),
                            )
                        );
                    }
                    if plaintext.len() >= 2 && plaintext[1] == 0 {
                        $self.received_close_notify = true;
                    }
                    $self.state = ConnectionState::Closed;
                    return Ok(0);
                }
                _ => {
                    return_alert_err!(
                        $mode,
                        $self,
                        TlsError::RecordError(format!("unexpected content type: {ct:?}"))
                    );
                }
            }
        }
    }};
}

/// Non-I/O accessor methods for TLS 1.3 server.
macro_rules! impl_tls13_server_accessors {
    ($Name:ident, $ConnectionState:ident, $sn_field:ident, $($bounds:tt)+) => {
        impl<S: $($bounds)+> $Name<S> {
            /// Export keying material per RFC 8446 §7.5 / RFC 5705.
            pub fn export_keying_material(
                &self,
                label: &[u8],
                context: Option<&[u8]>,
                length: usize,
            ) -> Result<Vec<u8>, TlsError> {
                if self.state != $ConnectionState::Connected {
                    return Err(TlsError::HandshakeFailed(
                        "export_keying_material: not connected".into(),
                    ));
                }
                let params = self
                    .cipher_params
                    .as_ref()
                    .ok_or_else(|| TlsError::HandshakeFailed("no cipher params".into()))?;
                crate::crypt::export::tls13_export_keying_material(
                    params.hash_alg_id(),
                    &self.exporter_master_secret,
                    label,
                    context,
                    length,
                )
            }

            /// Export early keying material per RFC 8446 §7.5 (0-RTT context).
            pub fn export_early_keying_material(
                &self,
                label: &[u8],
                context: Option<&[u8]>,
                length: usize,
            ) -> Result<Vec<u8>, TlsError> {
                if self.early_exporter_master_secret.is_empty() {
                    return Err(TlsError::HandshakeFailed(
                        "export_early_keying_material: no early exporter master secret \
                         (no PSK offered)"
                            .into(),
                    ));
                }
                let params = self
                    .cipher_params
                    .as_ref()
                    .ok_or_else(|| TlsError::HandshakeFailed("no cipher params".into()))?;
                crate::crypt::export::tls13_export_early_keying_material(
                    params.hash_alg_id(),
                    &self.early_exporter_master_secret,
                    label,
                    context,
                    length,
                )
            }

            /// Return a snapshot of the negotiated connection parameters.
            pub fn connection_info(&self) -> Option<ConnectionInfo> {
                self.negotiated_suite.map(|suite| ConnectionInfo {
                    cipher_suite: suite,
                    peer_certificates: self.peer_certificates.clone(),
                    alpn_protocol: self.negotiated_alpn.clone(),
                    server_name: self.$sn_field.clone(),
                    negotiated_group: self.negotiated_group,
                    session_resumed: self.session_resumed,
                    peer_verify_data: Vec::new(),
                    local_verify_data: Vec::new(),
                })
            }

            /// Peer certificates (DER-encoded, leaf first).
            pub fn peer_certificates(&self) -> &[Vec<u8>] {
                &self.peer_certificates
            }

            /// Negotiated ALPN protocol (if any).
            pub fn alpn_protocol(&self) -> Option<&[u8]> {
                self.negotiated_alpn.as_deref()
            }

            /// Client server name (SNI) received from the client.
            pub fn server_name(&self) -> Option<&str> {
                self.$sn_field.as_deref()
            }

            /// Negotiated key exchange group (if applicable).
            pub fn negotiated_group(&self) -> Option<NamedGroup> {
                self.negotiated_group
            }

            /// Whether this connection was resumed from a previous session.
            pub fn is_session_resumed(&self) -> bool {
                self.session_resumed
            }
        }
    };
}

// =========================================================================
// TLS 1.2 shared body macros
// =========================================================================

/// Body for TLS 1.2 `read_handshake_msg`.
macro_rules! tls12_read_handshake_msg_body {
    ($mode:ident, $self:ident) => {{
        let (ct, data) = maybe_await!($mode, $self.read_record())?;
        if ct != ContentType::Handshake {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Handshake, got {ct:?}"
            )));
        }
        let (hs_type, _, total) = parse_handshake_header(&data)?;
        Ok((hs_type, data[..total].to_vec()))
    }};
}

/// Body for TLS 1.2 `handshake` trait method.
macro_rules! tls12_handshake_trait_body {
    ($mode:ident, $self:ident) => {{
        if $self.state != ConnectionState::Handshaking {
            return Err(TlsError::HandshakeFailed(
                "handshake already completed or failed".into(),
            ));
        }
        match maybe_await!($mode, $self.do_handshake()) {
            Ok(()) => Ok(()),
            Err(e) => {
                // Phase T90 — same alert-before-close discipline as T89's
                // TLS 1.3 path. Best-effort: peer sees a wire-level fatal
                // alert (mapped from `e`) before the close.
                send_fatal_alert_for_error_body!($mode, $self, &e);
                $self.state = ConnectionState::Error;
                Err(e)
            }
        }
    }};
}

/// Non-I/O accessor methods for TLS 1.2 client.
macro_rules! impl_tls12_client_accessors {
    ($Name:ident, $ConnectionState:ident, $($bounds:tt)+) => {
        impl<S: $($bounds)+> $Name<S> {
            /// Take the session state (with ticket if applicable) for later resumption.
            pub fn take_session(&mut self) -> Option<TlsSession> {
                self.session.take()
            }

            /// Get a snapshot of the negotiated connection parameters.
            pub fn connection_info(&self) -> Option<ConnectionInfo> {
                self.negotiated_suite.map(|suite| ConnectionInfo {
                    cipher_suite: suite,
                    peer_certificates: self.peer_certificates.clone(),
                    alpn_protocol: self.negotiated_alpn.clone(),
                    server_name: self.server_name_used.clone(),
                    negotiated_group: self.negotiated_group,
                    session_resumed: self.session_resumed,
                    peer_verify_data: self.server_verify_data.clone(),
                    local_verify_data: self.client_verify_data.clone(),
                })
            }

            /// Get the peer's certificate chain (DER-encoded, leaf first).
            pub fn peer_certificates(&self) -> &[Vec<u8>] {
                &self.peer_certificates
            }

            /// Get the negotiated ALPN protocol (if any).
            pub fn alpn_protocol(&self) -> Option<&[u8]> {
                self.negotiated_alpn.as_deref()
            }

            /// Get the server name (SNI) used for this connection.
            pub fn server_name(&self) -> Option<&str> {
                self.server_name_used.as_deref()
            }

            /// Get the negotiated key exchange group (if applicable).
            pub fn negotiated_group(&self) -> Option<NamedGroup> {
                self.negotiated_group
            }

            /// Whether this connection was resumed from a previous session.
            pub fn is_session_resumed(&self) -> bool {
                self.session_resumed
            }

            /// Get the peer's Finished verify_data.
            pub fn peer_verify_data(&self) -> &[u8] {
                &self.server_verify_data
            }

            /// Get the local Finished verify_data.
            pub fn local_verify_data(&self) -> &[u8] {
                &self.client_verify_data
            }
        }
    };
}

/// Non-I/O accessor methods for TLS 1.2 server.
macro_rules! impl_tls12_server_accessors {
    ($Name:ident, $ConnectionState:ident, $($bounds:tt)+) => {
        impl<S: $($bounds)+> $Name<S> {
            /// Take the session state (for session caching on server side).
            pub fn take_session(&mut self) -> Option<TlsSession> {
                self.session.take()
            }

            /// Get a snapshot of the negotiated connection parameters.
            pub fn connection_info(&self) -> Option<ConnectionInfo> {
                self.negotiated_suite.map(|suite| ConnectionInfo {
                    cipher_suite: suite,
                    peer_certificates: self.peer_certificates.clone(),
                    alpn_protocol: self.negotiated_alpn.clone(),
                    server_name: self.client_server_name.clone(),
                    negotiated_group: self.negotiated_group,
                    session_resumed: self.session_resumed,
                    peer_verify_data: self.client_verify_data.clone(),
                    local_verify_data: self.server_verify_data.clone(),
                })
            }

            /// Get the peer's certificate chain (DER-encoded, leaf first).
            pub fn peer_certificates(&self) -> &[Vec<u8>] {
                &self.peer_certificates
            }

            /// Get the negotiated ALPN protocol (if any).
            pub fn alpn_protocol(&self) -> Option<&[u8]> {
                self.negotiated_alpn.as_deref()
            }

            /// Get the client's SNI hostname.
            pub fn server_name(&self) -> Option<&str> {
                self.client_server_name.as_deref()
            }

            /// Get the negotiated key exchange group (if applicable).
            pub fn negotiated_group(&self) -> Option<NamedGroup> {
                self.negotiated_group
            }

            /// Whether this connection was resumed from a previous session.
            pub fn is_session_resumed(&self) -> bool {
                self.session_resumed
            }

            /// Get the peer's Finished verify_data.
            pub fn peer_verify_data(&self) -> &[u8] {
                &self.client_verify_data
            }

            /// Get the local Finished verify_data.
            pub fn local_verify_data(&self) -> &[u8] {
                &self.server_verify_data
            }
        }
    };
}
