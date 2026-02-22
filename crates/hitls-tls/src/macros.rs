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
macro_rules! read_record_body {
    ($mode:ident, $self:ident) => {{
        maybe_await!($mode, $self.fill_buf(5))?;
        let length = u16::from_be_bytes([$self.read_buf[3], $self.read_buf[4]]) as usize;
        maybe_await!($mode, $self.fill_buf(5 + length))?;
        let (ct, plaintext, consumed) = $self.record_layer.open_record(&$self.read_buf)?;
        $self.read_buf.drain(..consumed);
        Ok((ct, plaintext))
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
        let mut cr_hash = vec![0u8; params.hash_len];
        hasher.finish(&mut cr_hash).map_err(TlsError::CryptoError)?;

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

            let mut cv_hash = vec![0u8; params.hash_len];
            let mut hasher3 = DigestVariant::new(alg);
            hasher3.update($full_msg).map_err(TlsError::CryptoError)?;
            hasher3
                .update(&cert_encoded)
                .map_err(TlsError::CryptoError)?;
            hasher3
                .finish(&mut cv_hash)
                .map_err(TlsError::CryptoError)?;

            let signature = sign_certificate_verify(client_key, scheme, &cv_hash, false)?;
            let cv_msg = encode_certificate_verify(&CertificateVerifyMsg {
                algorithm: scheme,
                signature,
            });

            let cv_record = $self
                .record_layer
                .seal_record(ContentType::Handshake, &cv_msg)?;
            maybe_await!($mode, $self.stream.write_all(&cv_record))
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

            let finished_key = ks.derive_finished_key(&$self.client_app_secret)?;
            let mut fin_hash = vec![0u8; params.hash_len];
            let mut hasher4 = DigestVariant::new(alg);
            hasher4.update($full_msg).map_err(TlsError::CryptoError)?;
            hasher4
                .update(&cert_encoded)
                .map_err(TlsError::CryptoError)?;
            hasher4.update(&cv_msg).map_err(TlsError::CryptoError)?;
            hasher4
                .finish(&mut fin_hash)
                .map_err(TlsError::CryptoError)?;

            let verify_data = ks.compute_finished_verify_data(&finished_key, &fin_hash)?;
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
        let sh_msg = &sh_data[..sh_total];

        match $hs.process_server_hello(sh_msg)? {
            ServerHelloResult::Actions(actions) => Ok(actions),
            ServerHelloResult::RetryNeeded(retry) => {
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

                        let fin_record = $self.record_layer.seal_record(
                            ContentType::Handshake,
                            &fin_actions.client_finished_msg,
                        )?;
                        maybe_await!($mode, $self.stream.write_all(&fin_record))
                            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

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
            let (ct, plaintext) = maybe_await!($mode, $self.read_record())?;
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
                    let (hs_type, body, total) = parse_handshake_header(&plaintext)?;
                    match hs_type {
                        HandshakeType::KeyUpdate => {
                            // Own body to avoid borrow issues across await
                            let body_owned = body.to_vec();
                            maybe_await!($mode, $self.handle_key_update(&body_owned))?;
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
                            maybe_await!(
                                $mode,
                                $self.handle_post_hs_cert_request(&body_owned, &full_msg_owned)
                            )?;
                            continue;
                        }
                        _ => {
                            return Err(TlsError::HandshakeFailed(format!(
                                "unexpected post-handshake message: {hs_type:?}"
                            )));
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
                    return Err(TlsError::RecordError(format!(
                        "unexpected content type: {ct:?}"
                    )));
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

        // Step 1: Read ClientHello
        let (ct, ch_data) = maybe_await!($mode, $self.read_record())?;
        if ct != ContentType::Handshake {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Handshake, got {ct:?}"
            )));
        }

        let (hs_type, _, ch_total) = parse_handshake_header(&ch_data)?;
        if hs_type != HandshakeType::ClientHello {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ClientHello, got {hs_type:?}"
            )));
        }
        let ch_msg = &ch_data[..ch_total];

        // Step 2: Process ClientHello (may result in HRR)
        let actions = match hs.process_client_hello(ch_msg)? {
            ClientHelloResult::Actions(actions) => *actions,
            ClientHelloResult::HelloRetryRequest(hrr_actions) => {
                let hrr_record = $self
                    .record_layer
                    .seal_record(ContentType::Handshake, &hrr_actions.hrr_msg)?;
                maybe_await!($mode, $self.stream.write_all(&hrr_record))
                    .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

                let (ct2, ch2_data) = maybe_await!($mode, $self.read_record())?;
                if ct2 != ContentType::Handshake {
                    return Err(TlsError::HandshakeFailed(format!(
                        "expected Handshake after HRR, got {ct2:?}"
                    )));
                }
                let (hs_type2, _, ch2_total) = parse_handshake_header(&ch2_data)?;
                if hs_type2 != HandshakeType::ClientHello {
                    return Err(TlsError::HandshakeFailed(format!(
                        "expected ClientHello after HRR, got {hs_type2:?}"
                    )));
                }
                let ch2_msg = &ch2_data[..ch2_total];
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

        // Step 6: Read client Finished
        let (ct, fin_data) = maybe_await!($mode, $self.read_record())?;
        if ct != ContentType::Handshake {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Handshake for client Finished, got {ct:?}"
            )));
        }

        let (hs_type, _, fin_total) = parse_handshake_header(&fin_data)?;
        if hs_type != HandshakeType::Finished {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Finished, got {hs_type:?}"
            )));
        }
        let fin_msg = &fin_data[..fin_total];

        // Step 7: Verify client Finished
        let fin_actions = hs.process_client_finished(fin_msg)?;

        // Step 8: Activate application keys
        $self
            .record_layer
            .activate_read_decryption(actions.suite, &actions.client_app_keys)?;
        $self
            .record_layer
            .activate_write_encryption(actions.suite, &actions.server_app_keys)?;
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
            let (ct, plaintext) = maybe_await!($mode, $self.read_record())?;
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
                    let (hs_type, body, _) = parse_handshake_header(&plaintext)?;
                    match hs_type {
                        HandshakeType::KeyUpdate => {
                            let body_owned = body.to_vec();
                            maybe_await!($mode, $self.handle_key_update(&body_owned))?;
                            continue;
                        }
                        _ => {
                            return Err(TlsError::HandshakeFailed(format!(
                                "unexpected post-handshake message: {hs_type:?}"
                            )));
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
                    return Err(TlsError::RecordError(format!(
                        "unexpected content type: {ct:?}"
                    )));
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
