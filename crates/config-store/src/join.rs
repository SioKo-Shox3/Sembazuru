//! Versioned envelope for one join transaction handed from the GUI to the elevated helper.
//!
//! The three logical fields correspond one-to-one with [`MachineTokenUpdate`], because
//! `prepare_machine_cluster_token_update` accepts the three targets as a single transaction. Sending
//! them as one envelope keeps that shape: one authorization, one bound, one zeroized buffer. Split
//! messages would add parse, retry, and ordering failure states that the transaction does not have.
//!
//! This layer is pure: it does not open the pipe, choose its security descriptor, or identify the
//! peer. Those belong to the transport and are not weakened or replaced by anything decided here.

use std::fmt;

use zeroize::Zeroizing;

use crate::{
    MAX_MACHINE_CLUSTER_TOKEN_BYTES, MAX_MACHINE_CONFIG_BYTES, MachineTokenUpdate,
    MachineTokenUpdateValue,
};

/// Fixed leading tag of a join envelope ("SBJN").
pub const JOIN_PAYLOAD_MAGIC: u32 = 0x5342_4a4e;

/// The only envelope layout this build produces or accepts.
pub const JOIN_PAYLOAD_VERSION: u32 = 1;

/// Bytes before the framed fields: magic, version, and the payload length.
const HEADER_BYTES: usize = 12;

/// Framing cost of one field: its kind, plus the length that a replacement carries.
const FIELD_FRAME_BYTES: usize = 1 + 4;

/// Largest envelope accepted from the transport, framing included.
pub const MAX_JOIN_PAYLOAD_BYTES: usize = HEADER_BYTES
    + 3 * FIELD_FRAME_BYTES
    + MAX_MACHINE_CLUSTER_TOKEN_BYTES
    + 2 * MAX_MACHINE_CONFIG_BYTES;

/// Why an envelope was refused. The cause is never the secret itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JoinPayloadError {
    /// The leading tag was not a join envelope.
    Magic,
    /// The envelope announced a layout this build does not accept.
    Version,
    /// The declared length disagreed with the bytes received, or exceeded the bound.
    Length,
    /// A field carried a kind or a length outside the fixed contract.
    Field,
    /// The cluster token was empty, oversized, not UTF-8, or not a single line.
    Token,
    /// A configuration body was empty or oversized.
    Config,
}

impl JoinPayloadError {
    /// Returns the stable reason, safe to log, for one refused envelope.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Magic => "join-envelope-magic",
            Self::Version => "join-envelope-version",
            Self::Length => "join-envelope-length",
            Self::Field => "join-envelope-field",
            Self::Token => "join-envelope-token",
            Self::Config => "join-envelope-config",
        }
    }
}

impl fmt::Display for JoinPayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for JoinPayloadError {}

/// What the join asks for one target, mirroring [`MachineTokenUpdateValue`].
pub enum JoinField {
    /// Assert and retain the target's current safe state, including absence.
    Preserve,
    /// Publish these bytes for the target. The buffer is zeroized on drop.
    Replace(Zeroizing<Vec<u8>>),
    /// Remove the target when present.
    Remove,
}

impl JoinField {
    /// Builds a replacement that owns a zeroized copy of `bytes`.
    pub fn replace(bytes: &[u8]) -> Self {
        Self::Replace(Zeroizing::new(bytes.to_vec()))
    }

    const fn kind(&self) -> u8 {
        match self {
            Self::Preserve => 0,
            Self::Replace(_) => 1,
            Self::Remove => 2,
        }
    }

    fn value(&self) -> MachineTokenUpdateValue<'_> {
        match self {
            Self::Preserve => MachineTokenUpdateValue::Preserve,
            Self::Replace(bytes) => MachineTokenUpdateValue::Replace(bytes.as_slice()),
            Self::Remove => MachineTokenUpdateValue::Remove,
        }
    }

    fn encoded_len(&self) -> usize {
        match self {
            Self::Replace(bytes) => FIELD_FRAME_BYTES + bytes.len(),
            _ => 1,
        }
    }
}

impl fmt::Debug for JoinField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preserve => f.write_str("Preserve"),
            Self::Replace(_) => f.write_str("Replace([REDACTED])"),
            Self::Remove => f.write_str("Remove"),
        }
    }
}

/// One complete join transaction: the three fixed targets and nothing else.
pub struct JoinPayload {
    cluster_token: JoinField,
    daemon_config: JoinField,
    worker_config: JoinField,
}

impl fmt::Debug for JoinPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinPayload")
            .field("cluster_token", &self.cluster_token)
            .field("daemon_config", &self.daemon_config)
            .field("worker_config", &self.worker_config)
            .finish()
    }
}

impl JoinPayload {
    /// Builds a transaction after proving every field against the fixed contract.
    pub fn new(
        cluster_token: JoinField,
        daemon_config: JoinField,
        worker_config: JoinField,
    ) -> Result<Self, JoinPayloadError> {
        let payload = Self {
            cluster_token,
            daemon_config,
            worker_config,
        };
        payload.validate()?;
        Ok(payload)
    }

    /// The transaction in the shape `prepare_machine_cluster_token_update` accepts.
    pub fn update(&self) -> MachineTokenUpdate<'_> {
        MachineTokenUpdate {
            cluster_token: self.cluster_token.value(),
            daemon_config: self.daemon_config.value(),
            worker_config: self.worker_config.value(),
        }
    }

    /// Serializes the transaction into one zeroized buffer.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, JoinPayloadError> {
        self.validate()?;
        let payload_len = self.cluster_token.encoded_len()
            + self.daemon_config.encoded_len()
            + self.worker_config.encoded_len();
        let mut bytes = Zeroizing::new(Vec::with_capacity(HEADER_BYTES + payload_len));
        bytes.extend_from_slice(&JOIN_PAYLOAD_MAGIC.to_le_bytes());
        bytes.extend_from_slice(&JOIN_PAYLOAD_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(payload_len as u32).to_le_bytes());
        for field in [
            &self.cluster_token,
            &self.daemon_config,
            &self.worker_config,
        ] {
            bytes.push(field.kind());
            if let JoinField::Replace(value) = field {
                bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
                bytes.extend_from_slice(value);
            }
        }
        if bytes.len() > MAX_JOIN_PAYLOAD_BYTES {
            return Err(JoinPayloadError::Length);
        }
        Ok(bytes)
    }

    /// Parses one complete envelope. Trailing bytes are a refusal, not a truncation point.
    pub fn decode(bytes: &[u8]) -> Result<Self, JoinPayloadError> {
        if bytes.len() > MAX_JOIN_PAYLOAD_BYTES {
            return Err(JoinPayloadError::Length);
        }
        if bytes.len() < HEADER_BYTES {
            return Err(JoinPayloadError::Length);
        }
        let word = |offset: usize| -> u32 {
            u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("four bytes"))
        };
        if word(0) != JOIN_PAYLOAD_MAGIC {
            return Err(JoinPayloadError::Magic);
        }
        if word(4) != JOIN_PAYLOAD_VERSION {
            return Err(JoinPayloadError::Version);
        }
        if word(8) as usize != bytes.len() - HEADER_BYTES {
            return Err(JoinPayloadError::Length);
        }
        let mut cursor = HEADER_BYTES;
        let mut fields = Vec::with_capacity(3);
        for _ in 0..3 {
            let kind = *bytes.get(cursor).ok_or(JoinPayloadError::Field)?;
            cursor += 1;
            fields.push(match kind {
                0 => JoinField::Preserve,
                2 => JoinField::Remove,
                1 => {
                    if cursor + 4 > bytes.len() {
                        return Err(JoinPayloadError::Field);
                    }
                    let length = u32::from_le_bytes(
                        bytes[cursor..cursor + 4].try_into().expect("four bytes"),
                    ) as usize;
                    cursor += 4;
                    let end = cursor.checked_add(length).ok_or(JoinPayloadError::Field)?;
                    if end > bytes.len() {
                        return Err(JoinPayloadError::Field);
                    }
                    let value = JoinField::replace(&bytes[cursor..end]);
                    cursor = end;
                    value
                }
                _ => return Err(JoinPayloadError::Field),
            });
        }
        if cursor != bytes.len() {
            return Err(JoinPayloadError::Length);
        }
        let mut fields = fields.into_iter();
        let payload = Self {
            cluster_token: fields.next().expect("three fields"),
            daemon_config: fields.next().expect("three fields"),
            worker_config: fields.next().expect("three fields"),
        };
        payload.validate()?;
        Ok(payload)
    }

    fn validate(&self) -> Result<(), JoinPayloadError> {
        if let JoinField::Replace(token) = &self.cluster_token {
            // The stored token keeps its single-line contract, the same one `rotate-token` enforces
            // on its own input; the envelope must not become a way around it.
            if token.is_empty()
                || token.len() > MAX_MACHINE_CLUSTER_TOKEN_BYTES
                || std::str::from_utf8(token).is_err()
                || token.iter().any(|byte| matches!(byte, b'\r' | b'\n' | 0))
            {
                return Err(JoinPayloadError::Token);
            }
        }
        for config in [&self.daemon_config, &self.worker_config] {
            if let JoinField::Replace(body) = config
                && (body.is_empty() || body.len() > MAX_MACHINE_CONFIG_BYTES)
            {
                return Err(JoinPayloadError::Config);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> JoinField {
        JoinField::replace(b"cluster-token")
    }

    fn config() -> JoinField {
        JoinField::replace(b"[worker]\nthreads = 4\n")
    }

    fn payload() -> JoinPayload {
        JoinPayload::new(token(), config(), config()).expect("fixture payload")
    }

    fn assert_same_shape(left: &JoinPayload, right: &JoinPayload) {
        for (left, right) in [
            (&left.cluster_token, &right.cluster_token),
            (&left.daemon_config, &right.daemon_config),
            (&left.worker_config, &right.worker_config),
        ] {
            match (left, right) {
                (JoinField::Preserve, JoinField::Preserve) => {}
                (JoinField::Remove, JoinField::Remove) => {}
                (JoinField::Replace(left), JoinField::Replace(right)) => {
                    assert_eq!(left.as_slice(), right.as_slice());
                }
                _ => panic!("field kind changed across the envelope"),
            }
        }
    }

    #[test]
    fn every_field_kind_survives_one_round_trip() {
        let kinds = || {
            [
                JoinField::Preserve,
                JoinField::Remove,
                JoinField::replace(b"body"),
            ]
        };
        for daemon in kinds() {
            for worker in kinds() {
                for secret in [JoinField::Preserve, JoinField::Remove, token()] {
                    let original = JoinPayload::new(
                        secret,
                        match daemon {
                            JoinField::Preserve => JoinField::Preserve,
                            JoinField::Remove => JoinField::Remove,
                            JoinField::Replace(ref bytes) => JoinField::replace(bytes),
                        },
                        match worker {
                            JoinField::Preserve => JoinField::Preserve,
                            JoinField::Remove => JoinField::Remove,
                            JoinField::Replace(ref bytes) => JoinField::replace(bytes),
                        },
                    )
                    .expect("valid combination");
                    let bytes = original.encode().expect("encode");
                    let decoded = JoinPayload::decode(&bytes).expect("decode");
                    assert_same_shape(&original, &decoded);
                }
            }
        }
    }

    #[test]
    fn the_envelope_maps_one_to_one_onto_the_transaction() {
        let payload = JoinPayload::new(token(), JoinField::Preserve, JoinField::Remove)
            .expect("valid payload");
        let update = payload.update();
        assert!(matches!(
            update.cluster_token,
            MachineTokenUpdateValue::Replace(b"cluster-token")
        ));
        assert!(matches!(
            update.daemon_config,
            MachineTokenUpdateValue::Preserve
        ));
        assert!(matches!(
            update.worker_config,
            MachineTokenUpdateValue::Remove
        ));
    }

    #[test]
    fn a_tampered_envelope_is_refused_rather_than_repaired() {
        let bytes = payload().encode().expect("encode");
        let patch = |offset: usize, value: u8| {
            let mut changed = bytes.to_vec();
            changed[offset] = value;
            changed
        };
        assert_eq!(
            JoinPayload::decode(&patch(0, 0)).unwrap_err(),
            JoinPayloadError::Magic
        );
        assert_eq!(
            JoinPayload::decode(&patch(4, 2)).unwrap_err(),
            JoinPayloadError::Version
        );
        assert_eq!(
            JoinPayload::decode(&patch(8, 0)).unwrap_err(),
            JoinPayloadError::Length
        );
        // The first field's kind byte sits immediately after the header.
        assert_eq!(
            JoinPayload::decode(&patch(HEADER_BYTES, 3)).unwrap_err(),
            JoinPayloadError::Field
        );

        let mut truncated = bytes.to_vec();
        truncated.pop();
        assert_eq!(
            JoinPayload::decode(&truncated).unwrap_err(),
            JoinPayloadError::Length
        );

        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert_eq!(
            JoinPayload::decode(&trailing).unwrap_err(),
            JoinPayloadError::Length
        );

        assert_eq!(
            JoinPayload::decode(&bytes[..HEADER_BYTES - 1]).unwrap_err(),
            JoinPayloadError::Length
        );
    }

    #[test]
    fn a_field_length_cannot_reach_past_the_envelope() {
        // The declared payload length is left intact, so only the first field's own length is out
        // of range: the envelope has to be refused on the field, not rescued by the outer bound.
        let length_at = HEADER_BYTES + 1;
        for overshoot in [
            u32::MAX,
            (MAX_JOIN_PAYLOAD_BYTES as u32).saturating_add(1),
            payload().encode().expect("encode").len() as u32,
        ] {
            let mut bytes = payload().encode().expect("encode").to_vec();
            bytes[length_at..length_at + 4].copy_from_slice(&overshoot.to_le_bytes());
            assert_eq!(
                JoinPayload::decode(&bytes).unwrap_err(),
                JoinPayloadError::Field,
                "accepted a field length of {overshoot}"
            );
        }
    }

    /// Frames `fields` with a header whose declared length is correct, so a refusal can only come
    /// from parsing the fields themselves and not from the outer length check.
    fn envelope(fields: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_BYTES + fields.len());
        bytes.extend_from_slice(&JOIN_PAYLOAD_MAGIC.to_le_bytes());
        bytes.extend_from_slice(&JOIN_PAYLOAD_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(fields.len() as u32).to_le_bytes());
        bytes.extend_from_slice(fields);
        bytes
    }

    #[test]
    fn the_field_parser_refuses_on_its_own_terms() {
        // Every case below declares its true payload length, so the outer check passes and the
        // field parser is what has to reject it.
        for (name, fields, expected) in [
            ("two fields", vec![0u8, 0], JoinPayloadError::Field),
            ("four fields", vec![0u8, 0, 0, 0], JoinPayloadError::Length),
            (
                "a replacement that runs past the envelope",
                {
                    let mut fields = vec![1u8];
                    fields.extend_from_slice(&9u32.to_le_bytes());
                    fields.extend_from_slice(b"abc");
                    fields
                },
                JoinPayloadError::Field,
            ),
            (
                "an empty token replacement",
                {
                    let mut fields = vec![1u8];
                    fields.extend_from_slice(&0u32.to_le_bytes());
                    fields.extend_from_slice(&[0, 0]);
                    fields
                },
                JoinPayloadError::Token,
            ),
            (
                "a token that is not UTF-8",
                {
                    let mut fields = vec![1u8];
                    fields.extend_from_slice(&2u32.to_le_bytes());
                    fields.extend_from_slice(&[0xff, 0xfe, 0, 0]);
                    fields
                },
                JoinPayloadError::Token,
            ),
            (
                "an empty configuration replacement",
                {
                    let mut fields = vec![0u8, 1];
                    fields.extend_from_slice(&0u32.to_le_bytes());
                    fields.push(0);
                    fields
                },
                JoinPayloadError::Config,
            ),
        ] {
            assert_eq!(
                JoinPayload::decode(&envelope(&fields))
                    .map(|_| ())
                    .unwrap_err(),
                expected,
                "{name}"
            );
        }

        // The same framing, correctly filled, still decodes: the helper above is not simply broken.
        let mut valid = vec![1u8];
        valid.extend_from_slice(&5u32.to_le_bytes());
        valid.extend_from_slice(b"token");
        valid.extend_from_slice(&[0, 2]);
        assert!(JoinPayload::decode(&envelope(&valid)).is_ok());
    }

    #[test]
    fn the_token_keeps_its_single_line_contract() {
        for invalid in [
            b"".to_vec(),
            b"line\nbreak".to_vec(),
            b"carriage\rreturn".to_vec(),
            b"nul\0byte".to_vec(),
            vec![0xff, 0xfe],
            vec![b'x'; MAX_MACHINE_CLUSTER_TOKEN_BYTES + 1],
        ] {
            let built = JoinPayload::new(
                JoinField::replace(&invalid),
                JoinField::Preserve,
                JoinField::Preserve,
            );
            assert_eq!(
                built.map(|_| ()).unwrap_err(),
                JoinPayloadError::Token,
                "accepted an invalid token of {} bytes",
                invalid.len()
            );
        }
    }

    #[test]
    fn a_configuration_body_is_bounded_and_never_empty() {
        for invalid in [Vec::new(), vec![b'x'; MAX_MACHINE_CONFIG_BYTES + 1]] {
            for position in 0..2 {
                let (daemon, worker) = if position == 0 {
                    (JoinField::replace(&invalid), JoinField::Preserve)
                } else {
                    (JoinField::Preserve, JoinField::replace(&invalid))
                };
                assert_eq!(
                    JoinPayload::new(JoinField::Preserve, daemon, worker)
                        .map(|_| ())
                        .unwrap_err(),
                    JoinPayloadError::Config
                );
            }
        }
    }

    #[test]
    fn the_largest_accepted_envelope_stays_inside_its_bound() {
        let payload = JoinPayload::new(
            JoinField::replace(&vec![b'x'; MAX_MACHINE_CLUSTER_TOKEN_BYTES]),
            JoinField::replace(&vec![b'y'; MAX_MACHINE_CONFIG_BYTES]),
            JoinField::replace(&vec![b'z'; MAX_MACHINE_CONFIG_BYTES]),
        )
        .expect("maximum payload");
        let bytes = payload.encode().expect("encode");
        assert_eq!(bytes.len(), MAX_JOIN_PAYLOAD_BYTES);
        assert!(JoinPayload::decode(&bytes).is_ok());

        let mut oversized = bytes.to_vec();
        oversized.push(0);
        assert_eq!(
            JoinPayload::decode(&oversized).unwrap_err(),
            JoinPayloadError::Length
        );
    }

    #[test]
    fn the_secret_never_reaches_a_debug_line() {
        let rendered = format!("{:?}", payload());
        assert!(!rendered.contains("cluster-token"), "{rendered}");
        assert!(rendered.contains("Replace([REDACTED])"), "{rendered}");
        assert_eq!(
            format!("{:?}", JoinField::Preserve),
            "Preserve",
            "non-secret kinds stay readable"
        );
    }
}
