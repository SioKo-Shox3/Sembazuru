//! Turning validated wizard input into one join transaction and handing it to the helper.
//!
//! The wizard's three answers do not map onto three writes. They map onto one transaction: the
//! cluster token, the worker's configuration, and the daemon's, applied together or not at all.
//! This module is where that shape is taken, and it is the only place the GUI's join reaches the
//! machine store.

use sembazuru_config_store::{JoinField, JoinPayload, JoinPayloadError};

use super::transport::{self, TransportError};
use super::worker_toml::{WorkerJoin, render_worker_toml};

/// Hands one prepared transaction to the elevated helper.
///
/// A trait, because the real path needs an elevation prompt that only a person can answer. Tests
/// stand in for the helper; nothing else does.
pub trait JoinSubmitter: Send + Sync {
    fn submit(&self, payload: &JoinPayload) -> Result<(), TransportError>;
}

/// The real path: a one-shot pipe to an elevated `sembazuru-storectl join`.
pub struct PipeJoinSubmitter;

impl JoinSubmitter for PipeJoinSubmitter {
    fn submit(&self, payload: &JoinPayload) -> Result<(), TransportError> {
        transport::deliver(payload)
    }
}

/// Builds the transaction the wizard's answers describe.
///
/// The token is its own field and never enters the rendered configuration: the machine store keeps
/// it as a DPAPI secret, so a copy in `worker.toml` would be a second, weaker home for it. The
/// daemon's configuration is preserved, because this wizard does not ask about it — and preserving
/// is an assertion, not a silence: the transaction still proves the daemon's current state is safe.
pub fn payload_for(join: &WorkerJoin) -> Result<JoinPayload, JoinPayloadError> {
    JoinPayload::new(
        JoinField::replace(join.cluster_token.as_bytes()),
        JoinField::Preserve,
        JoinField::replace(render_worker_toml(join).as_bytes()),
    )
}

/// What the operator is told after one join attempt.
///
/// The helper reports a saved transaction and a running machine separately, and so does this. A
/// join whose services did not come back is not a success, and saying so is the difference between
/// "retry the join" and "go look at the services".
pub fn outcome_notice(result: Result<(), TransportError>) -> String {
    match result {
        Ok(()) => {
            "Joined. The daemon and worker were restarted on the new configuration.".to_owned()
        }
        // storectl's exit code for a transaction that was written while the services stayed down.
        Err(TransportError::Helper(12)) => {
            "Settings were saved, but the services did not come back on them. \
             Check the Services tab before retrying the join."
                .to_owned()
        }
        Err(error) => format!("Join failed: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::join::worker_toml::{JoinInput, validate};

    fn join() -> WorkerJoin {
        validate(JoinInput {
            agent: "http://192.168.1.10:50070".into(),
            cluster_token: "cluster-token-sentinel".into(),
            listen_addr: "0.0.0.0:50061".into(),
            advertise: String::new(),
            detected_lan_ip: Some("192.168.1.11".into()),
            participation_mode: "adaptive".into(),
            allow_insecure_lan: true,
        })
        .expect("valid wizard input")
    }

    #[test]
    fn the_token_travels_in_the_payload_and_not_in_the_configuration() {
        let join = join();
        let rendered = render_worker_toml(&join);
        assert!(
            !rendered.contains("cluster-token-sentinel"),
            "the token must not be written into worker.toml: {rendered}"
        );
        assert!(rendered.contains("advertise = \"http://192.168.1.11:50061\""));

        let payload = payload_for(&join).expect("the wizard's answers form one transaction");
        let encoded = payload.encode().expect("encode");
        let needle = b"cluster-token-sentinel";
        assert!(
            encoded.windows(needle.len()).any(|window| window == needle),
            "the token has to reach the helper through the payload"
        );
        assert!(!format!("{payload:?}").contains("cluster-token-sentinel"));
    }

    #[test]
    fn the_transaction_replaces_the_worker_and_preserves_the_daemon() {
        let payload = payload_for(&join()).expect("payload");
        let update = payload.update();
        assert!(matches!(
            update.cluster_token,
            sembazuru_config_store::MachineTokenUpdateValue::Replace(_)
        ));
        assert!(matches!(
            update.daemon_config,
            sembazuru_config_store::MachineTokenUpdateValue::Preserve
        ));
        assert!(matches!(
            update.worker_config,
            sembazuru_config_store::MachineTokenUpdateValue::Replace(_)
        ));
    }

    #[test]
    fn a_saved_but_unreflected_join_reads_differently_from_a_failure() {
        let saved = outcome_notice(Err(TransportError::Helper(12)));
        assert!(saved.contains("saved"), "{saved}");
        assert!(saved.contains("Services"), "{saved}");

        let declined = outcome_notice(Err(TransportError::Elevation(
            "elevation was declined".into(),
        )));
        assert!(declined.contains("declined"), "{declined}");
        assert!(!declined.contains("saved"), "{declined}");

        assert!(outcome_notice(Ok(())).starts_with("Joined."));
    }
}
