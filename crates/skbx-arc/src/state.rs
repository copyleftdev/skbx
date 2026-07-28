use serde::{Deserialize, Serialize};
use skbx_contract::{CaptureStart, Envelope};
use skbx_core::{ReplayError, replay};
use skbx_mission::{
    ArtifactManifest, Assignment, AssignmentStatus, MISSION_CONTRACT_VERSION, MissionError,
    MissionRecord, MissionRequest, MissionStatus, SensorRegistration, SensorTrace,
    artifact_manifest, correlate_adjacent, validate_identifier,
};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Cursor};
use std::sync::{Arc, RwLock};
use thiserror::Error;

const LEASE_DURATION_NS: u64 = 30_000_000_000;
const MAX_TIMELINE_EVENTS: usize = 500;

pub type SharedControlPlane = Arc<RwLock<ControlPlane>>;

pub fn shared(control_plane: ControlPlane) -> SharedControlPlane {
    Arc::new(RwLock::new(control_plane))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorView {
    #[serde(flatten)]
    pub registration: SensorRegistration,
    pub last_seen_unix_ns: u64,
    pub state: SensorState,
    pub active_mission: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorState {
    Ready,
    Capturing,
    EvidenceReceived,
    Degraded,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub sensor_id: String,
    pub handle: String,
    pub timestamp_unix_ns: u64,
    pub function: String,
    pub packet_len: u32,
    pub drop_reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleSnapshot {
    pub schema: String,
    pub generated_unix_ns: u64,
    pub sensors: Vec<SensorView>,
    pub missions: Vec<MissionRecord>,
    pub selected_mission: Option<String>,
    pub timeline: Vec<TimelineEvent>,
}

#[derive(Clone, Debug)]
struct StoredArtifact {
    manifest: ArtifactManifest,
    trace: SensorTrace,
}

#[derive(Clone, Debug, Default)]
pub struct ControlPlane {
    sensors: BTreeMap<String, SensorView>,
    missions: BTreeMap<String, MissionRecord>,
    artifacts: BTreeMap<(String, String), StoredArtifact>,
    leases: BTreeMap<(String, String), Assignment>,
    generation: u64,
    selected_mission: Option<String>,
}

impl ControlPlane {
    pub fn register_sensor(
        &mut self,
        registration: SensorRegistration,
        now_ns: u64,
    ) -> Result<SensorView, ArcError> {
        registration.validate()?;
        let previous = self.sensors.get(&registration.sensor_id);
        let view = SensorView {
            state: previous.map_or(SensorState::Ready, |sensor| sensor.state),
            active_mission: previous.and_then(|sensor| sensor.active_mission.clone()),
            registration,
            last_seen_unix_ns: now_ns,
        };
        self.sensors
            .insert(view.registration.sensor_id.clone(), view.clone());
        Ok(view)
    }

    pub fn create_mission(
        &mut self,
        request: MissionRequest,
        now_ns: u64,
    ) -> Result<MissionRecord, ArcError> {
        request.validate()?;
        if self.missions.contains_key(&request.mission_id) {
            return Err(ArcError::MissionExists(request.mission_id));
        }
        for target in &request.targets {
            if !self.sensors.contains_key(target) {
                return Err(ArcError::SensorNotFound(target.clone()));
            }
        }
        let mission = MissionRecord {
            schema: MISSION_CONTRACT_VERSION.into(),
            mission_id: request.mission_id.clone(),
            name: request.name,
            targets: request.targets,
            status: MissionStatus::Draft,
            plan_digest: request.plan.digest(),
            plan: request.plan,
            created_unix_ns: now_ns,
            assignments: BTreeMap::new(),
            artifacts: BTreeMap::new(),
            correlations: Vec::new(),
        };
        self.selected_mission = Some(mission.mission_id.clone());
        self.missions
            .insert(mission.mission_id.clone(), mission.clone());
        Ok(mission)
    }

    pub fn arm_mission(&mut self, mission_id: &str) -> Result<MissionRecord, ArcError> {
        validate_identifier("mission_id", mission_id)?;
        let mission = self
            .missions
            .get_mut(mission_id)
            .ok_or_else(|| ArcError::MissionNotFound(mission_id.into()))?;
        if mission.status != MissionStatus::Draft {
            return Err(ArcError::InvalidTransition {
                mission_id: mission_id.into(),
                from: mission.status,
                action: "arm",
            });
        }
        for target in &mission.targets {
            if !self.sensors.contains_key(target) {
                return Err(ArcError::SensorNotFound(target.clone()));
            }
            mission
                .assignments
                .insert(target.clone(), AssignmentStatus::Pending);
        }
        mission.status = MissionStatus::Armed;
        Ok(mission.clone())
    }

    pub fn next_assignment(
        &mut self,
        sensor_id: &str,
        now_ns: u64,
    ) -> Result<Option<Assignment>, ArcError> {
        validate_identifier("sensor_id", sensor_id)?;
        if !self.sensors.contains_key(sensor_id) {
            return Err(ArcError::SensorNotFound(sensor_id.into()));
        }

        let mission_id = self.missions.iter().find_map(|(mission_id, mission)| {
            matches!(
                mission.assignments.get(sensor_id),
                Some(AssignmentStatus::Pending | AssignmentStatus::Leased)
            )
            .then(|| mission_id.clone())
        });
        let Some(mission_id) = mission_id else {
            return Ok(None);
        };

        let lease_key = (mission_id.clone(), sensor_id.to_owned());
        if let Some(existing) = self.leases.get(&lease_key)
            && existing.lease_expires_unix_ns > now_ns
        {
            let sensor = self
                .sensors
                .get_mut(sensor_id)
                .expect("sensor existence was checked");
            sensor.last_seen_unix_ns = now_ns;
            return Ok(Some(existing.clone()));
        }

        self.generation = self.generation.saturating_add(1);
        let mission = self
            .missions
            .get_mut(&mission_id)
            .expect("mission selected from the same map");
        mission
            .assignments
            .insert(sensor_id.into(), AssignmentStatus::Leased);
        mission.status = MissionStatus::Capturing;
        let sensor = self
            .sensors
            .get_mut(sensor_id)
            .expect("sensor existence was checked");
        sensor.state = SensorState::Capturing;
        sensor.active_mission = Some(mission_id.clone());
        sensor.last_seen_unix_ns = now_ns;

        let assignment = Assignment {
            schema: MISSION_CONTRACT_VERSION.into(),
            mission_id: mission_id.clone(),
            sensor_id: sensor_id.into(),
            generation: self.generation,
            plan_digest: mission.plan_digest.clone(),
            plan: mission.plan.clone(),
            lease_expires_unix_ns: now_ns.saturating_add(LEASE_DURATION_NS),
            status: AssignmentStatus::Leased,
        };
        self.leases.insert(lease_key, assignment.clone());
        Ok(Some(assignment))
    }

    pub fn submit_artifact(
        &mut self,
        mission_id: &str,
        sensor_id: &str,
        bytes: &[u8],
        now_ns: u64,
    ) -> Result<ArtifactManifest, ArcError> {
        validate_identifier("mission_id", mission_id)?;
        validate_identifier("sensor_id", sensor_id)?;
        let mission = self
            .missions
            .get(mission_id)
            .ok_or_else(|| ArcError::MissionNotFound(mission_id.into()))?;
        if !mission.targets.iter().any(|target| target == sensor_id) {
            return Err(ArcError::SensorNotTarget {
                mission_id: mission_id.into(),
                sensor_id: sensor_id.into(),
            });
        }
        if !matches!(
            mission.assignments.get(sensor_id),
            Some(AssignmentStatus::Leased | AssignmentStatus::Submitted)
        ) {
            return Err(ArcError::AssignmentNotLeased {
                mission_id: mission_id.into(),
                sensor_id: sensor_id.into(),
            });
        }
        let byte_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if byte_len > mission.plan.max_artifact_bytes {
            return Err(ArcError::ArtifactTooLarge {
                bytes: byte_len,
                limit: mission.plan.max_artifact_bytes,
            });
        }

        let summary = replay(BufReader::new(Cursor::new(bytes)))?;
        if summary.events > mission.plan.max_events {
            return Err(ArcError::ArtifactEventLimit {
                events: summary.events,
                limit: mission.plan.max_events,
            });
        }
        let manifest = artifact_manifest(mission_id, sensor_id, bytes, &summary);
        let key = (mission_id.to_owned(), sensor_id.to_owned());
        if let Some(existing) = self.artifacts.get(&key) {
            if existing.manifest.content_hash == manifest.content_hash {
                return Ok(existing.manifest.clone());
            }
            return Err(ArcError::ArtifactConflict {
                mission_id: mission_id.into(),
                sensor_id: sensor_id.into(),
            });
        }

        let trace = parse_sensor_trace(
            sensor_id,
            self.sensors
                .get(sensor_id)
                .ok_or_else(|| ArcError::SensorNotFound(sensor_id.into()))?
                .registration
                .clock_uncertainty_ns,
            bytes,
        )?;
        self.artifacts.insert(
            key,
            StoredArtifact {
                manifest: manifest.clone(),
                trace,
            },
        );

        let mission = self
            .missions
            .get_mut(mission_id)
            .expect("mission existence was checked");
        mission
            .assignments
            .insert(sensor_id.into(), AssignmentStatus::Submitted);
        mission.artifacts.insert(sensor_id.into(), manifest.clone());

        let traces = self
            .artifacts
            .iter()
            .filter(|((stored_mission, _), _)| stored_mission == mission_id)
            .map(|((_, stored_sensor), stored)| (stored_sensor.clone(), stored.trace.clone()))
            .collect::<BTreeMap<_, _>>();
        mission.correlations = correlate_adjacent(
            &mission.targets,
            &traces,
            mission.plan.correlation_window_ns,
        );

        let submitted = mission
            .assignments
            .values()
            .filter(|status| **status == AssignmentStatus::Submitted)
            .count();
        if submitted == mission.targets.len() {
            mission.status = if mission.artifacts.values().all(|artifact| artifact.complete) {
                MissionStatus::Complete
            } else {
                MissionStatus::Partial
            };
        }

        let sensor = self
            .sensors
            .get_mut(sensor_id)
            .expect("sensor existence was checked");
        sensor.state = if manifest.complete {
            SensorState::EvidenceReceived
        } else {
            SensorState::Degraded
        };
        sensor.active_mission = Some(mission_id.into());
        sensor.last_seen_unix_ns = now_ns;

        Ok(manifest)
    }

    pub fn mission(&self, mission_id: &str) -> Result<MissionRecord, ArcError> {
        self.missions
            .get(mission_id)
            .cloned()
            .ok_or_else(|| ArcError::MissionNotFound(mission_id.into()))
    }

    pub fn snapshot(&self, now_ns: u64) -> ConsoleSnapshot {
        let mut timeline = self
            .selected_mission
            .as_ref()
            .into_iter()
            .flat_map(|mission_id| {
                self.artifacts
                    .iter()
                    .filter(move |((stored_mission, _), _)| {
                        stored_mission.as_str() == mission_id.as_str()
                    })
            })
            .flat_map(|((_, sensor_id), artifact)| {
                artifact
                    .trace
                    .events
                    .iter()
                    .map(move |event| TimelineEvent {
                        sensor_id: sensor_id.clone(),
                        handle: event.handle.clone(),
                        timestamp_unix_ns: artifact.trace.global_timestamp(event),
                        function: event
                            .function
                            .symbol
                            .clone()
                            .unwrap_or_else(|| event.function.address.clone()),
                        packet_len: event.packet.len,
                        drop_reason: event.drop_reason.clone(),
                    })
            })
            .collect::<Vec<_>>();
        timeline.sort_by(|left, right| {
            left.timestamp_unix_ns
                .cmp(&right.timestamp_unix_ns)
                .then_with(|| left.sensor_id.cmp(&right.sensor_id))
                .then_with(|| left.handle.cmp(&right.handle))
        });
        timeline.truncate(MAX_TIMELINE_EVENTS);

        ConsoleSnapshot {
            schema: MISSION_CONTRACT_VERSION.into(),
            generated_unix_ns: now_ns,
            sensors: self.sensors.values().cloned().collect(),
            missions: self.missions.values().cloned().collect(),
            selected_mission: self.selected_mission.clone(),
            timeline,
        }
    }
}

fn parse_sensor_trace(
    sensor_id: &str,
    clock_uncertainty_ns: u64,
    bytes: &[u8],
) -> Result<SensorTrace, ArcError> {
    let mut start = None::<CaptureStart>;
    let mut events = Vec::new();
    for (index, line) in Cursor::new(bytes).lines().enumerate() {
        let line = line.map_err(ReplayError::Io)?;
        if line.trim().is_empty() {
            continue;
        }
        let envelope: Envelope =
            serde_json::from_str(&line).map_err(|source| ReplayError::Json {
                line: index + 1,
                source,
            })?;
        match envelope {
            Envelope::CaptureStart(capture) => start = Some(capture),
            Envelope::Event(event) => events.push(event),
            Envelope::CaptureEnd(_) => {}
        }
    }
    let start = start
        .ok_or_else(|| ArcError::Replay(ReplayError::Contract("missing capture_start".into())))?;
    Ok(SensorTrace {
        sensor_id: sensor_id.into(),
        started_unix_ns: start.started_unix_ns,
        started_monotonic_ns: start.started_monotonic_ns,
        clock_uncertainty_ns,
        events,
    })
}

#[derive(Debug, Error)]
pub enum ArcError {
    #[error(transparent)]
    Mission(#[from] MissionError),
    #[error(transparent)]
    Replay(#[from] ReplayError),
    #[error("sensor {0} is not registered")]
    SensorNotFound(String),
    #[error("mission {0} does not exist")]
    MissionNotFound(String),
    #[error("mission {0} already exists")]
    MissionExists(String),
    #[error("cannot {action} mission {mission_id} from state {from:?}")]
    InvalidTransition {
        mission_id: String,
        from: MissionStatus,
        action: &'static str,
    },
    #[error("sensor {sensor_id} is not a target of mission {mission_id}")]
    SensorNotTarget {
        mission_id: String,
        sensor_id: String,
    },
    #[error("mission {mission_id} has no leased assignment for sensor {sensor_id}")]
    AssignmentNotLeased {
        mission_id: String,
        sensor_id: String,
    },
    #[error("artifact is {bytes} bytes; mission limit is {limit}")]
    ArtifactTooLarge { bytes: u64, limit: u64 },
    #[error("artifact contains {events} events; mission limit is {limit}")]
    ArtifactEventLimit { events: u64, limit: u64 },
    #[error("sensor {sensor_id} already submitted different evidence for mission {mission_id}")]
    ArtifactConflict {
        mission_id: String,
        sensor_id: String,
    },
    #[error("control-plane state lock is unavailable")]
    StateUnavailable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo::test_trace;
    use skbx_mission::{CapturePlan, MissionRequest, SensorRegistration};

    fn armed_control(max_events: u64) -> ControlPlane {
        let mut control = ControlPlane::default();
        control
            .register_sensor(
                SensorRegistration {
                    sensor_id: "sensor-a".into(),
                    display_name: "Sensor A".into(),
                    kernel_release: "test".into(),
                    capabilities: vec!["fixture-artifact-submit".into()],
                    clock_uncertainty_ns: 1_000,
                },
                1,
            )
            .unwrap();
        control
            .create_mission(
                MissionRequest {
                    mission_id: "mission:a".into(),
                    name: "State invariants".into(),
                    targets: vec!["sensor-a".into()],
                    plan: CapturePlan {
                        duration_seconds: 10,
                        max_events,
                        max_artifact_bytes: 1_048_576,
                        filter: "tcp port 443".into(),
                        probes: vec!["ip_rcv".into()],
                        track_skb: true,
                        trace_tc: false,
                        trace_xdp: false,
                        correlation_window_ns: 1_000_000,
                    },
                },
                1,
            )
            .unwrap();
        control.arm_mission("mission:a").unwrap();
        control
    }

    #[test]
    fn assignment_lease_is_idempotent_until_expiration() {
        let mut control = armed_control(100);
        let first = control.next_assignment("sensor-a", 10).unwrap().unwrap();
        let retry = control.next_assignment("sensor-a", 20).unwrap().unwrap();
        assert_eq!(retry, first);

        let renewed = control
            .next_assignment("sensor-a", first.lease_expires_unix_ns)
            .unwrap()
            .unwrap();
        assert!(renewed.generation > first.generation);
        assert!(renewed.lease_expires_unix_ns > first.lease_expires_unix_ns);
    }

    #[test]
    fn different_second_artifact_is_rejected() {
        let mut control = armed_control(100);
        control.next_assignment("sensor-a", 10).unwrap().unwrap();
        control
            .submit_artifact("mission:a", "sensor-a", &test_trace("first", 100, true), 20)
            .unwrap();

        let error = control
            .submit_artifact(
                "mission:a",
                "sensor-a",
                &test_trace("second", 110, true),
                30,
            )
            .unwrap_err();
        assert!(matches!(error, ArcError::ArtifactConflict { .. }));
    }

    #[test]
    fn artifact_cannot_exceed_assignment_event_budget() {
        let mut control = armed_control(1);
        control.next_assignment("sensor-a", 10).unwrap().unwrap();
        let error = control
            .submit_artifact(
                "mission:a",
                "sensor-a",
                &test_trace("too-many", 100, true),
                20,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            ArcError::ArtifactEventLimit {
                events: 2,
                limit: 1
            }
        ));
    }
}
