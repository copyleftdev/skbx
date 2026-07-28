//! Outbound-only skbx Arc sensor agent.
//!
//! The first vertical slice deliberately supports fixture submission only.
//! It cannot execute arbitrary commands or start a privileged capture. A live
//! backend must derive an exact `skbx capture` invocation from the validated
//! `CapturePlan`; it must never accept shell text from the control plane.

use anyhow::{Context, Result, bail};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use skbx_mission::{ArtifactManifest, Assignment, SensorRegistration};
use std::path::Path;

#[derive(Clone, Debug)]
pub struct AgentClient {
    control_url: String,
    http: reqwest::Client,
}

impl AgentClient {
    pub fn new(control_url: impl Into<String>) -> Result<Self> {
        let control_url = control_url.into().trim_end_matches('/').to_owned();
        let parsed = reqwest::Url::parse(&control_url).context("parse Arc control URL")?;
        if !matches!(parsed.scheme(), "http" | "https") {
            bail!("Arc control URL must use http or https");
        }
        Ok(Self {
            control_url,
            http: reqwest::Client::builder()
                .user_agent(concat!("skbx-agent/", env!("CARGO_PKG_VERSION")))
                .build()
                .context("build Arc HTTP client")?,
        })
    }

    pub async fn register(&self, sensor: &SensorRegistration) -> Result<()> {
        sensor.validate().context("validate sensor registration")?;
        self.http
            .post(format!("{}/api/v1/sensors", self.control_url))
            .json(sensor)
            .send()
            .await
            .context("register sensor with Arc")?
            .error_for_status()
            .context("Arc rejected sensor registration")?;
        Ok(())
    }

    pub async fn next_assignment(&self, sensor_id: &str) -> Result<Option<Assignment>> {
        let response = self
            .http
            .get(format!(
                "{}/api/v1/sensors/{sensor_id}/assignments/next",
                self.control_url
            ))
            .send()
            .await
            .context("poll Arc assignment")?;
        if response.status() == StatusCode::NO_CONTENT {
            return Ok(None);
        }
        response
            .error_for_status()
            .context("Arc rejected assignment poll")?
            .json()
            .await
            .context("decode Arc assignment")
    }

    pub async fn upload(
        &self,
        assignment: &Assignment,
        artifact: Vec<u8>,
    ) -> Result<ArtifactManifest> {
        let bytes = u64::try_from(artifact.len()).unwrap_or(u64::MAX);
        if bytes > assignment.plan.max_artifact_bytes {
            bail!(
                "artifact is {bytes} bytes; mission limit is {}",
                assignment.plan.max_artifact_bytes
            );
        }
        if assignment.plan_digest != assignment.plan.digest() {
            bail!("assignment plan digest does not match its bounded capture plan");
        }
        self.http
            .post(format!(
                "{}/api/v1/missions/{}/artifacts/{}",
                self.control_url, assignment.mission_id, assignment.sensor_id
            ))
            .header("content-type", "application/x-ndjson")
            .body(artifact)
            .send()
            .await
            .context("upload traceq artifact to Arc")?
            .error_for_status()
            .context("Arc rejected traceq artifact")?
            .json()
            .await
            .context("decode Arc artifact manifest")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunReport {
    pub sensor_id: String,
    pub assignment: Option<String>,
    pub artifact: Option<ArtifactManifest>,
}

pub async fn run_fixture_once(
    client: &AgentClient,
    registration: SensorRegistration,
    artifact_path: &Path,
) -> Result<RunReport> {
    client.register(&registration).await?;
    let Some(assignment) = client.next_assignment(&registration.sensor_id).await? else {
        return Ok(RunReport {
            sensor_id: registration.sensor_id,
            assignment: None,
            artifact: None,
        });
    };
    let artifact = std::fs::read(artifact_path)
        .with_context(|| format!("read traceq fixture {}", artifact_path.display()))?;
    let manifest = client.upload(&assignment, artifact).await?;
    Ok(RunReport {
        sensor_id: registration.sensor_id,
        assignment: Some(assignment.mission_id),
        artifact: Some(manifest),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use skbx_arc::{ControlPlane, app, shared};
    use skbx_mission::{CapturePlan, MissionRequest, MissionStatus};

    #[test]
    fn client_rejects_non_http_control_urls() {
        assert!(AgentClient::new("file:///tmp/arc").is_err());
    }

    #[tokio::test]
    #[ignore = "requires permission to bind a loopback socket"]
    async fn fixture_agent_completes_real_http_assignment_and_upload() {
        let registration = SensorRegistration {
            sensor_id: "sensor-agent".into(),
            display_name: "Agent integration sensor".into(),
            kernel_release: "fixture".into(),
            capabilities: vec![
                "fixture-artifact-submit".into(),
                "deterministic-replay".into(),
            ],
            clock_uncertainty_ns: 1_000,
        };
        let mut control = ControlPlane::default();
        control.register_sensor(registration.clone(), 1).unwrap();
        control
            .create_mission(
                MissionRequest {
                    mission_id: "mission:agent-e2e".into(),
                    name: "Agent integration".into(),
                    targets: vec![registration.sensor_id.clone()],
                    plan: CapturePlan {
                        duration_seconds: 10,
                        max_events: 10,
                        max_artifact_bytes: 1_048_576,
                        filter: "icmp".into(),
                        probes: vec!["ip_rcv".into(), "kfree_skb_reason".into()],
                        track_skb: true,
                        trace_tc: false,
                        trace_xdp: false,
                        correlation_window_ns: 1_000_000,
                    },
                },
                1,
            )
            .unwrap();
        control.arm_mission("mission:agent-e2e").unwrap();
        let state = shared(control);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            axum::serve(listener, app(server_state)).await.unwrap();
        });

        let client = AgentClient::new(format!("http://{address}")).unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../skbx-cli/tests/fixtures/sample.traceq.jsonl");
        let report = run_fixture_once(&client, registration, &fixture)
            .await
            .unwrap();

        assert_eq!(report.assignment.as_deref(), Some("mission:agent-e2e"));
        assert_eq!(report.artifact.as_ref().map(|item| item.events), Some(3));
        assert_eq!(
            state
                .read()
                .unwrap()
                .mission("mission:agent-e2e")
                .unwrap()
                .status,
            MissionStatus::Complete
        );
        server.abort();
    }
}
