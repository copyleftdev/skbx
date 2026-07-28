use crate::state::{ArcError, SharedControlPlane};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use skbx_mission::{
    ArtifactManifest, Assignment, MAX_ARTIFACT_BYTES, MissionRecord, MissionRequest,
    SensorRegistration,
};
use std::time::{SystemTime, UNIX_EPOCH};
use tower_http::limit::RequestBodyLimitLayer;

const INDEX_HTML: &str = include_str!("../ui/index.html");
const ARC_CSS: &str = include_str!("../ui/arc.css");
const ARC_JS: &str = include_str!("../ui/arc.js");

pub fn app(state: SharedControlPlane) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/arc.css", get(styles))
        .route("/arc.js", get(script))
        .route("/healthz", get(health))
        .route("/api/v1/snapshot", get(snapshot))
        .route("/api/v1/sensors", post(register_sensor))
        .route("/api/v1/missions", post(create_mission))
        .route("/api/v1/missions/{mission_id}", get(get_mission))
        .route("/api/v1/missions/{mission_id}/arm", post(arm_mission))
        .route(
            "/api/v1/sensors/{sensor_id}/assignments/next",
            get(next_assignment),
        )
        .route(
            "/api/v1/missions/{mission_id}/artifacts/{sensor_id}",
            post(submit_artifact),
        )
        .layer(RequestBodyLimitLayer::new(
            usize::try_from(MAX_ARTIFACT_BYTES).expect("artifact limit fits usize"),
        ))
        .with_state(state)
}

async fn index() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        INDEX_HTML,
    )
}

async fn styles() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], ARC_CSS)
}

async fn script() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        ARC_JS,
    )
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
    service: &'static str,
    schema: &'static str,
}

async fn health() -> Json<Health> {
    Json(Health {
        status: "ready",
        service: "skbx-arc",
        schema: skbx_mission::MISSION_CONTRACT_VERSION,
    })
}

async fn snapshot(
    State(state): State<SharedControlPlane>,
) -> Result<Json<crate::ConsoleSnapshot>, ApiError> {
    let state = state.read().map_err(|_| ArcError::StateUnavailable)?;
    Ok(Json(state.snapshot(now_ns())))
}

async fn register_sensor(
    State(state): State<SharedControlPlane>,
    Json(registration): Json<SensorRegistration>,
) -> Result<(StatusCode, Json<crate::SensorView>), ApiError> {
    let mut state = state.write().map_err(|_| ArcError::StateUnavailable)?;
    let sensor = state.register_sensor(registration, now_ns())?;
    Ok((StatusCode::CREATED, Json(sensor)))
}

async fn create_mission(
    State(state): State<SharedControlPlane>,
    Json(request): Json<MissionRequest>,
) -> Result<(StatusCode, Json<MissionRecord>), ApiError> {
    let mut state = state.write().map_err(|_| ArcError::StateUnavailable)?;
    let mission = state.create_mission(request, now_ns())?;
    Ok((StatusCode::CREATED, Json(mission)))
}

async fn get_mission(
    State(state): State<SharedControlPlane>,
    Path(mission_id): Path<String>,
) -> Result<Json<MissionRecord>, ApiError> {
    let state = state.read().map_err(|_| ArcError::StateUnavailable)?;
    Ok(Json(state.mission(&mission_id)?))
}

async fn arm_mission(
    State(state): State<SharedControlPlane>,
    Path(mission_id): Path<String>,
) -> Result<Json<MissionRecord>, ApiError> {
    let mut state = state.write().map_err(|_| ArcError::StateUnavailable)?;
    Ok(Json(state.arm_mission(&mission_id)?))
}

async fn next_assignment(
    State(state): State<SharedControlPlane>,
    Path(sensor_id): Path<String>,
) -> Result<Json<Option<Assignment>>, ApiError> {
    let mut state = state.write().map_err(|_| ArcError::StateUnavailable)?;
    Ok(Json(state.next_assignment(&sensor_id, now_ns())?))
}

async fn submit_artifact(
    State(state): State<SharedControlPlane>,
    Path((mission_id, sensor_id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Json<ArtifactManifest>, ApiError> {
    let mut state = state.write().map_err(|_| ArcError::StateUnavailable)?;
    Ok(Json(state.submit_artifact(
        &mission_id,
        &sensor_id,
        &body,
        now_ns(),
    )?))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiErrorBody {
    pub code: String,
    pub message: String,
}

pub struct ApiError {
    status: StatusCode,
    body: ApiErrorBody,
}

impl From<ArcError> for ApiError {
    fn from(error: ArcError) -> Self {
        let (status, code) = match &error {
            ArcError::SensorNotFound(_) | ArcError::MissionNotFound(_) => {
                (StatusCode::NOT_FOUND, "not_found")
            }
            ArcError::MissionExists(_)
            | ArcError::InvalidTransition { .. }
            | ArcError::ArtifactConflict { .. }
            | ArcError::AssignmentNotLeased { .. } => (StatusCode::CONFLICT, "conflict"),
            ArcError::ArtifactTooLarge { .. } => {
                (StatusCode::PAYLOAD_TOO_LARGE, "artifact_too_large")
            }
            ArcError::StateUnavailable => (StatusCode::SERVICE_UNAVAILABLE, "state_unavailable"),
            ArcError::Mission(_)
            | ArcError::SensorNotTarget { .. }
            | ArcError::ArtifactEventLimit { .. } => {
                (StatusCode::UNPROCESSABLE_ENTITY, "invalid_request")
            }
            ArcError::Replay(_) => (StatusCode::UNPROCESSABLE_ENTITY, "invalid_trace"),
        };
        Self {
            status,
            body: ApiErrorBody {
                code: code.into(),
                message: error.to_string(),
            },
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo::test_trace;
    use crate::{ControlPlane, shared};
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use serde::de::DeserializeOwned;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    async fn response_json<T: DeserializeOwned>(response: Response) -> T {
        let body = to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .expect("read response body");
        serde_json::from_slice(&body).expect("response is JSON")
    }

    async fn json_request(router: &Router, method: &str, uri: &str, value: Value) -> Response {
        router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&value).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn register(router: &Router, sensor_id: &str) {
        let response = json_request(
            router,
            "POST",
            "/api/v1/sensors",
            json!({
                "sensor_id": sensor_id,
                "display_name": sensor_id,
                "kernel_release": "test",
                "capabilities": ["fixture-artifact-submit"],
                "clock_uncertainty_ns": 1000
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn complete_http_mission_is_correlated_and_idempotent() {
        let router = app(shared(ControlPlane::default()));
        register(&router, "client").await;
        register(&router, "edge").await;

        let response = json_request(
            &router,
            "POST",
            "/api/v1/missions",
            json!({
                "mission_id": "mission:test",
                "name": "HTTP lifecycle",
                "targets": ["client", "edge"],
                "plan": {
                    "duration_seconds": 10,
                    "max_events": 100,
                    "max_artifact_bytes": 1048576,
                    "filter": "tcp port 443",
                    "probes": ["ip_rcv"],
                    "track_skb": true,
                    "trace_tc": false,
                    "trace_xdp": false,
                    "correlation_window_ns": 1000000
                }
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = json_request(
            &router,
            "POST",
            "/api/v1/missions/mission:test/arm",
            json!({}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        for (sensor_id, capture_id, offset) in [
            ("client", "client-capture", 100_u64),
            ("edge", "edge-capture", 120),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/v1/sensors/{sensor_id}/assignments/next"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let assignment: Option<Assignment> = response_json(response).await;
            assert!(assignment.is_some());

            let trace = test_trace(capture_id, offset, true);
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!(
                            "/api/v1/missions/mission:test/artifacts/{sensor_id}"
                        ))
                        .header(header::CONTENT_TYPE, "application/x-ndjson")
                        .body(Body::from(trace.clone()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let duplicate = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!(
                            "/api/v1/missions/mission:test/artifacts/{sensor_id}"
                        ))
                        .body(Body::from(trace))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(duplicate.status(), StatusCode::OK);
        }

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/missions/mission:test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let mission: MissionRecord = response_json(response).await;
        assert_eq!(mission.status, skbx_mission::MissionStatus::Complete);
        assert_eq!(mission.correlations.len(), 1);
        assert_eq!(
            mission.correlations[0].level,
            skbx_mission::EvidenceLevel::Correlated
        );
        assert_eq!(mission.correlations[0].matches, 2);
    }

    #[tokio::test]
    async fn api_reports_actionable_contract_errors() {
        let router = app(shared(ControlPlane::default()));
        let response = json_request(
            &router,
            "POST",
            "/api/v1/missions",
            json!({
                "mission_id": "bad mission",
                "name": "Bad",
                "targets": [],
                "plan": {
                    "duration_seconds": 0,
                    "max_events": 0,
                    "max_artifact_bytes": 0,
                    "filter": ""
                }
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body: ApiErrorBody = response_json(response).await;
        assert_eq!(body.code, "invalid_request");
        assert!(body.message.contains("mission_id"));
    }

    #[tokio::test]
    async fn demo_snapshot_exposes_partial_evidence_without_hiding_loss() {
        let router = app(shared(crate::demo_control_plane()));
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/snapshot")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let snapshot: crate::ConsoleSnapshot = response_json(response).await;
        assert_eq!(snapshot.missions.len(), 1);
        assert_eq!(
            snapshot.missions[0].status,
            skbx_mission::MissionStatus::Partial
        );
        assert_eq!(snapshot.timeline.len(), 8);
        assert!(
            snapshot
                .timeline
                .iter()
                .any(|event| event.drop_reason.is_some())
        );
    }
}
