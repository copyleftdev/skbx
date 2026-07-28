(() => {
  "use strict";

  const $ = (selector) => document.querySelector(selector);
  const ui = {
    missionList: $("[data-mission-list]"),
    missionCount: $("[data-mission-count]"),
    sensorList: $("[data-sensor-list]"),
    sensorCount: $("[data-sensor-count]"),
    missionId: $("[data-mission-id]"),
    missionTitle: $("[data-mission-title]"),
    missionSummary: $("[data-mission-summary]"),
    missionState: $("[data-mission-state]"),
    artifactCount: $("[data-artifact-count]"),
    lossCount: $("[data-loss-count]"),
    window: $("[data-window]"),
    missionClock: $("[data-mission-clock]"),
    constellation: $("[data-constellation]"),
    canvas: $("[data-constellation-canvas]"),
    sensorLayer: $("[data-sensor-layer]"),
    stageEmpty: $("[data-stage-empty]"),
    timeline: $("[data-timeline]"),
    timelineEvents: $("[data-timeline-events]"),
    timelineScale: $("[data-timeline-scale]"),
    clockUncertainty: $("[data-clock-uncertainty]"),
    ledgerCount: $("[data-ledger-count]"),
    relationshipList: $("[data-relationship-list]"),
    findingTitle: $("[data-finding-title]"),
    findingCopy: $("[data-finding-copy]"),
    selectedLevel: $("[data-selected-level]"),
    eventDetail: $("[data-event-detail]"),
    eventList: $("[data-event-list]"),
    clearFilter: $("[data-clear-filter]"),
    connectionError: $("[data-connection-error]"),
    retry: $("[data-retry]"),
  };

  const state = {
    snapshot: null,
    missionId: null,
    selectedSensor: null,
    selectedEvent: null,
    visible: true,
    frame: null,
    paths: [],
    nodePositions: new Map(),
    reducedMotion: window.matchMedia("(prefers-reduced-motion: reduce)").matches,
  };

  const palette = {
    grid: "oklch(34% 0.023 116)",
    dim: "oklch(45% 0.024 116)",
    phosphor: "oklch(90% 0.2 120)",
    flare: "oklch(70% 0.2 42)",
    unknown: "oklch(45% 0.024 116)",
    field: "oklch(12% 0.015 116)",
  };

  async function loadSnapshot() {
    try {
      const response = await fetch("/api/v1/snapshot", {
        headers: { accept: "application/json" },
        cache: "no-store",
      });
      if (!response.ok) {
        throw new Error(`Arc returned HTTP ${response.status}`);
      }
      const snapshot = await response.json();
      if (snapshot.schema !== "missionq/0.1.0") {
        throw new Error(`Unsupported mission schema ${snapshot.schema}`);
      }
      state.snapshot = snapshot;
      if (!state.missionId || !snapshot.missions.some((mission) => mission.mission_id === state.missionId)) {
        state.missionId = snapshot.selected_mission ?? snapshot.missions.at(-1)?.mission_id ?? null;
      }
      ui.connectionError.hidden = true;
      render();
    } catch (error) {
      ui.connectionError.hidden = false;
      ui.connectionError.querySelector("span").textContent =
        `${error.message}. The last verified view remains on screen.`;
    }
  }

  function render() {
    const snapshot = state.snapshot;
    if (!snapshot) return;
    const mission = currentMission();
    renderMissionIndex(snapshot.missions);
    renderSensorIndex(snapshot.sensors);
    renderBriefing(mission);
    renderConstellation(mission, snapshot.sensors);
    renderRelationships(mission);
    renderTimeline(mission, snapshot.timeline);
    renderEventStream(mission, snapshot.timeline);
  }

  function currentMission() {
    return state.snapshot?.missions.find((mission) => mission.mission_id === state.missionId) ?? null;
  }

  function renderMissionIndex(missions) {
    ui.missionCount.textContent = pad(missions.length);
    ui.missionList.replaceChildren();
    if (missions.length === 0) {
      const empty = document.createElement("div");
      empty.className = "rail-loading";
      empty.textContent = "No missions yet. Register sensors, then create a bounded mission.";
      ui.missionList.append(empty);
      return;
    }

    for (const mission of missions) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "mission-entry";
      button.setAttribute("aria-current", String(mission.mission_id === state.missionId));
      const title = document.createElement("strong");
      title.textContent = mission.name;
      const meta = document.createElement("span");
      meta.textContent = `${mission.status} / ${mission.targets.length} sensors`;
      button.append(title, meta);
      button.addEventListener("click", () => {
        state.missionId = mission.mission_id;
        state.selectedSensor = null;
        state.selectedEvent = null;
        render();
      });
      ui.missionList.append(button);
    }
  }

  function renderSensorIndex(sensors) {
    const ready = sensors.filter((sensor) => sensor.state !== "degraded").length;
    ui.sensorCount.textContent = `${pad(ready)} / ${pad(sensors.length)}`;
    ui.sensorList.replaceChildren();
    for (const sensor of sensors) {
      const item = document.createElement("li");
      item.dataset.state = sensor.state;
      const beacon = document.createElement("i");
      beacon.setAttribute("aria-hidden", "true");
      const name = document.createElement("strong");
      name.textContent = sensor.display_name;
      const status = document.createElement("span");
      status.textContent = sensor.state.replaceAll("_", " ");
      item.append(beacon, name, status);
      ui.sensorList.append(item);
    }
  }

  function renderBriefing(mission) {
    if (!mission) {
      ui.missionId.textContent = "NO MISSION";
      ui.missionTitle.textContent = "Waiting for bounded evidence.";
      ui.missionSummary.textContent =
        "Register sensors and arm a mission. Arc will keep observations, correlations, and unknown space visibly separate.";
      ui.missionState.textContent = "—";
      ui.missionState.dataset.state = "";
      ui.artifactCount.textContent = "00 / 00";
      ui.lossCount.textContent = "—";
      ui.window.textContent = "—";
      ui.missionClock.textContent = "+00:00.000";
      ui.findingTitle.textContent = "No conclusion yet.";
      ui.findingCopy.textContent =
        "Arc only briefs from evidence already present in a validated artifact.";
      return;
    }

    const artifacts = Object.values(mission.artifacts);
    const losses = artifacts.reduce((total, artifact) => total + reliabilityLoss(artifact.reliability), 0);
    const drop = state.snapshot.timeline.find((event) => event.drop_reason);
    const unknown = mission.correlations.filter((edge) => edge.level === "unknown").length;

    ui.missionId.textContent = mission.mission_id;
    ui.missionTitle.textContent = drop
      ? `The request reached ${sensorName(drop.sensor_id)}—then the local path ended.`
      : mission.status === "complete"
        ? "Evidence converged across every assigned sensor."
        : "The evidence boundary is still moving.";
    ui.missionSummary.textContent = drop
      ? `${drop.function} reported ${drop.drop_reason}. ${losses > 0 ? `The mission also recorded ${losses} tracer reliability misses, so the route remains partial.` : "Every submitted artifact passed its reliability gate."}`
      : `${artifacts.length} of ${mission.targets.length} sensors submitted evidence. ${unknown > 0 ? `${unknown} cross-host hop remains unknown.` : "Every displayed cross-host relationship has an explicit correlation basis."}`;
    ui.missionState.textContent = mission.status;
    ui.missionState.dataset.state = mission.status;
    ui.artifactCount.textContent = `${pad(artifacts.length)} / ${pad(mission.targets.length)}`;
    ui.lossCount.textContent = losses === 0 ? "ZERO" : String(losses).padStart(2, "0");
    ui.window.textContent = formatDuration(mission.plan.correlation_window_ns);

    const timeline = missionTimeline(mission);
    if (timeline.length > 1) {
      ui.missionClock.textContent = `+${formatClock(timeline.at(-1).timestamp_unix_ns - timeline[0].timestamp_unix_ns)}`;
    } else {
      ui.missionClock.textContent = "+00:00.000";
    }

    if (drop) {
      ui.findingTitle.textContent = `${drop.function} recorded the terminal event.`;
      ui.findingCopy.textContent =
        `${sensorName(drop.sensor_id)} preserved ${drop.drop_reason} as ${drop.handle}. This is observed local evidence; it does not describe systems beyond that sensor.`;
    } else if (mission.status === "complete") {
      ui.findingTitle.textContent = "All assigned artifacts are complete.";
      ui.findingCopy.textContent =
        "The constellation distinguishes direct observations from cross-sensor correlation. Select a relationship to inspect its basis.";
    } else {
      ui.findingTitle.textContent = "The mission is not complete.";
      ui.findingCopy.textContent =
        "Missing artifacts and reliability loss stay visible. Arc will not promote an incomplete route into a complete conclusion.";
    }
  }

  function renderConstellation(mission, sensors) {
    stopAnimation();
    ui.sensorLayer.replaceChildren();
    state.nodePositions.clear();
    state.paths = [];
    ui.stageEmpty.hidden = Boolean(mission);
    if (!mission) {
      drawConstellation();
      return;
    }

    const sensorMap = new Map(sensors.map((sensor) => [sensor.sensor_id, sensor]));
    const mobile = window.matchMedia("(max-width: 40rem)").matches;
    mission.targets.forEach((sensorId, index) => {
      const sensor = sensorMap.get(sensorId);
      if (!sensor) return;
      const position = nodePosition(index, mission.targets.length, mobile);
      state.nodePositions.set(sensorId, position);

      const button = document.createElement("button");
      button.type = "button";
      button.className = "sensor-node";
      button.dataset.sensorId = sensorId;
      button.dataset.state = sensor.state;
      button.style.left = `${position.x * 100}%`;
      button.style.top = `${position.y * 100}%`;
      button.setAttribute("aria-pressed", String(state.selectedSensor === sensorId));
      button.setAttribute(
        "aria-label",
        `${sensor.display_name}, ${sensor.state.replaceAll("_", " ")}, clock uncertainty ${formatDuration(sensor.clock_uncertainty_ns)}`,
      );

      const core = document.createElement("span");
      core.className = "sensor-core";
      core.setAttribute("aria-hidden", "true");
      const name = document.createElement("strong");
      name.textContent = sensor.display_name;
      const meta = document.createElement("small");
      meta.textContent = `${sensorId} / ±${formatDuration(sensor.clock_uncertainty_ns)}`;
      button.append(core, name, meta);
      button.addEventListener("click", () => {
        state.selectedSensor = state.selectedSensor === sensorId ? null : sensorId;
        state.selectedEvent = null;
        renderConstellation(mission, sensors);
        renderEventStream(mission, state.snapshot.timeline);
        renderEventDetail(null);
      });
      ui.sensorLayer.append(button);
    });

    state.paths = mission.correlations.map((edge, index) => ({
      ...edge,
      index,
      from: state.nodePositions.get(edge.from_sensor),
      to: state.nodePositions.get(edge.to_sensor),
    })).filter((edge) => edge.from && edge.to);

    drawConstellation();
    if (!state.reducedMotion && state.visible && state.paths.some((path) => path.level !== "unknown")) {
      state.frame = requestAnimationFrame(animateConstellation);
    }
  }

  function nodePosition(index, total, mobile) {
    if (mobile) {
      return {
        x: index % 2 === 0 ? 0.42 : 0.58,
        y: total === 1 ? 0.5 : 0.17 + (index / (total - 1)) * 0.66,
      };
    }
    return {
      x: total === 1 ? 0.5 : 0.14 + (index / (total - 1)) * 0.72,
      y: index % 2 === 0 ? 0.46 : 0.37,
    };
  }

  function drawConstellation(time = 0) {
    const canvas = ui.canvas;
    const bounds = canvas.getBoundingClientRect();
    if (bounds.width === 0 || bounds.height === 0) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const width = Math.round(bounds.width * dpr);
    const height = Math.round(bounds.height * dpr);
    if (canvas.width !== width || canvas.height !== height) {
      canvas.width = width;
      canvas.height = height;
    }
    const context = canvas.getContext("2d");
    context.setTransform(dpr, 0, 0, dpr, 0, 0);
    context.clearRect(0, 0, bounds.width, bounds.height);
    drawCoordinates(context, bounds.width, bounds.height);

    for (const path of state.paths) {
      const curve = curveFor(path, bounds.width, bounds.height);
      context.save();
      context.beginPath();
      context.moveTo(curve.start.x, curve.start.y);
      context.bezierCurveTo(
        curve.control1.x,
        curve.control1.y,
        curve.control2.x,
        curve.control2.y,
        curve.end.x,
        curve.end.y,
      );
      context.lineWidth = path.level === "correlated" ? 1.6 : 1;
      context.strokeStyle =
        path.level === "candidate"
          ? palette.flare
          : path.level === "unknown"
            ? palette.unknown
            : palette.phosphor;
      context.globalAlpha = path.level === "unknown" ? 0.55 : 0.88;
      if (path.level === "candidate") context.setLineDash([7, 7]);
      if (path.level === "unknown") context.setLineDash([2, 9]);
      context.stroke();
      context.restore();

      if (path.level !== "unknown" && !state.reducedMotion) {
        const phase = ((time / 2600) + path.index * 0.31) % 1;
        const packet = cubicPoint(curve, phase);
        context.save();
        context.beginPath();
        context.arc(packet.x, packet.y, path.level === "correlated" ? 4.2 : 3.2, 0, Math.PI * 2);
        context.fillStyle = path.level === "candidate" ? palette.flare : palette.phosphor;
        context.shadowColor = context.fillStyle;
        context.shadowBlur = 16;
        context.fill();
        context.restore();
      }
    }
  }

  function drawCoordinates(context, width, height) {
    context.save();
    context.strokeStyle = palette.grid;
    context.globalAlpha = 0.18;
    context.lineWidth = 1;
    const spacing = 64;
    for (let x = spacing; x < width; x += spacing) {
      context.beginPath();
      context.moveTo(x, 0);
      context.lineTo(x, height);
      context.stroke();
    }
    for (let y = spacing; y < height; y += spacing) {
      context.beginPath();
      context.moveTo(0, y);
      context.lineTo(width, y);
      context.stroke();
    }
    context.restore();
  }

  function curveFor(path, width, height) {
    const start = { x: path.from.x * width, y: path.from.y * height };
    const end = { x: path.to.x * width, y: path.to.y * height };
    const vertical = window.matchMedia("(max-width: 40rem)").matches;
    if (vertical) {
      const distance = end.y - start.y;
      return {
        start,
        end,
        control1: { x: start.x + (path.index % 2 ? -48 : 48), y: start.y + distance * 0.36 },
        control2: { x: end.x + (path.index % 2 ? 48 : -48), y: end.y - distance * 0.36 },
      };
    }
    const distance = end.x - start.x;
    return {
      start,
      end,
      control1: { x: start.x + distance * 0.35, y: start.y - 54 },
      control2: { x: end.x - distance * 0.35, y: end.y + 54 },
    };
  }

  function cubicPoint(curve, t) {
    const inverse = 1 - t;
    const b0 = inverse ** 3;
    const b1 = 3 * inverse ** 2 * t;
    const b2 = 3 * inverse * t ** 2;
    const b3 = t ** 3;
    return {
      x: b0 * curve.start.x + b1 * curve.control1.x + b2 * curve.control2.x + b3 * curve.end.x,
      y: b0 * curve.start.y + b1 * curve.control1.y + b2 * curve.control2.y + b3 * curve.end.y,
    };
  }

  function animateConstellation(time) {
    drawConstellation(time);
    if (state.visible && !state.reducedMotion) {
      state.frame = requestAnimationFrame(animateConstellation);
    }
  }

  function stopAnimation() {
    if (state.frame) cancelAnimationFrame(state.frame);
    state.frame = null;
  }

  function renderRelationships(mission) {
    ui.relationshipList.replaceChildren();
    if (!mission || mission.correlations.length === 0) return;
    for (const edge of mission.correlations) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "relationship";
      button.dataset.level = edge.level;
      const route = document.createElement("span");
      route.className = "relationship-route";
      const from = document.createElement("strong");
      from.textContent = edge.from_sensor;
      const line = document.createElement("i");
      line.setAttribute("aria-hidden", "true");
      const to = document.createElement("strong");
      to.textContent = edge.to_sensor;
      route.append(from, line, to);
      const meta = document.createElement("span");
      meta.className = "relationship-meta";
      const level = document.createElement("span");
      level.textContent = edge.level;
      const confidence = document.createElement("span");
      confidence.textContent =
        edge.level === "unknown"
          ? "NO CLAIM"
          : `${(edge.confidence_basis_points / 100).toFixed(0)}% / ${edge.matches} MATCH${edge.matches === 1 ? "" : "ES"}`;
      meta.append(level, confidence);
      button.append(route, meta);
      button.addEventListener("click", () => renderEdgeDetail(edge));
      ui.relationshipList.append(button);
    }
  }

  function renderTimeline(mission, timeline) {
    ui.timelineEvents.replaceChildren();
    ui.timelineScale.replaceChildren();
    const events = mission ? missionTimeline(mission, timeline) : [];
    const uncertainty = mission
      ? mission.targets.reduce((maximum, sensorId) => {
          const sensor = state.snapshot.sensors.find((entry) => entry.sensor_id === sensorId);
          return Math.max(maximum, sensor?.clock_uncertainty_ns ?? 0);
        }, 0)
      : 0;
    ui.clockUncertainty.textContent = `clock uncertainty / ±${formatDuration(uncertainty)}`;

    if (events.length === 0) {
      ui.timelineScale.append(document.createTextNode("NO EVENTS"));
      return;
    }
    const start = events[0].timestamp_unix_ns;
    const end = events.at(-1).timestamp_unix_ns;
    const range = Math.max(1, end - start);
    for (const event of events) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "timeline-event";
      button.style.left = `${((event.timestamp_unix_ns - start) / range) * 100}%`;
      button.dataset.drop = String(Boolean(event.drop_reason));
      button.setAttribute("aria-pressed", String(state.selectedEvent === event.handle));
      button.setAttribute(
        "aria-label",
        `${sensorName(event.sensor_id)} ${event.function} at +${formatClock(event.timestamp_unix_ns - start)}${event.drop_reason ? `, ${event.drop_reason}` : ""}`,
      );
      button.addEventListener("click", () => selectEvent(event));
      ui.timelineEvents.append(button);
    }
    for (const value of [0, 0.25, 0.5, 0.75, 1]) {
      const mark = document.createElement("span");
      mark.textContent = `+${formatClock(Math.round(range * value))}`;
      ui.timelineScale.append(mark);
    }
  }

  function renderEventStream(mission, timeline) {
    const allEvents = mission ? missionTimeline(mission, timeline) : [];
    const events = state.selectedSensor
      ? allEvents.filter((event) => event.sensor_id === state.selectedSensor)
      : allEvents;
    ui.ledgerCount.textContent = `${pad(events.length)} EVENTS`;
    ui.eventList.replaceChildren();
    if (events.length === 0) {
      const empty = document.createElement("li");
      empty.className = "receipt";
      empty.textContent = mission
        ? "No events match this sensor filter."
        : "No mission evidence is available.";
      ui.eventList.append(empty);
      return;
    }

    const start = allEvents[0]?.timestamp_unix_ns ?? 0;
    for (const event of events) {
      const item = document.createElement("li");
      const button = document.createElement("button");
      button.type = "button";
      button.className = "event-row";
      button.dataset.drop = String(Boolean(event.drop_reason));
      const time = document.createElement("time");
      time.textContent = `+${formatClock(event.timestamp_unix_ns - start)}`;
      const name = document.createElement("strong");
      name.textContent = event.function;
      const sensor = document.createElement("span");
      sensor.textContent = event.sensor_id;
      button.append(time, name, sensor);
      button.addEventListener("click", () => selectEvent(event));
      item.append(button);
      ui.eventList.append(item);
    }
  }

  function selectEvent(event) {
    state.selectedEvent = event.handle;
    renderEventDetail(event);
    renderTimeline(currentMission(), state.snapshot.timeline);
  }

  function renderEventDetail(event) {
    ui.eventDetail.replaceChildren();
    if (!event) {
      ui.selectedLevel.textContent = "NONE";
      const copy = document.createElement("p");
      copy.textContent = state.selectedSensor
        ? `Showing receipts captured by ${sensorName(state.selectedSensor)}. Select one to inspect it.`
        : "Select a sensor, route relationship, or event marker to inspect its evidence.";
      ui.eventDetail.append(copy);
      return;
    }
    ui.selectedLevel.textContent = "OBSERVED";
    const list = document.createElement("dl");
    appendDefinition(list, "HANDLE", event.handle);
    appendDefinition(list, "SENSOR", `${sensorName(event.sensor_id)} / ${event.sensor_id}`);
    appendDefinition(list, "FUNCTION", event.function);
    appendDefinition(list, "LENGTH", `${event.packet_len} bytes`);
    appendDefinition(list, "TIME", String(event.timestamp_unix_ns));
    if (event.drop_reason) {
      appendDefinition(list, "DROP", event.drop_reason, "receipt-alert");
    }
    ui.eventDetail.append(list);
  }

  function renderEdgeDetail(edge) {
    state.selectedEvent = null;
    ui.eventDetail.replaceChildren();
    ui.selectedLevel.textContent = edge.level.toUpperCase();
    const list = document.createElement("dl");
    appendDefinition(list, "EDGE", edge.edge_id);
    appendDefinition(list, "FROM", edge.from_sensor);
    appendDefinition(list, "TO", edge.to_sensor);
    appendDefinition(
      list,
      "CONFIDENCE",
      edge.level === "unknown"
        ? "No correlation claim"
        : `${(edge.confidence_basis_points / 100).toFixed(2)}%`,
    );
    appendDefinition(list, "MATCHES", String(edge.matches));
    appendDefinition(list, "BASIS", edge.basis.join(" · "));
    if (edge.source_events.length > 0) {
      appendDefinition(list, "SOURCE", edge.source_events.join(", "));
      appendDefinition(list, "TARGET", edge.target_events.join(", "));
    }
    ui.eventDetail.append(list);
  }

  function appendDefinition(list, term, value, className = "") {
    const dt = document.createElement("dt");
    dt.textContent = term;
    const dd = document.createElement("dd");
    dd.textContent = value;
    if (className) dd.className = className;
    list.append(dt, dd);
  }

  function missionTimeline(mission, timeline = state.snapshot.timeline) {
    if (!mission) return [];
    const targets = new Set(mission.targets);
    return timeline.filter((event) => targets.has(event.sensor_id));
  }

  function sensorName(sensorId) {
    return state.snapshot?.sensors.find((sensor) => sensor.sensor_id === sensorId)?.display_name ?? sensorId;
  }

  function reliabilityLoss(reliability) {
    return [
      "kernel_reserve_failures",
      "kernel_read_failures",
      "kernel_recursion_misses",
      "userspace_decode_failures",
      "userspace_enrichment_failures",
      "output_failures",
    ].reduce((total, key) => total + (reliability[key] ?? 0), 0);
  }

  function formatDuration(nanoseconds) {
    if (nanoseconds >= 1_000_000_000) return `${(nanoseconds / 1_000_000_000).toFixed(2)}s`;
    if (nanoseconds >= 1_000_000) return `${(nanoseconds / 1_000_000).toFixed(1)}ms`;
    if (nanoseconds >= 1_000) return `${(nanoseconds / 1_000).toFixed(1)}µs`;
    return `${nanoseconds}ns`;
  }

  function formatClock(nanoseconds) {
    const milliseconds = Math.max(0, Math.floor(nanoseconds / 1_000_000));
    const minutes = Math.floor(milliseconds / 60_000);
    const seconds = Math.floor((milliseconds % 60_000) / 1_000);
    const remainder = milliseconds % 1_000;
    return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}.${String(remainder).padStart(3, "0")}`;
  }

  function pad(value) {
    return String(value).padStart(2, "0");
  }

  const resizeObserver = new ResizeObserver(() => {
    if (state.snapshot) renderConstellation(currentMission(), state.snapshot.sensors);
  });
  resizeObserver.observe(ui.constellation);

  const visibilityObserver = new IntersectionObserver(([entry]) => {
    state.visible = entry.isIntersecting;
    if (!state.visible) {
      stopAnimation();
    } else if (!state.reducedMotion && state.paths.some((path) => path.level !== "unknown")) {
      stopAnimation();
      state.frame = requestAnimationFrame(animateConstellation);
    } else {
      drawConstellation();
    }
  });
  visibilityObserver.observe(ui.constellation);

  window.matchMedia("(prefers-reduced-motion: reduce)").addEventListener("change", (event) => {
    state.reducedMotion = event.matches;
    if (event.matches) {
      stopAnimation();
      drawConstellation();
    } else if (state.visible) {
      state.frame = requestAnimationFrame(animateConstellation);
    }
  });

  ui.clearFilter.addEventListener("click", () => {
    state.selectedSensor = null;
    state.selectedEvent = null;
    render();
    renderEventDetail(null);
  });
  ui.retry.addEventListener("click", loadSnapshot);

  loadSnapshot();
  window.setInterval(loadSnapshot, 5_000);
})();
