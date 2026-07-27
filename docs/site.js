(() => {
  "use strict";

  document.documentElement.classList.add("has-js");

  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  const header = document.querySelector("[data-header]");
  const copyStatus = document.querySelector("#copy-status");
  const copyButtons = document.querySelectorAll("[data-copy]");

  const updateHeader = () => {
    header?.classList.toggle("is-scrolled", window.scrollY > 24);
  };

  updateHeader();
  window.addEventListener("scroll", updateHeader, { passive: true });

  copyButtons.forEach((button) => {
    button.addEventListener("click", async () => {
      const command = button.dataset.copy;
      try {
        await navigator.clipboard.writeText(command);
        const label = button.querySelector(".copy-label");
        if (label) {
          const original = label.textContent;
          label.textContent = "Copied";
          window.setTimeout(() => { label.textContent = original; }, 1800);
        } else {
          const original = button.textContent;
          button.textContent = "Copied";
          window.setTimeout(() => { button.textContent = original; }, 1800);
        }
        if (copyStatus) copyStatus.textContent = "Install command copied to clipboard.";
      } catch {
        if (copyStatus) {
          copyStatus.textContent = "Clipboard access was blocked. Select the command and copy it manually.";
        }
      }
    });
  });

  const steps = [...document.querySelectorAll(".flight-step")];
  if ("IntersectionObserver" in window) {
    const stepObserver = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        steps.forEach((step) => step.classList.toggle("is-active", step === entry.target));
      });
    }, { rootMargin: "-38% 0px -38% 0px", threshold: 0 });

    steps.forEach((step) => stepObserver.observe(step));
  } else {
    steps.forEach((step) => step.classList.add("is-active"));
  }

  const canvas = document.querySelector("#trace-field");
  const hero = document.querySelector(".hero");
  if (!canvas || !hero) return;

  const context = canvas.getContext("2d", { alpha: true });
  if (!context) return;

  let width = 0;
  let height = 0;
  let dpr = 1;
  let frame = 0;
  let visible = true;
  let lastTime = 0;
  let particles = [];

  const palette = {
    phosphor: "rgba(215, 255, 63, 0.92)",
    phosphorDim: "rgba(145, 178, 44, 0.32)",
    flare: "rgba(255, 107, 53, 0.95)",
    paper: "rgba(242, 245, 223, 0.55)",
    line: "rgba(89, 96, 75, 0.20)"
  };

  class Packet {
    constructor(index) {
      this.index = index;
      this.reset(true);
    }

    reset(initial = false) {
      this.progress = initial ? Math.random() : -Math.random() * 0.16;
      this.speed = 0.035 + Math.random() * 0.045;
      this.route = Math.floor(Math.random() * 4);
      this.radius = Math.random() > 0.82 ? 2.7 : 1.4;
      this.alpha = 0.28 + Math.random() * 0.7;
      this.offset = (Math.random() - 0.5) * Math.min(90, height * 0.09);
      this.color = Math.random() > 0.88 ? palette.flare : palette.phosphor;
    }

    point(t) {
      const startX = -40;
      const endX = width + 50;
      const lane = height * (0.2 + this.route * 0.16);
      const bend = Math.sin(t * Math.PI) * (this.route % 2 ? -1 : 1) * height * 0.12;
      const hook = Math.sin(t * Math.PI * 3 + this.route) * height * 0.025;
      return {
        x: startX + (endX - startX) * t,
        y: lane + bend + hook + this.offset
      };
    }

    draw(delta) {
      this.progress += this.speed * delta;
      if (this.progress > 1.05) this.reset();
      if (this.progress < 0) return;

      const point = this.point(this.progress);
      const previous = this.point(Math.max(0, this.progress - 0.032));
      const fade = Math.sin(Math.min(1, this.progress) * Math.PI);

      context.beginPath();
      context.moveTo(previous.x, previous.y);
      context.lineTo(point.x, point.y);
      context.strokeStyle = this.color === palette.flare
        ? `rgba(255, 107, 53, ${0.24 * fade * this.alpha})`
        : `rgba(215, 255, 63, ${0.16 * fade * this.alpha})`;
      context.lineWidth = this.radius;
      context.stroke();

      context.beginPath();
      context.arc(point.x, point.y, this.radius, 0, Math.PI * 2);
      context.fillStyle = this.color;
      context.globalAlpha = fade * this.alpha;
      context.fill();
      context.globalAlpha = 1;
    }
  }

  const drawTopology = () => {
    context.lineWidth = 1;
    context.strokeStyle = palette.line;
    for (let row = 0; row < 5; row += 1) {
      const y = height * (0.19 + row * 0.16);
      context.beginPath();
      context.moveTo(0, y);
      context.bezierCurveTo(width * 0.27, y - height * 0.08, width * 0.65, y + height * 0.09, width, y - height * 0.02);
      context.stroke();
    }

    const hooks = [
      [0.17, 0.29],
      [0.39, 0.47],
      [0.62, 0.34],
      [0.81, 0.58]
    ];
    hooks.forEach(([x, y], index) => {
      context.beginPath();
      context.arc(width * x, height * y, index === 2 ? 4 : 2.5, 0, Math.PI * 2);
      context.fillStyle = index === 2 ? palette.flare : palette.paper;
      context.fill();
    });
  };

  const render = (time) => {
    if (!visible) {
      frame = 0;
      return;
    }
    const elapsed = lastTime ? Math.min(32, time - lastTime) : 16;
    lastTime = time;
    context.clearRect(0, 0, width, height);
    drawTopology();

    const delta = elapsed / 1000;
    particles.forEach((particle) => particle.draw(delta));

    if (!reducedMotion.matches) frame = requestAnimationFrame(render);
  };

  const resize = () => {
    const rect = canvas.getBoundingClientRect();
    width = Math.max(1, rect.width);
    height = Math.max(1, rect.height);
    dpr = Math.min(window.devicePixelRatio || 1, 1.75);
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
    context.setTransform(dpr, 0, 0, dpr, 0, 0);
    const count = Math.max(12, Math.min(34, Math.round(width / 48)));
    particles = Array.from({ length: count }, (_, index) => new Packet(index));
    context.clearRect(0, 0, width, height);
    drawTopology();
    particles.forEach((particle) => particle.draw(0));
  };

  const start = () => {
    cancelAnimationFrame(frame);
    lastTime = 0;
    if (reducedMotion.matches) {
      context.clearRect(0, 0, width, height);
      drawTopology();
      particles.forEach((particle) => particle.draw(0));
    } else if (visible) {
      frame = requestAnimationFrame(render);
    }
  };

  const heroObserver = new IntersectionObserver(([entry]) => {
    visible = entry.isIntersecting && !document.hidden;
    start();
  }, { threshold: 0 });

  heroObserver.observe(hero);
  document.addEventListener("visibilitychange", () => {
    visible = !document.hidden && hero.getBoundingClientRect().bottom > 0;
    start();
  });
  reducedMotion.addEventListener?.("change", start);
  window.addEventListener("resize", resize, { passive: true });

  resize();
  start();
})();
