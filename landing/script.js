// ── Centinela landing — vanilla, sin dependencias ──

// Email donde te llegan los pedidos de reporte. CAMBIALO por el tuyo.
const CONTACT_EMAIL = "you@centinela.security";

// año del footer
document.getElementById("year").textContent = new Date().getFullYear();

// nav: borde al hacer scroll
const nav = document.getElementById("nav");
const onScroll = () => nav.classList.toggle("scrolled", window.scrollY > 8);
onScroll();
addEventListener("scroll", onScroll, { passive: true });

// reveal on scroll (respeta prefers-reduced-motion vía CSS)
const reveals = document.querySelectorAll(".reveal");
if ("IntersectionObserver" in window) {
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) {
      if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); }
    }
  }, { threshold: 0.12, rootMargin: "0px 0px -40px 0px" });
  reveals.forEach((el) => io.observe(el));
} else {
  reveals.forEach((el) => el.classList.add("in"));
}

// formulario: arma el pedido de reporte gratis
function requestReport(ev) {
  ev.preventDefault();
  const input = document.getElementById("site");
  let site = input.value.trim();
  if (!site) { input.focus(); return false; }
  site = site.replace(/^https?:\/\//i, "").replace(/\/+$/, "");

  const subject = `Free security report for ${site}`;
  const body =
    `Hi Centinela,\n\nPlease run a free security report for my store: ${site}\n\nThanks!`;
  window.location.href =
    `mailto:${CONTACT_EMAIL}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
  return false;
}
