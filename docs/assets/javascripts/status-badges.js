// Shows the documented capability statuses (`stable`, `partial`, ...) as coloured badges.
// The Markdown keeps plain inline code, so the pages still read well on GitHub.
(function () {
  var STATUSES = ["stable", "partial", "experimental", "planned", "unsupported", "deprecated"];

  function decorate() {
    document.querySelectorAll(".md-typeset code").forEach(function (el) {
      if (el.closest("pre") || el.classList.contains("kd-status")) return;
      var text = el.textContent.trim().toLowerCase();
      if (STATUSES.indexOf(text) === -1) return;
      el.classList.add("kd-status", "kd-status--" + text);
    });
    // Status columns in tables often hold the bare word, without code formatting.
    document.querySelectorAll(".md-typeset td").forEach(function (td) {
      if (td.children.length) return;
      var text = td.textContent.trim().toLowerCase();
      if (STATUSES.indexOf(text) === -1) return;
      td.innerHTML = "";
      var badge = document.createElement("span");
      badge.className = "kd-status kd-status--" + text;
      badge.textContent = text;
      td.appendChild(badge);
    });
  }

  // Material's instant navigation exposes document$; fall back to a plain load.
  if (window.document$ && typeof window.document$.subscribe === "function") {
    window.document$.subscribe(decorate);
  } else {
    document.addEventListener("DOMContentLoaded", decorate);
  }
})();
