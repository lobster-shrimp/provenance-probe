// Registers the "Provenance Capture" DevTools panel. DevTools (and therefore the
// panel and its network listener) is scoped to the single inspected tab only —
// there is no cross-tab or background observation.
chrome.devtools.panels.create(
  "Provenance Capture",
  "",
  "panel.html",
  () => {},
);
