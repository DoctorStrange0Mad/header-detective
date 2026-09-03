/**
 * Manual mock for react-leaflet.
 *
 * The real react-leaflet components require a real browser map context.
 * We replace each component with a thin React stub that:
 *   - Renders its children (so Marker > Popup nesting is preserved)
 *   - Exposes enough attributes / data-testid to let RTL assertions work
 *   - Counts as a real React element so snapshot tests are meaningful
 *
 * We do NOT mock out the HopMap component itself — only the Leaflet
 * primitives it composes. This means our tests exercise the real branching
 * logic (loading state, empty state, single-hop guard, marker icons) while
 * sidestepping the map-canvas code that needs a real browser.
 */

const React = require("react");

const MapContainer = ({ children, bounds, style, "data-testid": testId }) =>
  React.createElement(
    "div",
    {
      "data-testid": testId || "map-container",
      "data-bounds": JSON.stringify(bounds),
      style,
    },
    children
  );

const TileLayer = ({ url }) =>
  React.createElement("div", { "data-testid": "tile-layer", "data-url": url });

const Marker = ({ children, position, icon }) =>
  React.createElement(
    "div",
    {
      "data-testid": "marker",
      "data-position": JSON.stringify(position),
      // Serialise enough of the icon object so tests can assert on icon type
      "data-icon-type": icon?._type ?? icon?.options?.className ?? "default",
    },
    children
  );

const Popup = ({ children }) =>
  React.createElement("div", { "data-testid": "popup" }, children);

const Polyline = ({ positions, pathOptions }) =>
  React.createElement("div", {
    "data-testid": "polyline",
    "data-positions": JSON.stringify(positions),
    "data-dash": pathOptions?.dashArray,
  });

module.exports = { MapContainer, TileLayer, Marker, Popup, Polyline };
