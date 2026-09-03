/*
 * Header Detective - Geo Visualizer module (Jayshree, Member 2)
 *
 * Renders the relay-hop path on a world map using react-leaflet.
 * Consumes the `map` payload produced by backend/geo_lookup.py
 * (build_map_payload), e.g. from the /geo-preview or /analyze-geo endpoint.
 *
 * Setup:
 *   npm install react-leaflet leaflet
 *   // Add leaflet's CSS once in your App.jsx or index.js:
 *   import "leaflet/dist/leaflet.css";
 *
 * Usage:
 *   <HopMap mapData={response.map} />           // data ready
 *   <HopMap mapData={null} />                   // still loading
 *   <HopMap mapData={{ path: [], ... }} />      // tried, nothing locatable
 */

import React from "react";
import {
  MapContainer,
  TileLayer,
  Marker,
  Polyline,
  Popup,
} from "react-leaflet";
import L from "leaflet";

// ---------------------------------------------------------------------------
// Leaflet default-icon fix
// Webpack / Vite don't bundle the image references inside L.Icon.Default
// correctly. This is the canonical workaround.
// ---------------------------------------------------------------------------
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl:
    "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png",
  iconUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png",
  shadowUrl:
    "https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png",
});

// ---------------------------------------------------------------------------
// Marker icons
//
// L.Icon.Default does NOT support a `className` constructor option — it is
// silently dropped, so all three markers look identical.
//
// We use L.DivIcon instead: tiny coloured circles rendered purely in CSS,
// no external image files needed → works fully offline during the live demo.
//
//   ORIGIN      green  ●   first hop
//   DEST        red    ●   last hop
//   INTERMEDIATE  grey ●   everything in between
// ---------------------------------------------------------------------------
function makeDotIcon(color, label) {
  return L.divIcon({
    className: "", // prevent Leaflet injecting its own background/border styles
    html: `<span
      title="${label}"
      style="
        display:block;
        width:14px;
        height:14px;
        border-radius:50%;
        background:${color};
        border:2px solid #fff;
        box-shadow:0 0 0 1.5px ${color};
      "
    ></span>`,
    iconSize: [14, 14],
    iconAnchor: [7, 7],   // centre of the circle sits on the coordinate
    popupAnchor: [0, -10],
  });
}

const ORIGIN_ICON = makeDotIcon("#22c55e", "Origin");        // green
const DEST_ICON   = makeDotIcon("#ef4444", "Destination");   // red
const HOP_ICON    = makeDotIcon("#94a3b8", "Relay hop");     // slate-grey

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Return Leaflet LatLngBounds corners for a set of path points. */
function computeBounds(path) {
  if (path.length === 0) return null;
  const lats = path.map((p) => p.lat);
  const lons = path.map((p) => p.lon);
  return [
    [Math.min(...lats), Math.min(...lons)],
    [Math.max(...lats), Math.max(...lons)],
  ];
}

/** Pick the right icon for a point based on its position in the sorted path. */
function iconForIndex(idx, total) {
  if (idx === 0) return ORIGIN_ICON;
  if (idx === total - 1) return DEST_ICON;
  return HOP_ICON;
}

/** Human-readable location string for a hop popup. */
function formatLocation(hop) {
  const parts = [hop.city, hop.country].filter(Boolean);
  return parts.length > 0 ? parts.join(", ") : "Unknown location";
}

// ---------------------------------------------------------------------------
// Loading / error placeholder (shared style)
// ---------------------------------------------------------------------------
function MapPlaceholder({ children, testId }) {
  return (
    <div
      data-testid={testId}
      style={{
        padding: "1.25rem",
        borderRadius: "8px",
        background: "#f8fafc",
        border: "1px solid #e2e8f0",
        color: "#64748b",
        fontSize: "0.9rem",
      }}
    >
      {children}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------
export default function HopMap({ mapData }) {
  // ── State 1: no data at all — analysis hasn't run yet ──────────────────
  if (mapData === null || mapData === undefined) {
    return (
      <MapPlaceholder testId="hopmap-loading">
        No map data yet — analyze an email first.
      </MapPlaceholder>
    );
  }

  const { path, unresolved_hop_count = 0, sender_domain } = mapData;

  // ── State 2: analysis ran but nothing was locatable ─────────────────────
  if (!path || path.length === 0) {
    return (
      <MapPlaceholder testId="hopmap-empty">
        <strong>No hops could be mapped.</strong>
        <br />
        All IP addresses in this email were private, missing, or not found in
        the geolocation database — this is normal for emails that stayed entirely
        inside a corporate or ISP network.
        {unresolved_hop_count > 0 && (
          <span>
            {" "}
            ({unresolved_hop_count} unresolved hop
            {unresolved_hop_count !== 1 ? "s" : ""})
          </span>
        )}
      </MapPlaceholder>
    );
  }

  // ── State 3: we have at least one locatable hop — render the map ────────
  const orderedPath = [...path].sort((a, b) => a.hop_index - b.hop_index);
  const polylinePositions = orderedPath.map((p) => [p.lat, p.lon]);
  const bounds = computeBounds(orderedPath);
  const totalHops = orderedPath.length + unresolved_hop_count;

  return (
    <div data-testid="hopmap-map">
      <MapContainer
        bounds={bounds}
        boundsOptions={{ padding: [40, 40] }}
        style={{ height: "500px", width: "100%", borderRadius: "8px" }}
        scrollWheelZoom={true}
      >
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />

        {/* Only draw the line when there are 2+ points — 1 point is a no-op
            in Leaflet but we guard it to be explicit and testable. */}
        {orderedPath.length >= 2 && (
          <Polyline
            positions={polylinePositions}
            pathOptions={{ color: "#d84f3e", weight: 2, dashArray: "6, 8" }}
          />
        )}

        {orderedPath.map((hop, idx) => (
          <Marker
            key={hop.hop_index}
            position={[hop.lat, hop.lon]}
            icon={iconForIndex(idx, orderedPath.length)}
          >
            <Popup>
              <strong>Hop {hop.hop_index}</strong>
              <br />
              {formatLocation(hop)}
            </Popup>
          </Marker>
        ))}
      </MapContainer>

      {/* Footer legend + unresolved count */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "1rem",
          flexWrap: "wrap",
          marginTop: "0.5rem",
          fontSize: "0.8rem",
          color: "#64748b",
        }}
      >
        {/* Dot legend */}
        <span style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          <span style={{ width: 10, height: 10, borderRadius: "50%", background: "#22c55e", display: "inline-block" }} />
          Origin
        </span>
        <span style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          <span style={{ width: 10, height: 10, borderRadius: "50%", background: "#94a3b8", display: "inline-block" }} />
          Relay
        </span>
        <span style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          <span style={{ width: 10, height: 10, borderRadius: "50%", background: "#ef4444", display: "inline-block" }} />
          Destination
        </span>

        {/* Hop count summary */}
        <span style={{ marginLeft: "auto" }}>
          Traced {orderedPath.length} of {totalHops} hop
          {totalHops !== 1 ? "s" : ""} for{" "}
          <strong>{sender_domain || "unknown sender"}</strong>.
          {unresolved_hop_count > 0 && (
            <span>
              {" "}
              {unresolved_hop_count} hop
              {unresolved_hop_count !== 1 ? "s" : ""} couldn&apos;t be located
              (internal/private network).
            </span>
          )}
        </span>
      </div>
    </div>
  );
}
