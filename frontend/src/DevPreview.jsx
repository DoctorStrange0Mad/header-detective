/*
 * DEV PREVIEW — manual visual verification only.
 * NOT part of the production dashboard. NOT to be imported by Sagar's code.
 *
 * What it does:
 *   1. Fetches the hardcoded sample payload from GET /geo-preview/sample
 *      (proxied to http://localhost:8002 by vite.config.js)
 *   2. Renders HopMap.jsx with that payload so the map can be visually checked
 *      in a real browser before handoff to the rest of the team.
 *
 * To run:
 *   Terminal 1: uvicorn geo_preview:app --reload --port 8002
 *               (from the repo root, not this folder)
 *   Terminal 2: npm run dev
 *               (from this frontend/ folder)
 *   Browser:    http://localhost:5173
 */

import React, { useEffect, useState } from "react";
import HopMap from "./components/HopMap";

export default function DevPreview() {
  const [mapData, setMapData] = useState(null);   // null = loading
  const [fetchError, setFetchError] = useState(null);

  useEffect(() => {
    fetch("/geo-preview/sample")
      .then((res) => {
        if (!res.ok) {
          return res.json().then((body) => {
            throw new Error(
              body?.detail ?? `HTTP ${res.status} from /geo-preview/sample`
            );
          });
        }
        return res.json();
      })
      .then((data) => setMapData(data))
      .catch((err) => setFetchError(err.message));
  }, []);

  return (
    <div style={{ maxWidth: 900, margin: "2rem auto", fontFamily: "sans-serif" }}>
      {/* Header banner so it's obvious this is a dev tool */}
      <div
        style={{
          background: "#fef9c3",
          border: "1px solid #fde047",
          borderRadius: 6,
          padding: "0.6rem 1rem",
          marginBottom: "1rem",
          fontSize: "0.85rem",
          color: "#713f12",
        }}
      >
        <strong>Dev preview</strong> — fetching from{" "}
        <code>GET /geo-preview/sample</code> on localhost:8002. This page is for
        manual visual verification only; it is not part of the production
        dashboard.
      </div>

      <h2 style={{ marginBottom: "0.5rem" }}>
        Header Detective — Geo Visualizer
      </h2>

      {/* Fetch error state */}
      {fetchError && (
        <div
          style={{
            padding: "1rem",
            background: "#fef2f2",
            border: "1px solid #fca5a5",
            borderRadius: 6,
            color: "#7f1d1d",
            marginBottom: "1rem",
          }}
        >
          <strong>Could not load sample data.</strong>
          <br />
          {fetchError}
          <br />
          <br />
          Make sure the FastAPI server is running:
          <br />
          <code>uvicorn geo_preview:app --reload --port 8002</code>
          <br />
          (run from the repo root, not from the frontend/ folder)
        </div>
      )}

      {/* HopMap handles its own null (loading) and empty-path states */}
      {!fetchError && <HopMap mapData={mapData} />}
    </div>
  );
}
