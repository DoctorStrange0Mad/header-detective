// DEV PREVIEW ENTRY POINT — not part of the production dashboard.
// Mounts the DevPreview app for manual visual verification of HopMap.jsx.
import React from "react";
import { createRoot } from "react-dom/client";
import "leaflet/dist/leaflet.css";
import DevPreview from "./DevPreview";

createRoot(document.getElementById("root")).render(<DevPreview />);
