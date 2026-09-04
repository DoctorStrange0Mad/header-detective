import React from "react";
import { createRoot } from "react-dom/client";
import "leaflet/dist/leaflet.css";
import DevPreview from "./DevPreview";

createRoot(document.getElementById("root")).render(<DevPreview />);
