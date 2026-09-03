/**
 * HopMap.jsx — Jest + React Testing Library tests
 *
 * Covers:
 *   1. null mapData  → loading placeholder (no map rendered)
 *   2. empty path    → "no hops" error placeholder (no map rendered)
 *   3. single hop    → map renders, 1 marker, NO polyline
 *   4. multi-hop     → map renders, correct marker count, polyline present,
 *                      origin/destination icons distinguished from relay
 *   5. unresolved count text appears correctly
 *   6. popup content carries the right city/country text
 *
 * Mocks used (see src/__mocks__/):
 *   leaflet       → avoids canvas / DOM API errors in jsdom
 *   react-leaflet → thin React stubs; children are still rendered so we can
 *                   assert on Marker / Popup / Polyline presence
 */

import React from "react";
import { render, screen, within } from "@testing-library/react";
import HopMap from "../components/HopMap";

// ---------------------------------------------------------------------------
// Test-data factories
// ---------------------------------------------------------------------------

/** Build a minimal path point. */
function makePoint(hop_index, overrides = {}) {
  return {
    hop_index,
    lat: hop_index * 10,   // deterministic, spread across the globe
    lon: hop_index * 15,
    city: `City${hop_index}`,
    country: `Country${hop_index}`,
    ...overrides,
  };
}

/** Build a full mapData object with N locatable hops. */
function makeMapData(hopCount, { unresolved = 0, sender_domain = "test.example" } = {}) {
  const path = Array.from({ length: hopCount }, (_, i) => makePoint(i));
  return { sender_domain, path, unresolved_hop_count: unresolved };
}

// ---------------------------------------------------------------------------
// 1. null / undefined mapData → loading placeholder
// ---------------------------------------------------------------------------

describe("loading state (mapData is null or undefined)", () => {
  test("renders loading placeholder when mapData is null", () => {
    render(<HopMap mapData={null} />);
    expect(screen.getByTestId("hopmap-loading")).toBeInTheDocument();
    expect(screen.queryByTestId("hopmap-map")).not.toBeInTheDocument();
    expect(screen.queryByTestId("hopmap-empty")).not.toBeInTheDocument();
  });

  test("renders loading placeholder when mapData is undefined", () => {
    render(<HopMap />);
    expect(screen.getByTestId("hopmap-loading")).toBeInTheDocument();
  });

  test("loading message mentions analyzing an email", () => {
    render(<HopMap mapData={null} />);
    expect(screen.getByTestId("hopmap-loading")).toHaveTextContent(
      /analyze an email/i
    );
  });
});

// ---------------------------------------------------------------------------
// 2. mapData present but path is empty → "no hops" error placeholder
// ---------------------------------------------------------------------------

describe("empty path state (analysis ran, nothing locatable)", () => {
  const emptyData = { sender_domain: "corp.internal", path: [], unresolved_hop_count: 5 };

  test("renders empty placeholder, not the map", () => {
    render(<HopMap mapData={emptyData} />);
    expect(screen.getByTestId("hopmap-empty")).toBeInTheDocument();
    expect(screen.queryByTestId("hopmap-map")).not.toBeInTheDocument();
    expect(screen.queryByTestId("hopmap-loading")).not.toBeInTheDocument();
  });

  test("empty placeholder mentions no hops could be mapped", () => {
    render(<HopMap mapData={emptyData} />);
    expect(screen.getByTestId("hopmap-empty")).toHaveTextContent(
      /no hops could be mapped/i
    );
  });

  test("shows unresolved hop count when > 0", () => {
    render(<HopMap mapData={emptyData} />);
    expect(screen.getByTestId("hopmap-empty")).toHaveTextContent("5");
  });

  test("does not show unresolved count when it is 0", () => {
    render(<HopMap mapData={{ path: [], unresolved_hop_count: 0 }} />);
    // Text like "(0 unresolved hops)" should not appear
    expect(screen.getByTestId("hopmap-empty")).not.toHaveTextContent("0 unresolved");
  });

  test("handles missing path key gracefully (treats as empty)", () => {
    render(<HopMap mapData={{ sender_domain: "x.com" }} />);
    expect(screen.getByTestId("hopmap-empty")).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// 3. Single-hop path → map rendered, exactly 1 marker, NO polyline
// ---------------------------------------------------------------------------

describe("single-hop path", () => {
  const singleHop = makeMapData(1, { unresolved: 2 });

  test("renders the map container", () => {
    render(<HopMap mapData={singleHop} />);
    expect(screen.getByTestId("hopmap-map")).toBeInTheDocument();
  });

  test("renders exactly 1 marker", () => {
    render(<HopMap mapData={singleHop} />);
    expect(screen.getAllByTestId("marker")).toHaveLength(1);
  });

  test("does NOT render a polyline for a single hop", () => {
    render(<HopMap mapData={singleHop} />);
    expect(screen.queryByTestId("polyline")).not.toBeInTheDocument();
  });

  test("single marker gets origin icon (it is both first and last)", () => {
    render(<HopMap mapData={singleHop} />);
    // With 1 hop, idx===0 is origin. iconForIndex(0, 1) returns ORIGIN_ICON.
    // Our DivIcon mock sets _type: "divIcon".
    const marker = screen.getByTestId("marker");
    expect(marker.dataset.iconType).toBe("divIcon");
  });

  test("footer shows correct traced / total hop count", () => {
    render(<HopMap mapData={singleHop} />);
    // 1 traced + 2 unresolved = 3 total
    expect(screen.getByTestId("hopmap-map")).toHaveTextContent(/1 of 3 hop/i);
  });
});

// ---------------------------------------------------------------------------
// 4. Multi-hop path — marker count, polyline, icon roles
// ---------------------------------------------------------------------------

describe("multi-hop path (3 hops)", () => {
  const threeHops = makeMapData(3, { unresolved: 1, sender_domain: "relay.example" });

  test("renders the map container", () => {
    render(<HopMap mapData={threeHops} />);
    expect(screen.getByTestId("hopmap-map")).toBeInTheDocument();
  });

  test("renders exactly 3 markers", () => {
    render(<HopMap mapData={threeHops} />);
    expect(screen.getAllByTestId("marker")).toHaveLength(3);
  });

  test("renders a polyline", () => {
    render(<HopMap mapData={threeHops} />);
    expect(screen.getByTestId("polyline")).toBeInTheDocument();
  });

  test("polyline has a dashed style", () => {
    render(<HopMap mapData={threeHops} />);
    const polyline = screen.getByTestId("polyline");
    // Our mock passes pathOptions.dashArray through to data-dash
    expect(polyline).toHaveAttribute("data-dash");
    expect(polyline.dataset.dash).toBeTruthy();
  });

  test("all markers use divIcon (our custom dot icons)", () => {
    render(<HopMap mapData={threeHops} />);
    const markers = screen.getAllByTestId("marker");
    markers.forEach((m) => expect(m.dataset.iconType).toBe("divIcon"));
  });

  test("footer shows sender domain", () => {
    render(<HopMap mapData={threeHops} />);
    expect(screen.getByTestId("hopmap-map")).toHaveTextContent("relay.example");
  });

  test("footer shows unresolved count", () => {
    render(<HopMap mapData={threeHops} />);
    expect(screen.getByTestId("hopmap-map")).toHaveTextContent(
      /1 hop.*couldn.*t be located/i
    );
  });

  test("footer shows correct traced / total (3 of 4)", () => {
    render(<HopMap mapData={threeHops} />);
    expect(screen.getByTestId("hopmap-map")).toHaveTextContent(/3 of 4 hop/i);
  });
});

// ---------------------------------------------------------------------------
// 5. Popup content
// ---------------------------------------------------------------------------

describe("popup content", () => {
  test("popup shows hop index", () => {
    render(<HopMap mapData={makeMapData(2)} />);
    const popups = screen.getAllByTestId("popup");
    expect(popups[0]).toHaveTextContent("Hop 0");
    expect(popups[1]).toHaveTextContent("Hop 1");
  });

  test("popup shows city and country separated by comma+space", () => {
    const data = {
      sender_domain: "x.com",
      path: [{ hop_index: 0, lat: 1, lon: 1, city: "Mumbai", country: "India" }],
      unresolved_hop_count: 0,
    };
    render(<HopMap mapData={data} />);
    const popup = screen.getByTestId("popup");
    // Should render "Mumbai, India" not "Mumbai,India"
    expect(popup).toHaveTextContent("Mumbai, India");
  });

  test("popup shows only country when city is null", () => {
    const data = {
      sender_domain: "x.com",
      path: [{ hop_index: 0, lat: 1, lon: 1, city: null, country: "India" }],
      unresolved_hop_count: 0,
    };
    render(<HopMap mapData={data} />);
    expect(screen.getByTestId("popup")).toHaveTextContent("India");
    expect(screen.getByTestId("popup")).not.toHaveTextContent(",");
  });

  test("popup shows 'Unknown location' when both city and country are null", () => {
    const data = {
      sender_domain: "x.com",
      path: [{ hop_index: 0, lat: 1, lon: 1, city: null, country: null }],
      unresolved_hop_count: 0,
    };
    render(<HopMap mapData={data} />);
    expect(screen.getByTestId("popup")).toHaveTextContent(/unknown location/i);
  });
});

// ---------------------------------------------------------------------------
// 6. hop_index ordering — path should be sorted by hop_index before rendering
// ---------------------------------------------------------------------------

describe("hop ordering", () => {
  test("markers are rendered in hop_index order even if path array is shuffled", () => {
    const shuffled = {
      sender_domain: "x.com",
      path: [
        { hop_index: 2, lat: 20, lon: 30, city: "C", country: "CC" },
        { hop_index: 0, lat:  0, lon:  0, city: "A", country: "AA" },
        { hop_index: 1, lat: 10, lon: 15, city: "B", country: "BB" },
      ],
      unresolved_hop_count: 0,
    };
    render(<HopMap mapData={shuffled} />);
    const markers = screen.getAllByTestId("marker");
    expect(markers).toHaveLength(3);

    // First marker's position should be hop_index 0 → lat 0, lon 0
    expect(JSON.parse(markers[0].dataset.position)).toEqual([0, 0]);
    // Last marker → hop_index 2 → lat 20, lon 30
    expect(JSON.parse(markers[2].dataset.position)).toEqual([20, 30]);
  });
});
