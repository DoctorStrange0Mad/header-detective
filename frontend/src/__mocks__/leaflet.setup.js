/**
 * Runs before every test file (jest > setupFiles).
 * Provides the minimal window/global surface that Leaflet expects to find
 * in a browser environment. jsdom has most of it, but a few things need
 * explicit stubs so the module-level side-effects in our L mock don't throw.
 */

// Leaflet checks for SVG support
if (!window.SVGElement) {
  window.SVGElement = class SVGElement extends HTMLElement {};
}

// Leaflet checks navigator.userAgent
if (!window.navigator.userAgent) {
  Object.defineProperty(window.navigator, "userAgent", {
    value: "jest/jsdom",
    configurable: true,
  });
}
