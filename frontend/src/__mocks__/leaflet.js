/**
 * Manual mock for the `leaflet` package.
 *
 * The real Leaflet tries to access DOM APIs (canvas, SVG, offsetWidth …) at
 * module-load time, which breaks Jest's jsdom environment. We replace it with
 * the bare minimum that HopMap.jsx needs:
 *
 *   - L.Icon.Default  (with _getIconUrl and mergeOptions)
 *   - L.divIcon()     (returns a plain object)
 *   - L.icon()        (returns a plain object)
 */

class IconDefault {
  constructor(options = {}) {
    this.options = options;
  }
  // HopMap.jsx deletes this property on the prototype
  _getIconUrl() {}
}

// Static mergeOptions — no-op is fine for tests
IconDefault.mergeOptions = () => {};
IconDefault.prototype._getIconUrl = function () {};

const L = {
  Icon: {
    Default: IconDefault,
  },
  divIcon: (options) => ({ _type: "divIcon", ...options }),
  icon: (options) => ({ _type: "icon", ...options }),
};

module.exports = L;
module.exports.default = L;
