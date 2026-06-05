(function () {
  // ═══════════════════════════════════════════════════════════════
  // SECTION 0: Anti-bot bail-out
  // If we detect an anti-bot system, exit immediately to avoid
  // breaking challenge scripts. These systems rely on unpatched
  // browser APIs and our patches would cause false positives or
  // block challenge completion.
  // ═══════════════════════════════════════════════════════════════
  try {
    // Cloudflare challenge page
    if (window._cf_chl_opt) return;
    if (window._cf_chl_ctx) return;
    if (window.__CF$cv$params) return;
    if (window.turnstile) return;
    if (window.cloudflare) return;
    // Akamai Bot Manager
    if (window.bmak) return;
    // PerimeterX / HUMAN
    if (window._pxAppId) return;
    if (window._pxVid) return;
    // DataDome
    if (window.DataDome) return;
    if (window.ddCaptcha) return;
    // Cookie-based detection (Kasada reese84, Imperva incap_ses_*)
    try {
      var cookies = document.cookie;
      if (/\breese84=/.test(cookies)) return;
      if (/\bincap_ses_/.test(cookies)) return;
      if (/\bvisid_incap_/.test(cookies)) return;
      if (/\b_cf_bm=/.test(cookies)) return;
    } catch (e) { /* document.cookie may not be accessible */ }
    // DOM-based detection (checked lazily since document may not be ready)
    // Cloudflare Turnstile widget
    if (document.querySelector && document.querySelector(".cf-turnstile")) return;
    if (document.querySelector && document.querySelector('[name="cf-turnstile-response"]')) return;
    // Kasada polymorphic script (UUID in path)
    if (document.querySelector && document.querySelector('script[src*="149e9513-01fa-4fb0-aad4-566afd725d1b"]')) return;
    // Akamai sensor script
    if (document.querySelector && document.querySelector('script[src*="/akam/"]')) return;
    if (document.querySelector && document.querySelector('script[src*="_bm"]')) return;
    // PerimeterX script
    if (document.querySelector && document.querySelector('script[src*="px-cdn.net"]')) return;
    if (document.querySelector && document.querySelector('script[src*="perimeterx.net"]')) return;
    // DataDome script
    if (document.querySelector && document.querySelector('script[src*="datadome.co"]')) return;
    if (document.querySelector && document.querySelector('script[src*="captcha-delivery.com"]')) return;
    // Cloudflare challenge page title
    if (document.title === "Just a moment...") return;
  } catch (e) { /* bail-out checks must never throw */ }

  // ═══════════════════════════════════════════════════════════════
  // SECTION 1: Function.prototype.toString spoofing
  // Many anti-debug scripts detect patched functions by checking
  // if toString() returns [native code]. We maintain a WeakMap
  // of patched→native-string mappings so all our patches appear
  // as unmodified native code.
  // ═══════════════════════════════════════════════════════════════
  var _origFnToString = Function.prototype.toString;
  var _nativeStrings = new WeakMap();

  function markAsNative(fn, name) {
    _nativeStrings.set(fn, "function " + name + "() { [native code] }");
    return fn;
  }

  var _patchedToString = markAsNative(function toString() {
    var stub = _nativeStrings.get(this);
    if (stub !== undefined) return stub;
    return _origFnToString.call(this);
  }, "toString");

  Object.defineProperty(Function.prototype, "toString", {
    value: _patchedToString,
    writable: true,
    configurable: true,
    enumerable: false,
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION 2: Debugger injection prevention
  // Patches eval, Function constructor, setTimeout, setInterval,
  // requestAnimationFrame, and queueMicrotask to neutralize
  // "debugger" statements injected via these APIs.
  // ═══════════════════════════════════════════════════════════════

  // --- Helper: detect "debugger" keyword in strings with obfuscation ---
  function containsDebugger(code) {
    if (typeof code !== "string") return false;
    // Direct literal check
    if (code.indexOf("debugger") !== -1) return true;
    // Hex escapes: \x64ebugger (d = \x64)
    try {
      var decoded = code
        .replace(/\\x([0-9a-fA-F]{2})/g, function (_, h) { return String.fromCharCode(parseInt(h, 16)); })
        .replace(/\\u([0-9a-fA-F]{4})/g, function (_, h) { return String.fromCharCode(parseInt(h, 16)); });
      if (decoded.indexOf("debugger") !== -1) return true;
    } catch (e) { /* decoding failed, skip */ }
    // Base64: try atob on the entire string
    try {
      var b64 = window.atob(code);
      if (b64.indexOf("debugger") !== -1) return true;
    } catch (e) { /* not valid base64, skip */ }
    return false;
  }

  // --- 2a. Kill eval("debugger") — including indirect eval and obfuscation ---
  var _eval = window.eval;
  var _patchedEval = markAsNative(function eval(code) {
    if (containsDebugger(code)) return undefined;
    return _eval.call(this, code);
  }, "eval");

  Object.defineProperty(window, "eval", {
    value: _patchedEval,
    writable: true,
    configurable: true,
    enumerable: false,
  });

  // --- 2b. Kill Function("debugger")() — multiple layers ---
  var _Fn = window.Function;

  function SafeFunction() {
    var args = Array.prototype.slice.call(arguments);
    for (var i = 0; i < args.length; i++) {
      if (containsDebugger(args[i])) {
        return function () { };
      }
    }
    return _Fn.apply(this, args);
  }

  // Inherit prototype chain so instanceof checks still work
  SafeFunction.prototype = Object.create(_Fn.prototype);
  Object.defineProperty(SafeFunction.prototype, "constructor", {
    value: SafeFunction,
    writable: true,
    configurable: true,
    enumerable: false,
  });

  markAsNative(SafeFunction, "Function");
  Object.defineProperty(window, "Function", {
    value: SafeFunction,
    writable: true,
    configurable: true,
    enumerable: false,
  });

  // Patch .constructor on function instances — configurable:true per AGENTS.md
  Object.defineProperty(Function.prototype, "constructor", {
    get: function () { return SafeFunction; },
    set: function () { },
    configurable: true,
    enumerable: false,
  });

  // --- 2c. Kill setTimeout with debugger ---
  var _st = window.setTimeout;
  var _noop = function () { };

  var _patchedSetTimeout = markAsNative(function setTimeout(fn, ms) {
    var s = typeof fn === "function" ? fn.toString() : String(fn);
    if (containsDebugger(s)) {
      // Return a realistic timer ID by scheduling and immediately clearing a no-op
      var id = _st.call(window, _noop, 0);
      window.clearTimeout(id);
      return id;
    }
    return _st.apply(this, arguments);
  }, "setTimeout");

  Object.defineProperty(window, "setTimeout", {
    value: _patchedSetTimeout,
    writable: true,
    configurable: true,
    enumerable: false,
  });

  // --- 2d. Kill setInterval with debugger (improved: realistic timer ID, removed "eval" blocklist) ---
  var _si = window.setInterval;

  var _patchedSetInterval = markAsNative(function setInterval(fn, ms) {
    var s = typeof fn === "function" ? fn.toString() : String(fn);
    if (containsDebugger(s)) {
      // Return a realistic timer ID by scheduling and clearing a no-op
      var id = _si.call(window, _noop, 0);
      window.clearInterval(id);
      return id;
    }
    return _si.apply(this, arguments);
  }, "setInterval");

  Object.defineProperty(window, "setInterval", {
    value: _patchedSetInterval,
    writable: true,
    configurable: true,
    enumerable: false,
  });

  // --- 2e. Kill requestAnimationFrame with debugger ---
  var _raf = window.requestAnimationFrame;

  var _patchedRAF = markAsNative(function requestAnimationFrame(fn) {
    if (typeof fn === "function" && containsDebugger(fn.toString())) {
      return _raf.call(window, _noop);
    }
    return _raf.apply(this, arguments);
  }, "requestAnimationFrame");

  Object.defineProperty(window, "requestAnimationFrame", {
    value: _patchedRAF,
    writable: true,
    configurable: true,
    enumerable: false,
  });

  // --- 2f. Kill queueMicrotask with debugger ---
  var _qmt = window.queueMicrotask;

  var _patchedQMT = markAsNative(function queueMicrotask(fn) {
    if (typeof fn === "function" && containsDebugger(fn.toString())) {
      return; // silently drop
    }
    return _qmt.apply(this, arguments);
  }, "queueMicrotask");

  Object.defineProperty(window, "queueMicrotask", {
    value: _patchedQMT,
    writable: true,
    configurable: true,
    enumerable: false,
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION 3: DevTools detection prevention
  // Neutralizes side-channel detection methods that infer
  // DevTools state from window dimensions, console behavior,
  // custom formatters, or navigator properties.
  // ═══════════════════════════════════════════════════════════════

  // --- 3a. Window size getter override ---
  // Hide DevTools panel dimensions so outerWidth/outerHeight
  // always appear close to innerWidth/innerHeight
  var _origOuterWidth = Object.getOwnPropertyDescriptor(window, "outerWidth");
  var _origOuterHeight = Object.getOwnPropertyDescriptor(window, "outerHeight");

  if (_origOuterWidth && _origOuterWidth.get) {
    Object.defineProperty(window, "outerWidth", {
      get: markAsNative(function outerWidth() {
        return window.innerWidth + 16;
      }, "get outerWidth"),
      configurable: true,
      enumerable: true,
    });
  }

  if (_origOuterHeight && _origOuterHeight.get) {
    Object.defineProperty(window, "outerHeight", {
      get: markAsNative(function outerHeight() {
        return window.innerHeight + 88;
      }, "get outerHeight"),
      configurable: true,
      enumerable: true,
    });
  }

  // --- 3b. Console full interception ---
  // During page load: disable all console methods to prevent
  // timing-based and getter-trap detection. After load: restore
  // but with argument serialization to prevent getter traps.
  // console.clear stays permanently rate-limited.

  var _consoleMethods = ["log", "table", "clear", "debug", "info", "warn",
    "error", "dir", "trace", "time", "timeEnd", "count", "assert",
    "group", "groupEnd", "profile", "profileEnd"];
  var _consoleOrig = {};

  // Save all originals
  for (var _mi = 0; _mi < _consoleMethods.length; _mi++) {
    var _m = _consoleMethods[_mi];
    if (typeof console[_m] === "function") {
      _consoleOrig[_m] = console[_m];
    }
  }

  // Deep-serialize an argument to prevent getter/toString traps
  function safeArg(arg) {
    if (arg === null || arg === undefined) return arg;
    var t = typeof arg;
    if (t === "string" || t === "number" || t === "boolean") return arg;
    if (t === "function") {
      try { return arg.toString(); } catch (e) { return "[Function]"; }
    }
    // DOM elements — return a plain string representation
    if (arg instanceof Element || arg instanceof HTMLElement) {
      try { return arg.outerHTML; } catch (e) { return "[HTMLElement]"; }
    }
    if (arg instanceof Node) {
      try { return arg.nodeName; } catch (e) { return "[Node]"; }
    }
    // RegExp with custom toString — return the source string
    if (arg instanceof RegExp) {
      try { return arg.source; } catch (e) { return "[RegExp]"; }
    }
    // Date with custom toString — return ISO string from valueOf
    if (arg instanceof Date) {
      try { return arg.valueOf(); } catch (e) { return "[Date]"; }
    }
    // Objects (including those with custom getters) — shallow JSON serialization
    if (t === "object") {
      try {
        return JSON.parse(JSON.stringify(arg, function (key, val) {
          if (typeof val === "function") return val.toString();
          if (val instanceof Element || val instanceof HTMLElement) return "[HTMLElement]";
          if (val instanceof RegExp) return val.source;
          if (val instanceof Date) return val.valueOf();
          return val;
        }));
      } catch (e) {
        return "[Object]";
      }
    }
    return arg;
  }

  // Apply safe serialization to all arguments
  function safeArgs(args) {
    var out = [];
    for (var i = 0; i < args.length; i++) {
      out[i] = safeArg(args[i]);
    }
    return out;
  }

  // Disable all console methods during page load
  for (var _mi2 = 0; _mi2 < _consoleMethods.length; _mi2++) {
    var _m2 = _consoleMethods[_mi2];
    if (_consoleOrig[_m2]) {
      console[_m2] = function () { };
    }
  }

  // console.clear rate-limiting state
  var _lastClearTime = 0;
  var _clearMinInterval = 30000; // 30 seconds minimum between clears

  // Restore console after page load with getter-trap protection
  window.addEventListener("load", function () {
    setTimeout(function () {
      for (var _mi3 = 0; _mi3 < _consoleMethods.length; _mi3++) {
        var _m3 = _consoleMethods[_mi3];
        if (!_consoleOrig[_m3]) continue;

        if (_m3 === "clear") {
          // console.clear stays permanently rate-limited
          console.clear = markAsNative(function clear() {
            var now = Date.now();
            if (now - _lastClearTime < _clearMinInterval) return;
            _lastClearTime = now;
            return _consoleOrig.clear.apply(console, safeArgs(arguments));
          }, "clear");
        } else {
          // All other methods: serialize arguments to prevent getter traps
          (function (methodName, origFn) {
            console[methodName] = markAsNative(function () {
              return origFn.apply(console, safeArgs(arguments));
            }, methodName);
          })(_m3, _consoleOrig[_m3]);
        }
      }

      console.log("%c[Anti-Debugger Bypass] DevTools protection disabled. Console restored.", "color: #4D9B52; font-weight: bold;");
    }, 3000);
  });

  // --- 3c. DevTools Custom Formatter detection ---
  // Prevent scripts from registering custom formatters that detect
  // when DevTools inspects logged objects
  try {
    Object.defineProperty(window, "devtoolsFormatters", {
      value: [],
      writable: false,
      configurable: false,
      enumerable: true,
    });
  } catch (e) { /* already defined as non-configurable */ }

  // Also block the Symbol-based devtoolsFormatters key
  try {
    var _dtfSymbol = Symbol.for("devtoolsFormatters");
    Object.defineProperty(window, _dtfSymbol, {
      value: [],
      writable: false,
      configurable: false,
      enumerable: true,
    });
  } catch (e) { /* already defined */ }

  // --- 3d. navigator.webdriver override ---
  // Anti-bot systems check navigator.webdriver === true to detect
  // automated browsers. Override to return false.
  try {
    Object.defineProperty(Navigator.prototype, "webdriver", {
      get: markAsNative(function webdriver() {
        return false;
      }, "get webdriver"),
      configurable: true,
      enumerable: true,
    });
  } catch (e) { /* may not be configurable in some browsers */ }

  // ═══════════════════════════════════════════════════════════════
  // SECTION 4: Redirect prevention
  // Blocks hostile redirects used by anti-debug scripts to kick
  // users off the page when DevTools is detected.
  // ═══════════════════════════════════════════════════════════════

  // Hostile redirect targets that anti-debug scripts commonly use
  var _hostileRedirectTargets = {
    "/": true,
    "about:blank": true,
    "": true,
    "#": true,
  };

  // --- 4a. Block location.href redirect ---
  var _locDesc = Object.getOwnPropertyDescriptor(Location.prototype, "href");
  if (_locDesc) {
    Object.defineProperty(Location.prototype, "href", {
      get: _locDesc.get,
      set: markAsNative(function href(val) {
        var strVal = String(val);
        // Block known hostile redirect targets
        if (_hostileRedirectTargets[strVal] && this.pathname !== "/") return;
        // Block redirect to about:blank
        if (strVal === "about:blank") return;
        return _locDesc.set.call(this, val);
      }, "set href"),
      configurable: true,
      enumerable: true,
    });
  }

  // --- 4b. Block location.replace() ---
  var _origReplace = Location.prototype.replace;
  Location.prototype.replace = markAsNative(function replace(url) {
    var strUrl = String(url);
    if (_hostileRedirectTargets[strUrl] && this.pathname !== "/") return;
    if (strUrl === "about:blank") return;
    return _origReplace.call(this, url);
  }, "replace");

  // --- 4c. Block location.assign() ---
  var _origAssign = Location.prototype.assign;
  Location.prototype.assign = markAsNative(function assign(url) {
    var strUrl = String(url);
    if (_hostileRedirectTargets[strUrl] && this.pathname !== "/") return;
    if (strUrl === "about:blank") return;
    return _origAssign.call(this, url);
  }, "assign");

// NOTE: location.reload() is NOT patched — legitimate usage is too common

// --- Domain-seeded PRNG (FNV-1a → LCG) ---
var _domainSeed = (function () {
  var h = 0x811c9dc5;
  var domain = window.location.hostname || "localhost";
  for (var i = 0; i < domain.length; i++) {
    h ^= domain.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
})();
var _prngState = _domainSeed;
function seededRandom() {
  _prngState = (_prngState * 1664525 + 1013904223) & 0xffffffff;
  return (_prngState >>> 0) / 0x100000000;
}
var _jitterX = Math.floor(seededRandom() * 5) - 2;
var _jitterY = Math.floor(seededRandom() * 5) - 2;

// ═══════════════════════════════════════════════════════════════
// SECTION 6: Privacy — Device fingerprinting
// Normalize or spoof browser APIs that expose unique device
// characteristics used for fingerprinting: hardware concurrency,
// memory, battery, plugins, screen dimensions, speech, media
// devices, and more.
// ═══════════════════════════════════════════════════════════════

// --- 6a. Navigator patches ---

// hardwareConcurrency → 4
Object.defineProperty(Navigator.prototype, "hardwareConcurrency", {
  get: markAsNative(function hardwareConcurrency() { return 4; }, "get hardwareConcurrency"),
  configurable: true,
  enumerable: true,
});

// deviceMemory → 8
Object.defineProperty(Navigator.prototype, "deviceMemory", {
  get: markAsNative(function deviceMemory() { return 8; }, "get deviceMemory"),
  configurable: true,
  enumerable: true,
});

// getBattery → fake battery object
Object.defineProperty(Navigator.prototype, "getBattery", {
  value: markAsNative(function getBattery() {
    return Promise.resolve({
      charging: true,
      chargingTime: 0,
      dischargingTime: Infinity,
      level: 1,
      addEventListener: markAsNative(function addEventListener() {}, "addEventListener"),
      removeEventListener: markAsNative(function removeEventListener() {}, "removeEventListener"),
      dispatchEvent: markAsNative(function dispatchEvent() { return true; }, "dispatchEvent"),
    });
  }, "getBattery"),
  writable: true,
  configurable: true,
  enumerable: true,
});

// maxTouchPoints → 0
Object.defineProperty(Navigator.prototype, "maxTouchPoints", {
  get: markAsNative(function maxTouchPoints() { return 0; }, "get maxTouchPoints"),
  configurable: true,
  enumerable: true,
});

// platform → "Win32"
Object.defineProperty(Navigator.prototype, "platform", {
  get: markAsNative(function platform() { return "Win32"; }, "get platform"),
  configurable: true,
  enumerable: true,
});

// plugins → empty PluginArray-like (cached singleton)
var _emptyPA = Object.create(PluginArray.prototype);
Object.defineProperty(_emptyPA, "length", {
  get: markAsNative(function length() { return 0; }, "get length"),
  configurable: true,
  enumerable: true,
});
_emptyPA.item = markAsNative(function item() { return null; }, "item");
_emptyPA.namedItem = markAsNative(function namedItem() { return null; }, "namedItem");
_emptyPA.refresh = markAsNative(function refresh() {}, "refresh");

Object.defineProperty(Navigator.prototype, "plugins", {
  get: markAsNative(function plugins() { return _emptyPA; }, "get plugins"),
  configurable: true,
  enumerable: true,
});

// mimeTypes → empty MimeTypeArray-like (cached singleton)
var _emptyMTA = Object.create(MimeTypeArray.prototype);
Object.defineProperty(_emptyMTA, "length", {
  get: markAsNative(function length() { return 0; }, "get length"),
  configurable: true,
  enumerable: true,
});
_emptyMTA.item = markAsNative(function item() { return null; }, "item");
_emptyMTA.namedItem = markAsNative(function namedItem() { return null; }, "namedItem");

Object.defineProperty(Navigator.prototype, "mimeTypes", {
  get: markAsNative(function mimeTypes() { return _emptyMTA; }, "get mimeTypes"),
  configurable: true,
  enumerable: true,
});

// getGamepads → []
Object.defineProperty(Navigator.prototype, "getGamepads", {
  value: markAsNative(function getGamepads() { return []; }, "getGamepads"),
  writable: true,
  configurable: true,
  enumerable: true,
});

// connection → Proxy wrapping real connection
var _origConnDesc = Object.getOwnPropertyDescriptor(Navigator.prototype, "connection");
Object.defineProperty(Navigator.prototype, "connection", {
  get: markAsNative(function connection() {
    var _target = _origConnDesc && _origConnDesc.get ? _origConnDesc.get.call(navigator) : {};
    try {
      return new Proxy(_target, {
        get: function (target, prop) {
          if (prop === "effectiveType") return "4g";
          if (prop === "downlink") return 10;
          if (prop === "rtt") return 50;
          if (prop === "saveData") return false;
          var val = target[prop];
          return typeof val === "function" ? val.bind(target) : val;
        },
      });
    } catch (e) {
      return _target;
    }
  }, "get connection"),
  configurable: true,
  enumerable: true,
});

// clipboard.readText → Promise.resolve("")
if (navigator.clipboard && navigator.clipboard.readText) {
  var _origClipboardDesc = Object.getOwnPropertyDescriptor(Navigator.prototype, "clipboard");
  Object.defineProperty(Navigator.prototype, "clipboard", {
    get: markAsNative(function clipboard() {
      var _target = _origClipboardDesc && _origClipboardDesc.get ? _origClipboardDesc.get.call(navigator) : {};
      try {
        return new Proxy(_target, {
          get: function (target, prop) {
            if (prop === "readText") {
              return markAsNative(function readText() { return Promise.resolve(""); }, "readText");
            }
            var val = target[prop];
            return typeof val === "function" ? val.bind(target) : val;
          },
        });
      } catch (e) {
        return _target;
      }
    }, "get clipboard"),
    configurable: true,
    enumerable: true,
  });
}

// userAgentData.getHighEntropyValues → generic Chrome UA data
if (navigator.userAgentData && NavigatorUAData.prototype.getHighEntropyValues) {
  var _origGHEV = NavigatorUAData.prototype.getHighEntropyValues;
  NavigatorUAData.prototype.getHighEntropyValues = markAsNative(function getHighEntropyValues(hints) {
    return _origGHEV.call(this, hints).then(function (data) {
      return {
        brands: data.brands,
        mobile: false,
        platform: "Windows",
        architecture: "x86",
        bitness: "64",
        model: "",
        uaFullVersion: "130.0.6723.0",
        fullVersionList: [
          { brand: "Chromium", version: "130.0.6723.0" },
          { brand: "Google Chrome", version: "130.0.6723.0" },
        ],
        wow64: false,
      };
    });
  }, "getHighEntropyValues");
}

// StorageManager.prototype.estimate → fake quota
if (navigator.storage && navigator.storage.estimate && StorageManager.prototype.estimate) {
  StorageManager.prototype.estimate = markAsNative(function estimate() {
    return Promise.resolve({ usage: 0, quota: 1073741824 });
  }, "estimate");
}

// --- 6b. Screen patches ---

Object.defineProperty(Screen.prototype, "width", {
  get: markAsNative(function width() { return 1920; }, "get width"),
  configurable: true,
  enumerable: true,
});

Object.defineProperty(Screen.prototype, "height", {
  get: markAsNative(function height() { return 1080; }, "get height"),
  configurable: true,
  enumerable: true,
});

Object.defineProperty(Screen.prototype, "availWidth", {
  get: markAsNative(function availWidth() { return 1920; }, "get availWidth"),
  configurable: true,
  enumerable: true,
});

Object.defineProperty(Screen.prototype, "availHeight", {
  get: markAsNative(function availHeight() { return 1040; }, "get availHeight"),
  configurable: true,
  enumerable: true,
});

Object.defineProperty(Screen.prototype, "colorDepth", {
  get: markAsNative(function colorDepth() { return 24; }, "get colorDepth"),
  configurable: true,
  enumerable: true,
});

Object.defineProperty(Screen.prototype, "pixelDepth", {
  get: markAsNative(function pixelDepth() { return 24; }, "get pixelDepth"),
  configurable: true,
  enumerable: true,
});

// devicePixelRatio → 1
var _origDPR = Object.getOwnPropertyDescriptor(window, "devicePixelRatio");
if (_origDPR && _origDPR.get) {
  Object.defineProperty(window, "devicePixelRatio", {
    get: markAsNative(function devicePixelRatio() { return 1; }, "get devicePixelRatio"),
    configurable: true,
    enumerable: true,
  });
}

// --- 6c. Speech / Storage / Media patches ---

// speechSynthesis.getVoices → []
if (window.speechSynthesis && SpeechSynthesis.prototype.getVoices) {
  SpeechSynthesis.prototype.getVoices = markAsNative(function getVoices() {
    return [];
  }, "getVoices");
}

// MediaDevices.prototype.enumerateDevices → 2 generic devices
if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
  MediaDevices.prototype.enumerateDevices = markAsNative(function enumerateDevices() {
    return Promise.resolve([
      { deviceId: "", groupId: "", kind: "audioinput", label: "" },
      { deviceId: "", groupId: "", kind: "videoinput", label: "" },
    ]);
  }, "enumerateDevices");
}

// ═══════════════════════════════════════════════════════════════
// SECTION 7: Privacy — Visibility & cross-tab tracking
// Prevent pages from detecting tab visibility changes and
// isolate BroadcastChannel to prevent cross-tab communication
// used for tracking or coordination.
// ═══════════════════════════════════════════════════════════════

  // --- 7a. Document visibility patches ---
  // Override hidden/visibilityState to always report "visible", and
  // suppress the visibilitychange event so page scripts never see a
  // contradiction between the event firing and the getter values.

  Object.defineProperty(Document.prototype, "hidden", {
    get: markAsNative(function hidden() { return false; }, "get hidden"),
    configurable: true,
    enumerable: true,
  });

  Object.defineProperty(Document.prototype, "visibilityState", {
    get: markAsNative(function visibilityState() { return "visible"; }, "get visibilityState"),
    configurable: true,
    enumerable: true,
  });

  Document.prototype.hasFocus = markAsNative(function hasFocus() {
    return true;
  }, "hasFocus");

  // Block visibilitychange events from reaching page scripts.
  // Without this, the browser fires the event on actual tab switch
  // but our getters still return "visible" — creating contradictory
  // state that breaks sites like DuckDuckGo that rely on the event
  // to manage rendering lifecycle.
  document.addEventListener("visibilitychange", function (e) {
    e.stopImmediatePropagation();
  }, true);

// --- 7b. BroadcastChannel namespace isolation ---

if (window.BroadcastChannel) {
  var _origBC = window.BroadcastChannel;
  var _bcPrefix = "_adb" + (_domainSeed >>> 0).toString(36) + ":";

  function _patchedBC(name) {
    return new _origBC(_bcPrefix + name);
  }
  _patchedBC.prototype = _origBC.prototype;

  Object.defineProperty(window, "BroadcastChannel", {
    value: markAsNative(_patchedBC, "BroadcastChannel"),
    writable: true,
    configurable: true,
    enumerable: false,
  });
}

// --- 7c. window.name reset ---
window.name = "";

// ═══════════════════════════════════════════════════════════════
// SECTION 8: Privacy — Canvas & Audio noise
// Add domain-seeded noise to canvas image data and audio buffers
// to defeat fingerprinting while preserving visible content.
// Spoof WebGL renderer/vendor strings.
// ═══════════════════════════════════════════════════════════════

// --- 8a. Canvas noise (offscreen canvases only) ---

var _origToDataURL = HTMLCanvasElement.prototype.toDataURL;
var _origToBlob = HTMLCanvasElement.prototype.toBlob;
var _origGetImageData = CanvasRenderingContext2D.prototype.getImageData;

function _isOffscreen(canvas) {
  try { return !document.body.contains(canvas); } catch (e) { return true; }
}

function _addCanvasNoise(imageData) {
  var data = imageData.data;
  _prngState = _domainSeed;
  for (var i = 0; i < data.length; i += 128) {
    if (seededRandom() > 0.5) data[i] ^= 1;
    if (seededRandom() > 0.5) data[i + 1] ^= 1;
    if (seededRandom() > 0.5) data[i + 2] ^= 1;
  }
}

HTMLCanvasElement.prototype.toDataURL = markAsNative(function toDataURL() {
  if (!_isOffscreen(this)) return _origToDataURL.apply(this, arguments);
  var ctx = this.getContext("2d");
  if (!ctx) return _origToDataURL.apply(this, arguments);
  var imgData = _origGetImageData.call(ctx, 0, 0, this.width, this.height);
  _addCanvasNoise(imgData);
  var clone = document.createElement("canvas");
  clone.width = this.width;
  clone.height = this.height;
  var cloneCtx = clone.getContext("2d");
  cloneCtx.putImageData(imgData, 0, 0);
  return _origToDataURL.apply(clone, arguments);
}, "toDataURL");

HTMLCanvasElement.prototype.toBlob = markAsNative(function toBlob(callback) {
  if (!_isOffscreen(this)) return _origToBlob.apply(this, arguments);
  var ctx = this.getContext("2d");
  if (!ctx) return _origToBlob.apply(this, arguments);
  var imgData = _origGetImageData.call(ctx, 0, 0, this.width, this.height);
  _addCanvasNoise(imgData);
  var clone = document.createElement("canvas");
  clone.width = this.width;
  clone.height = this.height;
  var cloneCtx = clone.getContext("2d");
  cloneCtx.putImageData(imgData, 0, 0);
  return _origToBlob.call(clone, callback, arguments[1], arguments[2]);
}, "toBlob");

CanvasRenderingContext2D.prototype.getImageData = markAsNative(function getImageData(sx, sy, sw, sh) {
  var imgData = _origGetImageData.call(this, sx, sy, sw, sh);
  if (_isOffscreen(this.canvas)) _addCanvasNoise(imgData);
  return imgData;
}, "getImageData");

// --- 8b. Audio noise ---

if (window.AudioBuffer && AudioBuffer.prototype.getChannelData) {
  var _origGetChannelData = AudioBuffer.prototype.getChannelData;
  var _origCopyFromChannel = AudioBuffer.prototype.copyFromChannel;
  var _fakedArrays = new WeakMap();

  AudioBuffer.prototype.getChannelData = markAsNative(function getChannelData(channel) {
    var result = _origGetChannelData.call(this, channel);
    if (_fakedArrays.has(result)) return result;
    _prngState = _domainSeed;
    for (var i = 0; i < result.length; i++) {
      if (result[i] !== 0) {
        result[i] += (seededRandom() - 0.5) * 2e-7;
      }
    }
    _fakedArrays.set(result, true);
    return result;
  }, "getChannelData");

  if (_origCopyFromChannel) {
    AudioBuffer.prototype.copyFromChannel = markAsNative(function copyFromChannel(destination, channelNumber, startInChannel) {
      this.getChannelData(channelNumber);
      return _origCopyFromChannel.apply(this, arguments);
    }, "copyFromChannel");
  }
}

// --- 8c. WebGL parameter spoofing ---

var _webglSpoofMap = {
  7936: "WebKit",
  7937: "WebKit WebGL",
  37445: "Google Inc. (Intel)",
  37446: "ANGLE (Intel, Intel(R) UHD Graphics 630, OpenGL 4.5)",
};

function _patchGetParameter(proto) {
  var _origGetParam = proto.getParameter;
  proto.getParameter = markAsNative(function getParameter(pname) {
    if (_webglSpoofMap[pname] !== undefined) return _webglSpoofMap[pname];
    return _origGetParam.call(this, pname);
  }, "getParameter");
}

if (window.WebGLRenderingContext) _patchGetParameter(WebGLRenderingContext.prototype);
if (window.WebGL2RenderingContext) _patchGetParameter(WebGL2RenderingContext.prototype);

// ═══════════════════════════════════════════════════════════════
// SECTION 9: Privacy — Input & interaction tracking
// Add deterministic coordinate jitter to mouse/pointer/touch
// events and spoof device orientation/motion to prevent
// behavioral and sensor-based fingerprinting.
// ═══════════════════════════════════════════════════════════════

// --- 9a. Coordinate jitter ---

var _origMESX = Object.getOwnPropertyDescriptor(MouseEvent.prototype, "screenX");
var _origMESY = Object.getOwnPropertyDescriptor(MouseEvent.prototype, "screenY");

if (_origMESX && _origMESX.get) {
  Object.defineProperty(MouseEvent.prototype, "screenX", {
    get: markAsNative(function screenX() {
      return _origMESX.get.call(this) + _jitterX;
    }, "get screenX"),
    configurable: true,
    enumerable: true,
  });
}

if (_origMESY && _origMESY.get) {
  Object.defineProperty(MouseEvent.prototype, "screenY", {
    get: markAsNative(function screenY() {
      return _origMESY.get.call(this) + _jitterY;
    }, "get screenY"),
    configurable: true,
    enumerable: true,
  });
}

// PointerEvent inherits MouseEvent, but patch defensively
if (window.PointerEvent) {
  var _origPESX = Object.getOwnPropertyDescriptor(PointerEvent.prototype, "screenX");
  var _origPESY = Object.getOwnPropertyDescriptor(PointerEvent.prototype, "screenY");

  if (_origPESX && _origPESX.get) {
    Object.defineProperty(PointerEvent.prototype, "screenX", {
      get: markAsNative(function screenX() {
        return _origPESX.get.call(this) + _jitterX;
      }, "get screenX"),
      configurable: true,
      enumerable: true,
    });
  }

  if (_origPESY && _origPESY.get) {
    Object.defineProperty(PointerEvent.prototype, "screenY", {
      get: markAsNative(function screenY() {
        return _origPESY.get.call(this) + _jitterY;
      }, "get screenY"),
      configurable: true,
      enumerable: true,
    });
  }
}

if (window.Touch && Touch.prototype) {
  var _origTSX = Object.getOwnPropertyDescriptor(Touch.prototype, "screenX");
  var _origTSY = Object.getOwnPropertyDescriptor(Touch.prototype, "screenY");

  if (_origTSX && _origTSX.get) {
    Object.defineProperty(Touch.prototype, "screenX", {
      get: markAsNative(function screenX() {
        return _origTSX.get.call(this) + _jitterX;
      }, "get screenX"),
      configurable: true,
      enumerable: true,
    });
  }

  if (_origTSY && _origTSY.get) {
    Object.defineProperty(Touch.prototype, "screenY", {
      get: markAsNative(function screenY() {
        return _origTSY.get.call(this) + _jitterY;
      }, "get screenY"),
      configurable: true,
      enumerable: true,
    });
  }
}

// --- 9b. Device orientation/motion spoofing ---

if (window.DeviceOrientationEvent) {
  Object.defineProperty(DeviceOrientationEvent.prototype, "alpha", {
    get: markAsNative(function alpha() { return 0; }, "get alpha"),
    configurable: true,
    enumerable: true,
  });
  Object.defineProperty(DeviceOrientationEvent.prototype, "beta", {
    get: markAsNative(function beta() { return 90; }, "get beta"),
    configurable: true,
    enumerable: true,
  });
  Object.defineProperty(DeviceOrientationEvent.prototype, "gamma", {
    get: markAsNative(function gamma() { return 0; }, "get gamma"),
    configurable: true,
    enumerable: true,
  });
}

if (window.DeviceMotionEvent) {
  Object.defineProperty(DeviceMotionEvent.prototype, "accelerationIncludingGravity", {
    get: markAsNative(function accelerationIncludingGravity() {
      return { x: 0, y: 0, z: -9.8 };
    }, "get accelerationIncludingGravity"),
    configurable: true,
    enumerable: true,
  });
}

// ═══════════════════════════════════════════════════════════════
// SECTION 10: Privacy — Timezone & WebRTC
// Normalize timezone to UTC and filter WebRTC host candidates
// to prevent local IP leaks via RTCPeerConnection.
// ═══════════════════════════════════════════════════════════════

// --- 10a. Timezone normalization ---

var _origGetTimezoneOffset = Date.prototype.getTimezoneOffset;
Date.prototype.getTimezoneOffset = markAsNative(function getTimezoneOffset() {
  return 0;
}, "getTimezoneOffset");

if (window.Intl && window.Intl.DateTimeFormat) {
  var _origResolvedOptions = Intl.DateTimeFormat.prototype.resolvedOptions;
  Intl.DateTimeFormat.prototype.resolvedOptions = markAsNative(function resolvedOptions() {
    var opts = _origResolvedOptions.call(this);
    opts.timeZone = "UTC";
    return opts;
  }, "resolvedOptions");
}

// --- 10b. WebRTC host candidate filtering ---

if (window.RTCPeerConnection) {
  var _origRPCAddEventListener = RTCPeerConnection.prototype.addEventListener;
  var _origOnIceCandidate = Object.getOwnPropertyDescriptor(RTCPeerConnection.prototype, "onicecandidate");

  function _filterHostCandidate(event) {
    if (event.candidate && event.candidate.candidate &&
        event.candidate.candidate.indexOf("typ host") !== -1) {
      return;
    }
    return event;
  }

  RTCPeerConnection.prototype.addEventListener = markAsNative(function addEventListener(type, listener, options) {
    if (type === "icecandidate" && typeof listener === "function") {
      var _origListener = listener;
      arguments[1] = function (event) {
        if (_filterHostCandidate(event)) {
          return _origListener.apply(this, arguments);
        }
      };
    }
    return _origRPCAddEventListener.apply(this, arguments);
  }, "addEventListener");

  if (_origOnIceCandidate && _origOnIceCandidate.set) {
    Object.defineProperty(RTCPeerConnection.prototype, "onicecandidate", {
      get: _origOnIceCandidate.get,
      set: markAsNative(function onicecandidate(listener) {
        if (typeof listener === "function") {
          var _origListener = listener;
          _origOnIceCandidate.set.call(this, function (event) {
            if (_filterHostCandidate(event)) {
              return _origListener.apply(this, arguments);
            }
          });
        } else {
          _origOnIceCandidate.set.call(this, listener);
        }
      }, "set onicecandidate"),
      configurable: true,
      enumerable: true,
    });
  }
}

// ═══════════════════════════════════════════════════════════════
// SECTION 5: Patch hardening
// Make patched globals harder to re-overwrite by page scripts.
// Uses Object.defineProperty with writable:false where safe.
// ═══════════════════════════════════════════════════════════════

var _hardenedGlobals = ["eval", "Function", "setTimeout", "setInterval",
  "requestAnimationFrame", "queueMicrotask", "devicePixelRatio", "BroadcastChannel"];

for (var _hi = 0; _hi < _hardenedGlobals.length; _hi++) {
  var _g = _hardenedGlobals[_hi];
  try {
    Object.defineProperty(window, _g, {
      value: window[_g],
      writable: false,
      configurable: false,
      enumerable: false,
    });
  } catch (e) { /* property already non-configurable, that's fine */ }
}
})();
