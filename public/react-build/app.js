(() => {
  var __create = Object.create;
  var __defProp = Object.defineProperty;
  var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __getProtoOf = Object.getPrototypeOf;
  var __hasOwnProp = Object.prototype.hasOwnProperty;
  var __commonJS = (cb, mod) => function __require() {
    return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
  };
  var __copyProps = (to, from, except, desc) => {
    if (from && typeof from === "object" || typeof from === "function") {
      for (let key of __getOwnPropNames(from))
        if (!__hasOwnProp.call(to, key) && key !== except)
          __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
    }
    return to;
  };
  var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
    // If the importer is in node compatibility mode or this is not an ESM
    // file that has been converted to a CommonJS file using a Babel-
    // compatible transform (i.e. "__esModule" has not been set), then set
    // "default" to the CommonJS "module.exports" for node compatibility.
    isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
    mod
  ));

  // node_modules/react/cjs/react.production.min.js
  var require_react_production_min = __commonJS({
    "node_modules/react/cjs/react.production.min.js"(exports) {
      "use strict";
      var l = Symbol.for("react.element");
      var n = Symbol.for("react.portal");
      var p = Symbol.for("react.fragment");
      var q = Symbol.for("react.strict_mode");
      var r = Symbol.for("react.profiler");
      var t = Symbol.for("react.provider");
      var u = Symbol.for("react.context");
      var v = Symbol.for("react.forward_ref");
      var w = Symbol.for("react.suspense");
      var x = Symbol.for("react.memo");
      var y = Symbol.for("react.lazy");
      var z = Symbol.iterator;
      function A(a) {
        if (null === a || "object" !== typeof a) return null;
        a = z && a[z] || a["@@iterator"];
        return "function" === typeof a ? a : null;
      }
      var B = { isMounted: function() {
        return false;
      }, enqueueForceUpdate: function() {
      }, enqueueReplaceState: function() {
      }, enqueueSetState: function() {
      } };
      var C = Object.assign;
      var D = {};
      function E(a, b, e) {
        this.props = a;
        this.context = b;
        this.refs = D;
        this.updater = e || B;
      }
      E.prototype.isReactComponent = {};
      E.prototype.setState = function(a, b) {
        if ("object" !== typeof a && "function" !== typeof a && null != a) throw Error("setState(...): takes an object of state variables to update or a function which returns an object of state variables.");
        this.updater.enqueueSetState(this, a, b, "setState");
      };
      E.prototype.forceUpdate = function(a) {
        this.updater.enqueueForceUpdate(this, a, "forceUpdate");
      };
      function F() {
      }
      F.prototype = E.prototype;
      function G(a, b, e) {
        this.props = a;
        this.context = b;
        this.refs = D;
        this.updater = e || B;
      }
      var H = G.prototype = new F();
      H.constructor = G;
      C(H, E.prototype);
      H.isPureReactComponent = true;
      var I = Array.isArray;
      var J = Object.prototype.hasOwnProperty;
      var K = { current: null };
      var L = { key: true, ref: true, __self: true, __source: true };
      function M(a, b, e) {
        var d, c = {}, k = null, h = null;
        if (null != b) for (d in void 0 !== b.ref && (h = b.ref), void 0 !== b.key && (k = "" + b.key), b) J.call(b, d) && !L.hasOwnProperty(d) && (c[d] = b[d]);
        var g = arguments.length - 2;
        if (1 === g) c.children = e;
        else if (1 < g) {
          for (var f = Array(g), m = 0; m < g; m++) f[m] = arguments[m + 2];
          c.children = f;
        }
        if (a && a.defaultProps) for (d in g = a.defaultProps, g) void 0 === c[d] && (c[d] = g[d]);
        return { $$typeof: l, type: a, key: k, ref: h, props: c, _owner: K.current };
      }
      function N(a, b) {
        return { $$typeof: l, type: a.type, key: b, ref: a.ref, props: a.props, _owner: a._owner };
      }
      function O(a) {
        return "object" === typeof a && null !== a && a.$$typeof === l;
      }
      function escape(a) {
        var b = { "=": "=0", ":": "=2" };
        return "$" + a.replace(/[=:]/g, function(a2) {
          return b[a2];
        });
      }
      var P = /\/+/g;
      function Q(a, b) {
        return "object" === typeof a && null !== a && null != a.key ? escape("" + a.key) : b.toString(36);
      }
      function R(a, b, e, d, c) {
        var k = typeof a;
        if ("undefined" === k || "boolean" === k) a = null;
        var h = false;
        if (null === a) h = true;
        else switch (k) {
          case "string":
          case "number":
            h = true;
            break;
          case "object":
            switch (a.$$typeof) {
              case l:
              case n:
                h = true;
            }
        }
        if (h) return h = a, c = c(h), a = "" === d ? "." + Q(h, 0) : d, I(c) ? (e = "", null != a && (e = a.replace(P, "$&/") + "/"), R(c, b, e, "", function(a2) {
          return a2;
        })) : null != c && (O(c) && (c = N(c, e + (!c.key || h && h.key === c.key ? "" : ("" + c.key).replace(P, "$&/") + "/") + a)), b.push(c)), 1;
        h = 0;
        d = "" === d ? "." : d + ":";
        if (I(a)) for (var g = 0; g < a.length; g++) {
          k = a[g];
          var f = d + Q(k, g);
          h += R(k, b, e, f, c);
        }
        else if (f = A(a), "function" === typeof f) for (a = f.call(a), g = 0; !(k = a.next()).done; ) k = k.value, f = d + Q(k, g++), h += R(k, b, e, f, c);
        else if ("object" === k) throw b = String(a), Error("Objects are not valid as a React child (found: " + ("[object Object]" === b ? "object with keys {" + Object.keys(a).join(", ") + "}" : b) + "). If you meant to render a collection of children, use an array instead.");
        return h;
      }
      function S(a, b, e) {
        if (null == a) return a;
        var d = [], c = 0;
        R(a, d, "", "", function(a2) {
          return b.call(e, a2, c++);
        });
        return d;
      }
      function T(a) {
        if (-1 === a._status) {
          var b = a._result;
          b = b();
          b.then(function(b2) {
            if (0 === a._status || -1 === a._status) a._status = 1, a._result = b2;
          }, function(b2) {
            if (0 === a._status || -1 === a._status) a._status = 2, a._result = b2;
          });
          -1 === a._status && (a._status = 0, a._result = b);
        }
        if (1 === a._status) return a._result.default;
        throw a._result;
      }
      var U = { current: null };
      var V = { transition: null };
      var W = { ReactCurrentDispatcher: U, ReactCurrentBatchConfig: V, ReactCurrentOwner: K };
      function X() {
        throw Error("act(...) is not supported in production builds of React.");
      }
      exports.Children = { map: S, forEach: function(a, b, e) {
        S(a, function() {
          b.apply(this, arguments);
        }, e);
      }, count: function(a) {
        var b = 0;
        S(a, function() {
          b++;
        });
        return b;
      }, toArray: function(a) {
        return S(a, function(a2) {
          return a2;
        }) || [];
      }, only: function(a) {
        if (!O(a)) throw Error("React.Children.only expected to receive a single React element child.");
        return a;
      } };
      exports.Component = E;
      exports.Fragment = p;
      exports.Profiler = r;
      exports.PureComponent = G;
      exports.StrictMode = q;
      exports.Suspense = w;
      exports.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED = W;
      exports.act = X;
      exports.cloneElement = function(a, b, e) {
        if (null === a || void 0 === a) throw Error("React.cloneElement(...): The argument must be a React element, but you passed " + a + ".");
        var d = C({}, a.props), c = a.key, k = a.ref, h = a._owner;
        if (null != b) {
          void 0 !== b.ref && (k = b.ref, h = K.current);
          void 0 !== b.key && (c = "" + b.key);
          if (a.type && a.type.defaultProps) var g = a.type.defaultProps;
          for (f in b) J.call(b, f) && !L.hasOwnProperty(f) && (d[f] = void 0 === b[f] && void 0 !== g ? g[f] : b[f]);
        }
        var f = arguments.length - 2;
        if (1 === f) d.children = e;
        else if (1 < f) {
          g = Array(f);
          for (var m = 0; m < f; m++) g[m] = arguments[m + 2];
          d.children = g;
        }
        return { $$typeof: l, type: a.type, key: c, ref: k, props: d, _owner: h };
      };
      exports.createContext = function(a) {
        a = { $$typeof: u, _currentValue: a, _currentValue2: a, _threadCount: 0, Provider: null, Consumer: null, _defaultValue: null, _globalName: null };
        a.Provider = { $$typeof: t, _context: a };
        return a.Consumer = a;
      };
      exports.createElement = M;
      exports.createFactory = function(a) {
        var b = M.bind(null, a);
        b.type = a;
        return b;
      };
      exports.createRef = function() {
        return { current: null };
      };
      exports.forwardRef = function(a) {
        return { $$typeof: v, render: a };
      };
      exports.isValidElement = O;
      exports.lazy = function(a) {
        return { $$typeof: y, _payload: { _status: -1, _result: a }, _init: T };
      };
      exports.memo = function(a, b) {
        return { $$typeof: x, type: a, compare: void 0 === b ? null : b };
      };
      exports.startTransition = function(a) {
        var b = V.transition;
        V.transition = {};
        try {
          a();
        } finally {
          V.transition = b;
        }
      };
      exports.unstable_act = X;
      exports.useCallback = function(a, b) {
        return U.current.useCallback(a, b);
      };
      exports.useContext = function(a) {
        return U.current.useContext(a);
      };
      exports.useDebugValue = function() {
      };
      exports.useDeferredValue = function(a) {
        return U.current.useDeferredValue(a);
      };
      exports.useEffect = function(a, b) {
        return U.current.useEffect(a, b);
      };
      exports.useId = function() {
        return U.current.useId();
      };
      exports.useImperativeHandle = function(a, b, e) {
        return U.current.useImperativeHandle(a, b, e);
      };
      exports.useInsertionEffect = function(a, b) {
        return U.current.useInsertionEffect(a, b);
      };
      exports.useLayoutEffect = function(a, b) {
        return U.current.useLayoutEffect(a, b);
      };
      exports.useMemo = function(a, b) {
        return U.current.useMemo(a, b);
      };
      exports.useReducer = function(a, b, e) {
        return U.current.useReducer(a, b, e);
      };
      exports.useRef = function(a) {
        return U.current.useRef(a);
      };
      exports.useState = function(a) {
        return U.current.useState(a);
      };
      exports.useSyncExternalStore = function(a, b, e) {
        return U.current.useSyncExternalStore(a, b, e);
      };
      exports.useTransition = function() {
        return U.current.useTransition();
      };
      exports.version = "18.3.1";
    }
  });

  // node_modules/react/index.js
  var require_react = __commonJS({
    "node_modules/react/index.js"(exports, module) {
      "use strict";
      if (true) {
        module.exports = require_react_production_min();
      } else {
        module.exports = null;
      }
    }
  });

  // node_modules/scheduler/cjs/scheduler.production.min.js
  var require_scheduler_production_min = __commonJS({
    "node_modules/scheduler/cjs/scheduler.production.min.js"(exports) {
      "use strict";
      function f(a, b) {
        var c = a.length;
        a.push(b);
        a: for (; 0 < c; ) {
          var d = c - 1 >>> 1, e = a[d];
          if (0 < g(e, b)) a[d] = b, a[c] = e, c = d;
          else break a;
        }
      }
      function h(a) {
        return 0 === a.length ? null : a[0];
      }
      function k(a) {
        if (0 === a.length) return null;
        var b = a[0], c = a.pop();
        if (c !== b) {
          a[0] = c;
          a: for (var d = 0, e = a.length, w = e >>> 1; d < w; ) {
            var m = 2 * (d + 1) - 1, C = a[m], n = m + 1, x = a[n];
            if (0 > g(C, c)) n < e && 0 > g(x, C) ? (a[d] = x, a[n] = c, d = n) : (a[d] = C, a[m] = c, d = m);
            else if (n < e && 0 > g(x, c)) a[d] = x, a[n] = c, d = n;
            else break a;
          }
        }
        return b;
      }
      function g(a, b) {
        var c = a.sortIndex - b.sortIndex;
        return 0 !== c ? c : a.id - b.id;
      }
      if ("object" === typeof performance && "function" === typeof performance.now) {
        l = performance;
        exports.unstable_now = function() {
          return l.now();
        };
      } else {
        p = Date, q = p.now();
        exports.unstable_now = function() {
          return p.now() - q;
        };
      }
      var l;
      var p;
      var q;
      var r = [];
      var t = [];
      var u = 1;
      var v = null;
      var y = 3;
      var z = false;
      var A = false;
      var B = false;
      var D = "function" === typeof setTimeout ? setTimeout : null;
      var E = "function" === typeof clearTimeout ? clearTimeout : null;
      var F = "undefined" !== typeof setImmediate ? setImmediate : null;
      "undefined" !== typeof navigator && void 0 !== navigator.scheduling && void 0 !== navigator.scheduling.isInputPending && navigator.scheduling.isInputPending.bind(navigator.scheduling);
      function G(a) {
        for (var b = h(t); null !== b; ) {
          if (null === b.callback) k(t);
          else if (b.startTime <= a) k(t), b.sortIndex = b.expirationTime, f(r, b);
          else break;
          b = h(t);
        }
      }
      function H(a) {
        B = false;
        G(a);
        if (!A) if (null !== h(r)) A = true, I(J);
        else {
          var b = h(t);
          null !== b && K(H, b.startTime - a);
        }
      }
      function J(a, b) {
        A = false;
        B && (B = false, E(L), L = -1);
        z = true;
        var c = y;
        try {
          G(b);
          for (v = h(r); null !== v && (!(v.expirationTime > b) || a && !M()); ) {
            var d = v.callback;
            if ("function" === typeof d) {
              v.callback = null;
              y = v.priorityLevel;
              var e = d(v.expirationTime <= b);
              b = exports.unstable_now();
              "function" === typeof e ? v.callback = e : v === h(r) && k(r);
              G(b);
            } else k(r);
            v = h(r);
          }
          if (null !== v) var w = true;
          else {
            var m = h(t);
            null !== m && K(H, m.startTime - b);
            w = false;
          }
          return w;
        } finally {
          v = null, y = c, z = false;
        }
      }
      var N = false;
      var O = null;
      var L = -1;
      var P = 5;
      var Q = -1;
      function M() {
        return exports.unstable_now() - Q < P ? false : true;
      }
      function R() {
        if (null !== O) {
          var a = exports.unstable_now();
          Q = a;
          var b = true;
          try {
            b = O(true, a);
          } finally {
            b ? S() : (N = false, O = null);
          }
        } else N = false;
      }
      var S;
      if ("function" === typeof F) S = function() {
        F(R);
      };
      else if ("undefined" !== typeof MessageChannel) {
        T = new MessageChannel(), U = T.port2;
        T.port1.onmessage = R;
        S = function() {
          U.postMessage(null);
        };
      } else S = function() {
        D(R, 0);
      };
      var T;
      var U;
      function I(a) {
        O = a;
        N || (N = true, S());
      }
      function K(a, b) {
        L = D(function() {
          a(exports.unstable_now());
        }, b);
      }
      exports.unstable_IdlePriority = 5;
      exports.unstable_ImmediatePriority = 1;
      exports.unstable_LowPriority = 4;
      exports.unstable_NormalPriority = 3;
      exports.unstable_Profiling = null;
      exports.unstable_UserBlockingPriority = 2;
      exports.unstable_cancelCallback = function(a) {
        a.callback = null;
      };
      exports.unstable_continueExecution = function() {
        A || z || (A = true, I(J));
      };
      exports.unstable_forceFrameRate = function(a) {
        0 > a || 125 < a ? console.error("forceFrameRate takes a positive int between 0 and 125, forcing frame rates higher than 125 fps is not supported") : P = 0 < a ? Math.floor(1e3 / a) : 5;
      };
      exports.unstable_getCurrentPriorityLevel = function() {
        return y;
      };
      exports.unstable_getFirstCallbackNode = function() {
        return h(r);
      };
      exports.unstable_next = function(a) {
        switch (y) {
          case 1:
          case 2:
          case 3:
            var b = 3;
            break;
          default:
            b = y;
        }
        var c = y;
        y = b;
        try {
          return a();
        } finally {
          y = c;
        }
      };
      exports.unstable_pauseExecution = function() {
      };
      exports.unstable_requestPaint = function() {
      };
      exports.unstable_runWithPriority = function(a, b) {
        switch (a) {
          case 1:
          case 2:
          case 3:
          case 4:
          case 5:
            break;
          default:
            a = 3;
        }
        var c = y;
        y = a;
        try {
          return b();
        } finally {
          y = c;
        }
      };
      exports.unstable_scheduleCallback = function(a, b, c) {
        var d = exports.unstable_now();
        "object" === typeof c && null !== c ? (c = c.delay, c = "number" === typeof c && 0 < c ? d + c : d) : c = d;
        switch (a) {
          case 1:
            var e = -1;
            break;
          case 2:
            e = 250;
            break;
          case 5:
            e = 1073741823;
            break;
          case 4:
            e = 1e4;
            break;
          default:
            e = 5e3;
        }
        e = c + e;
        a = { id: u++, callback: b, priorityLevel: a, startTime: c, expirationTime: e, sortIndex: -1 };
        c > d ? (a.sortIndex = c, f(t, a), null === h(r) && a === h(t) && (B ? (E(L), L = -1) : B = true, K(H, c - d))) : (a.sortIndex = e, f(r, a), A || z || (A = true, I(J)));
        return a;
      };
      exports.unstable_shouldYield = M;
      exports.unstable_wrapCallback = function(a) {
        var b = y;
        return function() {
          var c = y;
          y = b;
          try {
            return a.apply(this, arguments);
          } finally {
            y = c;
          }
        };
      };
    }
  });

  // node_modules/scheduler/index.js
  var require_scheduler = __commonJS({
    "node_modules/scheduler/index.js"(exports, module) {
      "use strict";
      if (true) {
        module.exports = require_scheduler_production_min();
      } else {
        module.exports = null;
      }
    }
  });

  // node_modules/react-dom/cjs/react-dom.production.min.js
  var require_react_dom_production_min = __commonJS({
    "node_modules/react-dom/cjs/react-dom.production.min.js"(exports) {
      "use strict";
      var aa = require_react();
      var ca = require_scheduler();
      function p(a) {
        for (var b = "https://reactjs.org/docs/error-decoder.html?invariant=" + a, c = 1; c < arguments.length; c++) b += "&args[]=" + encodeURIComponent(arguments[c]);
        return "Minified React error #" + a + "; visit " + b + " for the full message or use the non-minified dev environment for full errors and additional helpful warnings.";
      }
      var da = /* @__PURE__ */ new Set();
      var ea = {};
      function fa(a, b) {
        ha(a, b);
        ha(a + "Capture", b);
      }
      function ha(a, b) {
        ea[a] = b;
        for (a = 0; a < b.length; a++) da.add(b[a]);
      }
      var ia = !("undefined" === typeof window || "undefined" === typeof window.document || "undefined" === typeof window.document.createElement);
      var ja = Object.prototype.hasOwnProperty;
      var ka = /^[:A-Z_a-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD][:A-Z_a-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD\-.0-9\u00B7\u0300-\u036F\u203F-\u2040]*$/;
      var la = {};
      var ma = {};
      function oa(a) {
        if (ja.call(ma, a)) return true;
        if (ja.call(la, a)) return false;
        if (ka.test(a)) return ma[a] = true;
        la[a] = true;
        return false;
      }
      function pa(a, b, c, d) {
        if (null !== c && 0 === c.type) return false;
        switch (typeof b) {
          case "function":
          case "symbol":
            return true;
          case "boolean":
            if (d) return false;
            if (null !== c) return !c.acceptsBooleans;
            a = a.toLowerCase().slice(0, 5);
            return "data-" !== a && "aria-" !== a;
          default:
            return false;
        }
      }
      function qa(a, b, c, d) {
        if (null === b || "undefined" === typeof b || pa(a, b, c, d)) return true;
        if (d) return false;
        if (null !== c) switch (c.type) {
          case 3:
            return !b;
          case 4:
            return false === b;
          case 5:
            return isNaN(b);
          case 6:
            return isNaN(b) || 1 > b;
        }
        return false;
      }
      function v(a, b, c, d, e, f, g) {
        this.acceptsBooleans = 2 === b || 3 === b || 4 === b;
        this.attributeName = d;
        this.attributeNamespace = e;
        this.mustUseProperty = c;
        this.propertyName = a;
        this.type = b;
        this.sanitizeURL = f;
        this.removeEmptyString = g;
      }
      var z = {};
      "children dangerouslySetInnerHTML defaultValue defaultChecked innerHTML suppressContentEditableWarning suppressHydrationWarning style".split(" ").forEach(function(a) {
        z[a] = new v(a, 0, false, a, null, false, false);
      });
      [["acceptCharset", "accept-charset"], ["className", "class"], ["htmlFor", "for"], ["httpEquiv", "http-equiv"]].forEach(function(a) {
        var b = a[0];
        z[b] = new v(b, 1, false, a[1], null, false, false);
      });
      ["contentEditable", "draggable", "spellCheck", "value"].forEach(function(a) {
        z[a] = new v(a, 2, false, a.toLowerCase(), null, false, false);
      });
      ["autoReverse", "externalResourcesRequired", "focusable", "preserveAlpha"].forEach(function(a) {
        z[a] = new v(a, 2, false, a, null, false, false);
      });
      "allowFullScreen async autoFocus autoPlay controls default defer disabled disablePictureInPicture disableRemotePlayback formNoValidate hidden loop noModule noValidate open playsInline readOnly required reversed scoped seamless itemScope".split(" ").forEach(function(a) {
        z[a] = new v(a, 3, false, a.toLowerCase(), null, false, false);
      });
      ["checked", "multiple", "muted", "selected"].forEach(function(a) {
        z[a] = new v(a, 3, true, a, null, false, false);
      });
      ["capture", "download"].forEach(function(a) {
        z[a] = new v(a, 4, false, a, null, false, false);
      });
      ["cols", "rows", "size", "span"].forEach(function(a) {
        z[a] = new v(a, 6, false, a, null, false, false);
      });
      ["rowSpan", "start"].forEach(function(a) {
        z[a] = new v(a, 5, false, a.toLowerCase(), null, false, false);
      });
      var ra = /[\-:]([a-z])/g;
      function sa(a) {
        return a[1].toUpperCase();
      }
      "accent-height alignment-baseline arabic-form baseline-shift cap-height clip-path clip-rule color-interpolation color-interpolation-filters color-profile color-rendering dominant-baseline enable-background fill-opacity fill-rule flood-color flood-opacity font-family font-size font-size-adjust font-stretch font-style font-variant font-weight glyph-name glyph-orientation-horizontal glyph-orientation-vertical horiz-adv-x horiz-origin-x image-rendering letter-spacing lighting-color marker-end marker-mid marker-start overline-position overline-thickness paint-order panose-1 pointer-events rendering-intent shape-rendering stop-color stop-opacity strikethrough-position strikethrough-thickness stroke-dasharray stroke-dashoffset stroke-linecap stroke-linejoin stroke-miterlimit stroke-opacity stroke-width text-anchor text-decoration text-rendering underline-position underline-thickness unicode-bidi unicode-range units-per-em v-alphabetic v-hanging v-ideographic v-mathematical vector-effect vert-adv-y vert-origin-x vert-origin-y word-spacing writing-mode xmlns:xlink x-height".split(" ").forEach(function(a) {
        var b = a.replace(
          ra,
          sa
        );
        z[b] = new v(b, 1, false, a, null, false, false);
      });
      "xlink:actuate xlink:arcrole xlink:role xlink:show xlink:title xlink:type".split(" ").forEach(function(a) {
        var b = a.replace(ra, sa);
        z[b] = new v(b, 1, false, a, "http://www.w3.org/1999/xlink", false, false);
      });
      ["xml:base", "xml:lang", "xml:space"].forEach(function(a) {
        var b = a.replace(ra, sa);
        z[b] = new v(b, 1, false, a, "http://www.w3.org/XML/1998/namespace", false, false);
      });
      ["tabIndex", "crossOrigin"].forEach(function(a) {
        z[a] = new v(a, 1, false, a.toLowerCase(), null, false, false);
      });
      z.xlinkHref = new v("xlinkHref", 1, false, "xlink:href", "http://www.w3.org/1999/xlink", true, false);
      ["src", "href", "action", "formAction"].forEach(function(a) {
        z[a] = new v(a, 1, false, a.toLowerCase(), null, true, true);
      });
      function ta(a, b, c, d) {
        var e = z.hasOwnProperty(b) ? z[b] : null;
        if (null !== e ? 0 !== e.type : d || !(2 < b.length) || "o" !== b[0] && "O" !== b[0] || "n" !== b[1] && "N" !== b[1]) qa(b, c, e, d) && (c = null), d || null === e ? oa(b) && (null === c ? a.removeAttribute(b) : a.setAttribute(b, "" + c)) : e.mustUseProperty ? a[e.propertyName] = null === c ? 3 === e.type ? false : "" : c : (b = e.attributeName, d = e.attributeNamespace, null === c ? a.removeAttribute(b) : (e = e.type, c = 3 === e || 4 === e && true === c ? "" : "" + c, d ? a.setAttributeNS(d, b, c) : a.setAttribute(b, c)));
      }
      var ua = aa.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED;
      var va = Symbol.for("react.element");
      var wa = Symbol.for("react.portal");
      var ya = Symbol.for("react.fragment");
      var za = Symbol.for("react.strict_mode");
      var Aa = Symbol.for("react.profiler");
      var Ba = Symbol.for("react.provider");
      var Ca = Symbol.for("react.context");
      var Da = Symbol.for("react.forward_ref");
      var Ea = Symbol.for("react.suspense");
      var Fa = Symbol.for("react.suspense_list");
      var Ga = Symbol.for("react.memo");
      var Ha = Symbol.for("react.lazy");
      Symbol.for("react.scope");
      Symbol.for("react.debug_trace_mode");
      var Ia = Symbol.for("react.offscreen");
      Symbol.for("react.legacy_hidden");
      Symbol.for("react.cache");
      Symbol.for("react.tracing_marker");
      var Ja = Symbol.iterator;
      function Ka(a) {
        if (null === a || "object" !== typeof a) return null;
        a = Ja && a[Ja] || a["@@iterator"];
        return "function" === typeof a ? a : null;
      }
      var A = Object.assign;
      var La;
      function Ma(a) {
        if (void 0 === La) try {
          throw Error();
        } catch (c) {
          var b = c.stack.trim().match(/\n( *(at )?)/);
          La = b && b[1] || "";
        }
        return "\n" + La + a;
      }
      var Na = false;
      function Oa(a, b) {
        if (!a || Na) return "";
        Na = true;
        var c = Error.prepareStackTrace;
        Error.prepareStackTrace = void 0;
        try {
          if (b) if (b = function() {
            throw Error();
          }, Object.defineProperty(b.prototype, "props", { set: function() {
            throw Error();
          } }), "object" === typeof Reflect && Reflect.construct) {
            try {
              Reflect.construct(b, []);
            } catch (l) {
              var d = l;
            }
            Reflect.construct(a, [], b);
          } else {
            try {
              b.call();
            } catch (l) {
              d = l;
            }
            a.call(b.prototype);
          }
          else {
            try {
              throw Error();
            } catch (l) {
              d = l;
            }
            a();
          }
        } catch (l) {
          if (l && d && "string" === typeof l.stack) {
            for (var e = l.stack.split("\n"), f = d.stack.split("\n"), g = e.length - 1, h = f.length - 1; 1 <= g && 0 <= h && e[g] !== f[h]; ) h--;
            for (; 1 <= g && 0 <= h; g--, h--) if (e[g] !== f[h]) {
              if (1 !== g || 1 !== h) {
                do
                  if (g--, h--, 0 > h || e[g] !== f[h]) {
                    var k = "\n" + e[g].replace(" at new ", " at ");
                    a.displayName && k.includes("<anonymous>") && (k = k.replace("<anonymous>", a.displayName));
                    return k;
                  }
                while (1 <= g && 0 <= h);
              }
              break;
            }
          }
        } finally {
          Na = false, Error.prepareStackTrace = c;
        }
        return (a = a ? a.displayName || a.name : "") ? Ma(a) : "";
      }
      function Pa(a) {
        switch (a.tag) {
          case 5:
            return Ma(a.type);
          case 16:
            return Ma("Lazy");
          case 13:
            return Ma("Suspense");
          case 19:
            return Ma("SuspenseList");
          case 0:
          case 2:
          case 15:
            return a = Oa(a.type, false), a;
          case 11:
            return a = Oa(a.type.render, false), a;
          case 1:
            return a = Oa(a.type, true), a;
          default:
            return "";
        }
      }
      function Qa(a) {
        if (null == a) return null;
        if ("function" === typeof a) return a.displayName || a.name || null;
        if ("string" === typeof a) return a;
        switch (a) {
          case ya:
            return "Fragment";
          case wa:
            return "Portal";
          case Aa:
            return "Profiler";
          case za:
            return "StrictMode";
          case Ea:
            return "Suspense";
          case Fa:
            return "SuspenseList";
        }
        if ("object" === typeof a) switch (a.$$typeof) {
          case Ca:
            return (a.displayName || "Context") + ".Consumer";
          case Ba:
            return (a._context.displayName || "Context") + ".Provider";
          case Da:
            var b = a.render;
            a = a.displayName;
            a || (a = b.displayName || b.name || "", a = "" !== a ? "ForwardRef(" + a + ")" : "ForwardRef");
            return a;
          case Ga:
            return b = a.displayName || null, null !== b ? b : Qa(a.type) || "Memo";
          case Ha:
            b = a._payload;
            a = a._init;
            try {
              return Qa(a(b));
            } catch (c) {
            }
        }
        return null;
      }
      function Ra(a) {
        var b = a.type;
        switch (a.tag) {
          case 24:
            return "Cache";
          case 9:
            return (b.displayName || "Context") + ".Consumer";
          case 10:
            return (b._context.displayName || "Context") + ".Provider";
          case 18:
            return "DehydratedFragment";
          case 11:
            return a = b.render, a = a.displayName || a.name || "", b.displayName || ("" !== a ? "ForwardRef(" + a + ")" : "ForwardRef");
          case 7:
            return "Fragment";
          case 5:
            return b;
          case 4:
            return "Portal";
          case 3:
            return "Root";
          case 6:
            return "Text";
          case 16:
            return Qa(b);
          case 8:
            return b === za ? "StrictMode" : "Mode";
          case 22:
            return "Offscreen";
          case 12:
            return "Profiler";
          case 21:
            return "Scope";
          case 13:
            return "Suspense";
          case 19:
            return "SuspenseList";
          case 25:
            return "TracingMarker";
          case 1:
          case 0:
          case 17:
          case 2:
          case 14:
          case 15:
            if ("function" === typeof b) return b.displayName || b.name || null;
            if ("string" === typeof b) return b;
        }
        return null;
      }
      function Sa(a) {
        switch (typeof a) {
          case "boolean":
          case "number":
          case "string":
          case "undefined":
            return a;
          case "object":
            return a;
          default:
            return "";
        }
      }
      function Ta(a) {
        var b = a.type;
        return (a = a.nodeName) && "input" === a.toLowerCase() && ("checkbox" === b || "radio" === b);
      }
      function Ua(a) {
        var b = Ta(a) ? "checked" : "value", c = Object.getOwnPropertyDescriptor(a.constructor.prototype, b), d = "" + a[b];
        if (!a.hasOwnProperty(b) && "undefined" !== typeof c && "function" === typeof c.get && "function" === typeof c.set) {
          var e = c.get, f = c.set;
          Object.defineProperty(a, b, { configurable: true, get: function() {
            return e.call(this);
          }, set: function(a2) {
            d = "" + a2;
            f.call(this, a2);
          } });
          Object.defineProperty(a, b, { enumerable: c.enumerable });
          return { getValue: function() {
            return d;
          }, setValue: function(a2) {
            d = "" + a2;
          }, stopTracking: function() {
            a._valueTracker = null;
            delete a[b];
          } };
        }
      }
      function Va(a) {
        a._valueTracker || (a._valueTracker = Ua(a));
      }
      function Wa(a) {
        if (!a) return false;
        var b = a._valueTracker;
        if (!b) return true;
        var c = b.getValue();
        var d = "";
        a && (d = Ta(a) ? a.checked ? "true" : "false" : a.value);
        a = d;
        return a !== c ? (b.setValue(a), true) : false;
      }
      function Xa(a) {
        a = a || ("undefined" !== typeof document ? document : void 0);
        if ("undefined" === typeof a) return null;
        try {
          return a.activeElement || a.body;
        } catch (b) {
          return a.body;
        }
      }
      function Ya(a, b) {
        var c = b.checked;
        return A({}, b, { defaultChecked: void 0, defaultValue: void 0, value: void 0, checked: null != c ? c : a._wrapperState.initialChecked });
      }
      function Za(a, b) {
        var c = null == b.defaultValue ? "" : b.defaultValue, d = null != b.checked ? b.checked : b.defaultChecked;
        c = Sa(null != b.value ? b.value : c);
        a._wrapperState = { initialChecked: d, initialValue: c, controlled: "checkbox" === b.type || "radio" === b.type ? null != b.checked : null != b.value };
      }
      function ab(a, b) {
        b = b.checked;
        null != b && ta(a, "checked", b, false);
      }
      function bb(a, b) {
        ab(a, b);
        var c = Sa(b.value), d = b.type;
        if (null != c) if ("number" === d) {
          if (0 === c && "" === a.value || a.value != c) a.value = "" + c;
        } else a.value !== "" + c && (a.value = "" + c);
        else if ("submit" === d || "reset" === d) {
          a.removeAttribute("value");
          return;
        }
        b.hasOwnProperty("value") ? cb(a, b.type, c) : b.hasOwnProperty("defaultValue") && cb(a, b.type, Sa(b.defaultValue));
        null == b.checked && null != b.defaultChecked && (a.defaultChecked = !!b.defaultChecked);
      }
      function db(a, b, c) {
        if (b.hasOwnProperty("value") || b.hasOwnProperty("defaultValue")) {
          var d = b.type;
          if (!("submit" !== d && "reset" !== d || void 0 !== b.value && null !== b.value)) return;
          b = "" + a._wrapperState.initialValue;
          c || b === a.value || (a.value = b);
          a.defaultValue = b;
        }
        c = a.name;
        "" !== c && (a.name = "");
        a.defaultChecked = !!a._wrapperState.initialChecked;
        "" !== c && (a.name = c);
      }
      function cb(a, b, c) {
        if ("number" !== b || Xa(a.ownerDocument) !== a) null == c ? a.defaultValue = "" + a._wrapperState.initialValue : a.defaultValue !== "" + c && (a.defaultValue = "" + c);
      }
      var eb = Array.isArray;
      function fb(a, b, c, d) {
        a = a.options;
        if (b) {
          b = {};
          for (var e = 0; e < c.length; e++) b["$" + c[e]] = true;
          for (c = 0; c < a.length; c++) e = b.hasOwnProperty("$" + a[c].value), a[c].selected !== e && (a[c].selected = e), e && d && (a[c].defaultSelected = true);
        } else {
          c = "" + Sa(c);
          b = null;
          for (e = 0; e < a.length; e++) {
            if (a[e].value === c) {
              a[e].selected = true;
              d && (a[e].defaultSelected = true);
              return;
            }
            null !== b || a[e].disabled || (b = a[e]);
          }
          null !== b && (b.selected = true);
        }
      }
      function gb(a, b) {
        if (null != b.dangerouslySetInnerHTML) throw Error(p(91));
        return A({}, b, { value: void 0, defaultValue: void 0, children: "" + a._wrapperState.initialValue });
      }
      function hb(a, b) {
        var c = b.value;
        if (null == c) {
          c = b.children;
          b = b.defaultValue;
          if (null != c) {
            if (null != b) throw Error(p(92));
            if (eb(c)) {
              if (1 < c.length) throw Error(p(93));
              c = c[0];
            }
            b = c;
          }
          null == b && (b = "");
          c = b;
        }
        a._wrapperState = { initialValue: Sa(c) };
      }
      function ib(a, b) {
        var c = Sa(b.value), d = Sa(b.defaultValue);
        null != c && (c = "" + c, c !== a.value && (a.value = c), null == b.defaultValue && a.defaultValue !== c && (a.defaultValue = c));
        null != d && (a.defaultValue = "" + d);
      }
      function jb(a) {
        var b = a.textContent;
        b === a._wrapperState.initialValue && "" !== b && null !== b && (a.value = b);
      }
      function kb(a) {
        switch (a) {
          case "svg":
            return "http://www.w3.org/2000/svg";
          case "math":
            return "http://www.w3.org/1998/Math/MathML";
          default:
            return "http://www.w3.org/1999/xhtml";
        }
      }
      function lb(a, b) {
        return null == a || "http://www.w3.org/1999/xhtml" === a ? kb(b) : "http://www.w3.org/2000/svg" === a && "foreignObject" === b ? "http://www.w3.org/1999/xhtml" : a;
      }
      var mb;
      var nb = (function(a) {
        return "undefined" !== typeof MSApp && MSApp.execUnsafeLocalFunction ? function(b, c, d, e) {
          MSApp.execUnsafeLocalFunction(function() {
            return a(b, c, d, e);
          });
        } : a;
      })(function(a, b) {
        if ("http://www.w3.org/2000/svg" !== a.namespaceURI || "innerHTML" in a) a.innerHTML = b;
        else {
          mb = mb || document.createElement("div");
          mb.innerHTML = "<svg>" + b.valueOf().toString() + "</svg>";
          for (b = mb.firstChild; a.firstChild; ) a.removeChild(a.firstChild);
          for (; b.firstChild; ) a.appendChild(b.firstChild);
        }
      });
      function ob(a, b) {
        if (b) {
          var c = a.firstChild;
          if (c && c === a.lastChild && 3 === c.nodeType) {
            c.nodeValue = b;
            return;
          }
        }
        a.textContent = b;
      }
      var pb = {
        animationIterationCount: true,
        aspectRatio: true,
        borderImageOutset: true,
        borderImageSlice: true,
        borderImageWidth: true,
        boxFlex: true,
        boxFlexGroup: true,
        boxOrdinalGroup: true,
        columnCount: true,
        columns: true,
        flex: true,
        flexGrow: true,
        flexPositive: true,
        flexShrink: true,
        flexNegative: true,
        flexOrder: true,
        gridArea: true,
        gridRow: true,
        gridRowEnd: true,
        gridRowSpan: true,
        gridRowStart: true,
        gridColumn: true,
        gridColumnEnd: true,
        gridColumnSpan: true,
        gridColumnStart: true,
        fontWeight: true,
        lineClamp: true,
        lineHeight: true,
        opacity: true,
        order: true,
        orphans: true,
        tabSize: true,
        widows: true,
        zIndex: true,
        zoom: true,
        fillOpacity: true,
        floodOpacity: true,
        stopOpacity: true,
        strokeDasharray: true,
        strokeDashoffset: true,
        strokeMiterlimit: true,
        strokeOpacity: true,
        strokeWidth: true
      };
      var qb = ["Webkit", "ms", "Moz", "O"];
      Object.keys(pb).forEach(function(a) {
        qb.forEach(function(b) {
          b = b + a.charAt(0).toUpperCase() + a.substring(1);
          pb[b] = pb[a];
        });
      });
      function rb(a, b, c) {
        return null == b || "boolean" === typeof b || "" === b ? "" : c || "number" !== typeof b || 0 === b || pb.hasOwnProperty(a) && pb[a] ? ("" + b).trim() : b + "px";
      }
      function sb(a, b) {
        a = a.style;
        for (var c in b) if (b.hasOwnProperty(c)) {
          var d = 0 === c.indexOf("--"), e = rb(c, b[c], d);
          "float" === c && (c = "cssFloat");
          d ? a.setProperty(c, e) : a[c] = e;
        }
      }
      var tb = A({ menuitem: true }, { area: true, base: true, br: true, col: true, embed: true, hr: true, img: true, input: true, keygen: true, link: true, meta: true, param: true, source: true, track: true, wbr: true });
      function ub(a, b) {
        if (b) {
          if (tb[a] && (null != b.children || null != b.dangerouslySetInnerHTML)) throw Error(p(137, a));
          if (null != b.dangerouslySetInnerHTML) {
            if (null != b.children) throw Error(p(60));
            if ("object" !== typeof b.dangerouslySetInnerHTML || !("__html" in b.dangerouslySetInnerHTML)) throw Error(p(61));
          }
          if (null != b.style && "object" !== typeof b.style) throw Error(p(62));
        }
      }
      function vb(a, b) {
        if (-1 === a.indexOf("-")) return "string" === typeof b.is;
        switch (a) {
          case "annotation-xml":
          case "color-profile":
          case "font-face":
          case "font-face-src":
          case "font-face-uri":
          case "font-face-format":
          case "font-face-name":
          case "missing-glyph":
            return false;
          default:
            return true;
        }
      }
      var wb = null;
      function xb(a) {
        a = a.target || a.srcElement || window;
        a.correspondingUseElement && (a = a.correspondingUseElement);
        return 3 === a.nodeType ? a.parentNode : a;
      }
      var yb = null;
      var zb = null;
      var Ab = null;
      function Bb(a) {
        if (a = Cb(a)) {
          if ("function" !== typeof yb) throw Error(p(280));
          var b = a.stateNode;
          b && (b = Db(b), yb(a.stateNode, a.type, b));
        }
      }
      function Eb(a) {
        zb ? Ab ? Ab.push(a) : Ab = [a] : zb = a;
      }
      function Fb() {
        if (zb) {
          var a = zb, b = Ab;
          Ab = zb = null;
          Bb(a);
          if (b) for (a = 0; a < b.length; a++) Bb(b[a]);
        }
      }
      function Gb(a, b) {
        return a(b);
      }
      function Hb() {
      }
      var Ib = false;
      function Jb(a, b, c) {
        if (Ib) return a(b, c);
        Ib = true;
        try {
          return Gb(a, b, c);
        } finally {
          if (Ib = false, null !== zb || null !== Ab) Hb(), Fb();
        }
      }
      function Kb(a, b) {
        var c = a.stateNode;
        if (null === c) return null;
        var d = Db(c);
        if (null === d) return null;
        c = d[b];
        a: switch (b) {
          case "onClick":
          case "onClickCapture":
          case "onDoubleClick":
          case "onDoubleClickCapture":
          case "onMouseDown":
          case "onMouseDownCapture":
          case "onMouseMove":
          case "onMouseMoveCapture":
          case "onMouseUp":
          case "onMouseUpCapture":
          case "onMouseEnter":
            (d = !d.disabled) || (a = a.type, d = !("button" === a || "input" === a || "select" === a || "textarea" === a));
            a = !d;
            break a;
          default:
            a = false;
        }
        if (a) return null;
        if (c && "function" !== typeof c) throw Error(p(231, b, typeof c));
        return c;
      }
      var Lb = false;
      if (ia) try {
        Mb = {};
        Object.defineProperty(Mb, "passive", { get: function() {
          Lb = true;
        } });
        window.addEventListener("test", Mb, Mb);
        window.removeEventListener("test", Mb, Mb);
      } catch (a) {
        Lb = false;
      }
      var Mb;
      function Nb(a, b, c, d, e, f, g, h, k) {
        var l = Array.prototype.slice.call(arguments, 3);
        try {
          b.apply(c, l);
        } catch (m) {
          this.onError(m);
        }
      }
      var Ob = false;
      var Pb = null;
      var Qb = false;
      var Rb = null;
      var Sb = { onError: function(a) {
        Ob = true;
        Pb = a;
      } };
      function Tb(a, b, c, d, e, f, g, h, k) {
        Ob = false;
        Pb = null;
        Nb.apply(Sb, arguments);
      }
      function Ub(a, b, c, d, e, f, g, h, k) {
        Tb.apply(this, arguments);
        if (Ob) {
          if (Ob) {
            var l = Pb;
            Ob = false;
            Pb = null;
          } else throw Error(p(198));
          Qb || (Qb = true, Rb = l);
        }
      }
      function Vb(a) {
        var b = a, c = a;
        if (a.alternate) for (; b.return; ) b = b.return;
        else {
          a = b;
          do
            b = a, 0 !== (b.flags & 4098) && (c = b.return), a = b.return;
          while (a);
        }
        return 3 === b.tag ? c : null;
      }
      function Wb(a) {
        if (13 === a.tag) {
          var b = a.memoizedState;
          null === b && (a = a.alternate, null !== a && (b = a.memoizedState));
          if (null !== b) return b.dehydrated;
        }
        return null;
      }
      function Xb(a) {
        if (Vb(a) !== a) throw Error(p(188));
      }
      function Yb(a) {
        var b = a.alternate;
        if (!b) {
          b = Vb(a);
          if (null === b) throw Error(p(188));
          return b !== a ? null : a;
        }
        for (var c = a, d = b; ; ) {
          var e = c.return;
          if (null === e) break;
          var f = e.alternate;
          if (null === f) {
            d = e.return;
            if (null !== d) {
              c = d;
              continue;
            }
            break;
          }
          if (e.child === f.child) {
            for (f = e.child; f; ) {
              if (f === c) return Xb(e), a;
              if (f === d) return Xb(e), b;
              f = f.sibling;
            }
            throw Error(p(188));
          }
          if (c.return !== d.return) c = e, d = f;
          else {
            for (var g = false, h = e.child; h; ) {
              if (h === c) {
                g = true;
                c = e;
                d = f;
                break;
              }
              if (h === d) {
                g = true;
                d = e;
                c = f;
                break;
              }
              h = h.sibling;
            }
            if (!g) {
              for (h = f.child; h; ) {
                if (h === c) {
                  g = true;
                  c = f;
                  d = e;
                  break;
                }
                if (h === d) {
                  g = true;
                  d = f;
                  c = e;
                  break;
                }
                h = h.sibling;
              }
              if (!g) throw Error(p(189));
            }
          }
          if (c.alternate !== d) throw Error(p(190));
        }
        if (3 !== c.tag) throw Error(p(188));
        return c.stateNode.current === c ? a : b;
      }
      function Zb(a) {
        a = Yb(a);
        return null !== a ? $b(a) : null;
      }
      function $b(a) {
        if (5 === a.tag || 6 === a.tag) return a;
        for (a = a.child; null !== a; ) {
          var b = $b(a);
          if (null !== b) return b;
          a = a.sibling;
        }
        return null;
      }
      var ac = ca.unstable_scheduleCallback;
      var bc = ca.unstable_cancelCallback;
      var cc = ca.unstable_shouldYield;
      var dc = ca.unstable_requestPaint;
      var B = ca.unstable_now;
      var ec = ca.unstable_getCurrentPriorityLevel;
      var fc = ca.unstable_ImmediatePriority;
      var gc = ca.unstable_UserBlockingPriority;
      var hc = ca.unstable_NormalPriority;
      var ic = ca.unstable_LowPriority;
      var jc = ca.unstable_IdlePriority;
      var kc = null;
      var lc = null;
      function mc(a) {
        if (lc && "function" === typeof lc.onCommitFiberRoot) try {
          lc.onCommitFiberRoot(kc, a, void 0, 128 === (a.current.flags & 128));
        } catch (b) {
        }
      }
      var oc = Math.clz32 ? Math.clz32 : nc;
      var pc = Math.log;
      var qc = Math.LN2;
      function nc(a) {
        a >>>= 0;
        return 0 === a ? 32 : 31 - (pc(a) / qc | 0) | 0;
      }
      var rc = 64;
      var sc = 4194304;
      function tc(a) {
        switch (a & -a) {
          case 1:
            return 1;
          case 2:
            return 2;
          case 4:
            return 4;
          case 8:
            return 8;
          case 16:
            return 16;
          case 32:
            return 32;
          case 64:
          case 128:
          case 256:
          case 512:
          case 1024:
          case 2048:
          case 4096:
          case 8192:
          case 16384:
          case 32768:
          case 65536:
          case 131072:
          case 262144:
          case 524288:
          case 1048576:
          case 2097152:
            return a & 4194240;
          case 4194304:
          case 8388608:
          case 16777216:
          case 33554432:
          case 67108864:
            return a & 130023424;
          case 134217728:
            return 134217728;
          case 268435456:
            return 268435456;
          case 536870912:
            return 536870912;
          case 1073741824:
            return 1073741824;
          default:
            return a;
        }
      }
      function uc(a, b) {
        var c = a.pendingLanes;
        if (0 === c) return 0;
        var d = 0, e = a.suspendedLanes, f = a.pingedLanes, g = c & 268435455;
        if (0 !== g) {
          var h = g & ~e;
          0 !== h ? d = tc(h) : (f &= g, 0 !== f && (d = tc(f)));
        } else g = c & ~e, 0 !== g ? d = tc(g) : 0 !== f && (d = tc(f));
        if (0 === d) return 0;
        if (0 !== b && b !== d && 0 === (b & e) && (e = d & -d, f = b & -b, e >= f || 16 === e && 0 !== (f & 4194240))) return b;
        0 !== (d & 4) && (d |= c & 16);
        b = a.entangledLanes;
        if (0 !== b) for (a = a.entanglements, b &= d; 0 < b; ) c = 31 - oc(b), e = 1 << c, d |= a[c], b &= ~e;
        return d;
      }
      function vc(a, b) {
        switch (a) {
          case 1:
          case 2:
          case 4:
            return b + 250;
          case 8:
          case 16:
          case 32:
          case 64:
          case 128:
          case 256:
          case 512:
          case 1024:
          case 2048:
          case 4096:
          case 8192:
          case 16384:
          case 32768:
          case 65536:
          case 131072:
          case 262144:
          case 524288:
          case 1048576:
          case 2097152:
            return b + 5e3;
          case 4194304:
          case 8388608:
          case 16777216:
          case 33554432:
          case 67108864:
            return -1;
          case 134217728:
          case 268435456:
          case 536870912:
          case 1073741824:
            return -1;
          default:
            return -1;
        }
      }
      function wc(a, b) {
        for (var c = a.suspendedLanes, d = a.pingedLanes, e = a.expirationTimes, f = a.pendingLanes; 0 < f; ) {
          var g = 31 - oc(f), h = 1 << g, k = e[g];
          if (-1 === k) {
            if (0 === (h & c) || 0 !== (h & d)) e[g] = vc(h, b);
          } else k <= b && (a.expiredLanes |= h);
          f &= ~h;
        }
      }
      function xc(a) {
        a = a.pendingLanes & -1073741825;
        return 0 !== a ? a : a & 1073741824 ? 1073741824 : 0;
      }
      function yc() {
        var a = rc;
        rc <<= 1;
        0 === (rc & 4194240) && (rc = 64);
        return a;
      }
      function zc(a) {
        for (var b = [], c = 0; 31 > c; c++) b.push(a);
        return b;
      }
      function Ac(a, b, c) {
        a.pendingLanes |= b;
        536870912 !== b && (a.suspendedLanes = 0, a.pingedLanes = 0);
        a = a.eventTimes;
        b = 31 - oc(b);
        a[b] = c;
      }
      function Bc(a, b) {
        var c = a.pendingLanes & ~b;
        a.pendingLanes = b;
        a.suspendedLanes = 0;
        a.pingedLanes = 0;
        a.expiredLanes &= b;
        a.mutableReadLanes &= b;
        a.entangledLanes &= b;
        b = a.entanglements;
        var d = a.eventTimes;
        for (a = a.expirationTimes; 0 < c; ) {
          var e = 31 - oc(c), f = 1 << e;
          b[e] = 0;
          d[e] = -1;
          a[e] = -1;
          c &= ~f;
        }
      }
      function Cc(a, b) {
        var c = a.entangledLanes |= b;
        for (a = a.entanglements; c; ) {
          var d = 31 - oc(c), e = 1 << d;
          e & b | a[d] & b && (a[d] |= b);
          c &= ~e;
        }
      }
      var C = 0;
      function Dc(a) {
        a &= -a;
        return 1 < a ? 4 < a ? 0 !== (a & 268435455) ? 16 : 536870912 : 4 : 1;
      }
      var Ec;
      var Fc;
      var Gc;
      var Hc;
      var Ic;
      var Jc = false;
      var Kc = [];
      var Lc = null;
      var Mc = null;
      var Nc = null;
      var Oc = /* @__PURE__ */ new Map();
      var Pc = /* @__PURE__ */ new Map();
      var Qc = [];
      var Rc = "mousedown mouseup touchcancel touchend touchstart auxclick dblclick pointercancel pointerdown pointerup dragend dragstart drop compositionend compositionstart keydown keypress keyup input textInput copy cut paste click change contextmenu reset submit".split(" ");
      function Sc(a, b) {
        switch (a) {
          case "focusin":
          case "focusout":
            Lc = null;
            break;
          case "dragenter":
          case "dragleave":
            Mc = null;
            break;
          case "mouseover":
          case "mouseout":
            Nc = null;
            break;
          case "pointerover":
          case "pointerout":
            Oc.delete(b.pointerId);
            break;
          case "gotpointercapture":
          case "lostpointercapture":
            Pc.delete(b.pointerId);
        }
      }
      function Tc(a, b, c, d, e, f) {
        if (null === a || a.nativeEvent !== f) return a = { blockedOn: b, domEventName: c, eventSystemFlags: d, nativeEvent: f, targetContainers: [e] }, null !== b && (b = Cb(b), null !== b && Fc(b)), a;
        a.eventSystemFlags |= d;
        b = a.targetContainers;
        null !== e && -1 === b.indexOf(e) && b.push(e);
        return a;
      }
      function Uc(a, b, c, d, e) {
        switch (b) {
          case "focusin":
            return Lc = Tc(Lc, a, b, c, d, e), true;
          case "dragenter":
            return Mc = Tc(Mc, a, b, c, d, e), true;
          case "mouseover":
            return Nc = Tc(Nc, a, b, c, d, e), true;
          case "pointerover":
            var f = e.pointerId;
            Oc.set(f, Tc(Oc.get(f) || null, a, b, c, d, e));
            return true;
          case "gotpointercapture":
            return f = e.pointerId, Pc.set(f, Tc(Pc.get(f) || null, a, b, c, d, e)), true;
        }
        return false;
      }
      function Vc(a) {
        var b = Wc(a.target);
        if (null !== b) {
          var c = Vb(b);
          if (null !== c) {
            if (b = c.tag, 13 === b) {
              if (b = Wb(c), null !== b) {
                a.blockedOn = b;
                Ic(a.priority, function() {
                  Gc(c);
                });
                return;
              }
            } else if (3 === b && c.stateNode.current.memoizedState.isDehydrated) {
              a.blockedOn = 3 === c.tag ? c.stateNode.containerInfo : null;
              return;
            }
          }
        }
        a.blockedOn = null;
      }
      function Xc(a) {
        if (null !== a.blockedOn) return false;
        for (var b = a.targetContainers; 0 < b.length; ) {
          var c = Yc(a.domEventName, a.eventSystemFlags, b[0], a.nativeEvent);
          if (null === c) {
            c = a.nativeEvent;
            var d = new c.constructor(c.type, c);
            wb = d;
            c.target.dispatchEvent(d);
            wb = null;
          } else return b = Cb(c), null !== b && Fc(b), a.blockedOn = c, false;
          b.shift();
        }
        return true;
      }
      function Zc(a, b, c) {
        Xc(a) && c.delete(b);
      }
      function $c() {
        Jc = false;
        null !== Lc && Xc(Lc) && (Lc = null);
        null !== Mc && Xc(Mc) && (Mc = null);
        null !== Nc && Xc(Nc) && (Nc = null);
        Oc.forEach(Zc);
        Pc.forEach(Zc);
      }
      function ad(a, b) {
        a.blockedOn === b && (a.blockedOn = null, Jc || (Jc = true, ca.unstable_scheduleCallback(ca.unstable_NormalPriority, $c)));
      }
      function bd(a) {
        function b(b2) {
          return ad(b2, a);
        }
        if (0 < Kc.length) {
          ad(Kc[0], a);
          for (var c = 1; c < Kc.length; c++) {
            var d = Kc[c];
            d.blockedOn === a && (d.blockedOn = null);
          }
        }
        null !== Lc && ad(Lc, a);
        null !== Mc && ad(Mc, a);
        null !== Nc && ad(Nc, a);
        Oc.forEach(b);
        Pc.forEach(b);
        for (c = 0; c < Qc.length; c++) d = Qc[c], d.blockedOn === a && (d.blockedOn = null);
        for (; 0 < Qc.length && (c = Qc[0], null === c.blockedOn); ) Vc(c), null === c.blockedOn && Qc.shift();
      }
      var cd = ua.ReactCurrentBatchConfig;
      var dd = true;
      function ed(a, b, c, d) {
        var e = C, f = cd.transition;
        cd.transition = null;
        try {
          C = 1, fd(a, b, c, d);
        } finally {
          C = e, cd.transition = f;
        }
      }
      function gd(a, b, c, d) {
        var e = C, f = cd.transition;
        cd.transition = null;
        try {
          C = 4, fd(a, b, c, d);
        } finally {
          C = e, cd.transition = f;
        }
      }
      function fd(a, b, c, d) {
        if (dd) {
          var e = Yc(a, b, c, d);
          if (null === e) hd(a, b, d, id, c), Sc(a, d);
          else if (Uc(e, a, b, c, d)) d.stopPropagation();
          else if (Sc(a, d), b & 4 && -1 < Rc.indexOf(a)) {
            for (; null !== e; ) {
              var f = Cb(e);
              null !== f && Ec(f);
              f = Yc(a, b, c, d);
              null === f && hd(a, b, d, id, c);
              if (f === e) break;
              e = f;
            }
            null !== e && d.stopPropagation();
          } else hd(a, b, d, null, c);
        }
      }
      var id = null;
      function Yc(a, b, c, d) {
        id = null;
        a = xb(d);
        a = Wc(a);
        if (null !== a) if (b = Vb(a), null === b) a = null;
        else if (c = b.tag, 13 === c) {
          a = Wb(b);
          if (null !== a) return a;
          a = null;
        } else if (3 === c) {
          if (b.stateNode.current.memoizedState.isDehydrated) return 3 === b.tag ? b.stateNode.containerInfo : null;
          a = null;
        } else b !== a && (a = null);
        id = a;
        return null;
      }
      function jd(a) {
        switch (a) {
          case "cancel":
          case "click":
          case "close":
          case "contextmenu":
          case "copy":
          case "cut":
          case "auxclick":
          case "dblclick":
          case "dragend":
          case "dragstart":
          case "drop":
          case "focusin":
          case "focusout":
          case "input":
          case "invalid":
          case "keydown":
          case "keypress":
          case "keyup":
          case "mousedown":
          case "mouseup":
          case "paste":
          case "pause":
          case "play":
          case "pointercancel":
          case "pointerdown":
          case "pointerup":
          case "ratechange":
          case "reset":
          case "resize":
          case "seeked":
          case "submit":
          case "touchcancel":
          case "touchend":
          case "touchstart":
          case "volumechange":
          case "change":
          case "selectionchange":
          case "textInput":
          case "compositionstart":
          case "compositionend":
          case "compositionupdate":
          case "beforeblur":
          case "afterblur":
          case "beforeinput":
          case "blur":
          case "fullscreenchange":
          case "focus":
          case "hashchange":
          case "popstate":
          case "select":
          case "selectstart":
            return 1;
          case "drag":
          case "dragenter":
          case "dragexit":
          case "dragleave":
          case "dragover":
          case "mousemove":
          case "mouseout":
          case "mouseover":
          case "pointermove":
          case "pointerout":
          case "pointerover":
          case "scroll":
          case "toggle":
          case "touchmove":
          case "wheel":
          case "mouseenter":
          case "mouseleave":
          case "pointerenter":
          case "pointerleave":
            return 4;
          case "message":
            switch (ec()) {
              case fc:
                return 1;
              case gc:
                return 4;
              case hc:
              case ic:
                return 16;
              case jc:
                return 536870912;
              default:
                return 16;
            }
          default:
            return 16;
        }
      }
      var kd = null;
      var ld = null;
      var md = null;
      function nd() {
        if (md) return md;
        var a, b = ld, c = b.length, d, e = "value" in kd ? kd.value : kd.textContent, f = e.length;
        for (a = 0; a < c && b[a] === e[a]; a++) ;
        var g = c - a;
        for (d = 1; d <= g && b[c - d] === e[f - d]; d++) ;
        return md = e.slice(a, 1 < d ? 1 - d : void 0);
      }
      function od(a) {
        var b = a.keyCode;
        "charCode" in a ? (a = a.charCode, 0 === a && 13 === b && (a = 13)) : a = b;
        10 === a && (a = 13);
        return 32 <= a || 13 === a ? a : 0;
      }
      function pd() {
        return true;
      }
      function qd() {
        return false;
      }
      function rd(a) {
        function b(b2, d, e, f, g) {
          this._reactName = b2;
          this._targetInst = e;
          this.type = d;
          this.nativeEvent = f;
          this.target = g;
          this.currentTarget = null;
          for (var c in a) a.hasOwnProperty(c) && (b2 = a[c], this[c] = b2 ? b2(f) : f[c]);
          this.isDefaultPrevented = (null != f.defaultPrevented ? f.defaultPrevented : false === f.returnValue) ? pd : qd;
          this.isPropagationStopped = qd;
          return this;
        }
        A(b.prototype, { preventDefault: function() {
          this.defaultPrevented = true;
          var a2 = this.nativeEvent;
          a2 && (a2.preventDefault ? a2.preventDefault() : "unknown" !== typeof a2.returnValue && (a2.returnValue = false), this.isDefaultPrevented = pd);
        }, stopPropagation: function() {
          var a2 = this.nativeEvent;
          a2 && (a2.stopPropagation ? a2.stopPropagation() : "unknown" !== typeof a2.cancelBubble && (a2.cancelBubble = true), this.isPropagationStopped = pd);
        }, persist: function() {
        }, isPersistent: pd });
        return b;
      }
      var sd = { eventPhase: 0, bubbles: 0, cancelable: 0, timeStamp: function(a) {
        return a.timeStamp || Date.now();
      }, defaultPrevented: 0, isTrusted: 0 };
      var td = rd(sd);
      var ud = A({}, sd, { view: 0, detail: 0 });
      var vd = rd(ud);
      var wd;
      var xd;
      var yd;
      var Ad = A({}, ud, { screenX: 0, screenY: 0, clientX: 0, clientY: 0, pageX: 0, pageY: 0, ctrlKey: 0, shiftKey: 0, altKey: 0, metaKey: 0, getModifierState: zd, button: 0, buttons: 0, relatedTarget: function(a) {
        return void 0 === a.relatedTarget ? a.fromElement === a.srcElement ? a.toElement : a.fromElement : a.relatedTarget;
      }, movementX: function(a) {
        if ("movementX" in a) return a.movementX;
        a !== yd && (yd && "mousemove" === a.type ? (wd = a.screenX - yd.screenX, xd = a.screenY - yd.screenY) : xd = wd = 0, yd = a);
        return wd;
      }, movementY: function(a) {
        return "movementY" in a ? a.movementY : xd;
      } });
      var Bd = rd(Ad);
      var Cd = A({}, Ad, { dataTransfer: 0 });
      var Dd = rd(Cd);
      var Ed = A({}, ud, { relatedTarget: 0 });
      var Fd = rd(Ed);
      var Gd = A({}, sd, { animationName: 0, elapsedTime: 0, pseudoElement: 0 });
      var Hd = rd(Gd);
      var Id = A({}, sd, { clipboardData: function(a) {
        return "clipboardData" in a ? a.clipboardData : window.clipboardData;
      } });
      var Jd = rd(Id);
      var Kd = A({}, sd, { data: 0 });
      var Ld = rd(Kd);
      var Md = {
        Esc: "Escape",
        Spacebar: " ",
        Left: "ArrowLeft",
        Up: "ArrowUp",
        Right: "ArrowRight",
        Down: "ArrowDown",
        Del: "Delete",
        Win: "OS",
        Menu: "ContextMenu",
        Apps: "ContextMenu",
        Scroll: "ScrollLock",
        MozPrintableKey: "Unidentified"
      };
      var Nd = {
        8: "Backspace",
        9: "Tab",
        12: "Clear",
        13: "Enter",
        16: "Shift",
        17: "Control",
        18: "Alt",
        19: "Pause",
        20: "CapsLock",
        27: "Escape",
        32: " ",
        33: "PageUp",
        34: "PageDown",
        35: "End",
        36: "Home",
        37: "ArrowLeft",
        38: "ArrowUp",
        39: "ArrowRight",
        40: "ArrowDown",
        45: "Insert",
        46: "Delete",
        112: "F1",
        113: "F2",
        114: "F3",
        115: "F4",
        116: "F5",
        117: "F6",
        118: "F7",
        119: "F8",
        120: "F9",
        121: "F10",
        122: "F11",
        123: "F12",
        144: "NumLock",
        145: "ScrollLock",
        224: "Meta"
      };
      var Od = { Alt: "altKey", Control: "ctrlKey", Meta: "metaKey", Shift: "shiftKey" };
      function Pd(a) {
        var b = this.nativeEvent;
        return b.getModifierState ? b.getModifierState(a) : (a = Od[a]) ? !!b[a] : false;
      }
      function zd() {
        return Pd;
      }
      var Qd = A({}, ud, { key: function(a) {
        if (a.key) {
          var b = Md[a.key] || a.key;
          if ("Unidentified" !== b) return b;
        }
        return "keypress" === a.type ? (a = od(a), 13 === a ? "Enter" : String.fromCharCode(a)) : "keydown" === a.type || "keyup" === a.type ? Nd[a.keyCode] || "Unidentified" : "";
      }, code: 0, location: 0, ctrlKey: 0, shiftKey: 0, altKey: 0, metaKey: 0, repeat: 0, locale: 0, getModifierState: zd, charCode: function(a) {
        return "keypress" === a.type ? od(a) : 0;
      }, keyCode: function(a) {
        return "keydown" === a.type || "keyup" === a.type ? a.keyCode : 0;
      }, which: function(a) {
        return "keypress" === a.type ? od(a) : "keydown" === a.type || "keyup" === a.type ? a.keyCode : 0;
      } });
      var Rd = rd(Qd);
      var Sd = A({}, Ad, { pointerId: 0, width: 0, height: 0, pressure: 0, tangentialPressure: 0, tiltX: 0, tiltY: 0, twist: 0, pointerType: 0, isPrimary: 0 });
      var Td = rd(Sd);
      var Ud = A({}, ud, { touches: 0, targetTouches: 0, changedTouches: 0, altKey: 0, metaKey: 0, ctrlKey: 0, shiftKey: 0, getModifierState: zd });
      var Vd = rd(Ud);
      var Wd = A({}, sd, { propertyName: 0, elapsedTime: 0, pseudoElement: 0 });
      var Xd = rd(Wd);
      var Yd = A({}, Ad, {
        deltaX: function(a) {
          return "deltaX" in a ? a.deltaX : "wheelDeltaX" in a ? -a.wheelDeltaX : 0;
        },
        deltaY: function(a) {
          return "deltaY" in a ? a.deltaY : "wheelDeltaY" in a ? -a.wheelDeltaY : "wheelDelta" in a ? -a.wheelDelta : 0;
        },
        deltaZ: 0,
        deltaMode: 0
      });
      var Zd = rd(Yd);
      var $d = [9, 13, 27, 32];
      var ae = ia && "CompositionEvent" in window;
      var be = null;
      ia && "documentMode" in document && (be = document.documentMode);
      var ce = ia && "TextEvent" in window && !be;
      var de = ia && (!ae || be && 8 < be && 11 >= be);
      var ee = String.fromCharCode(32);
      var fe = false;
      function ge(a, b) {
        switch (a) {
          case "keyup":
            return -1 !== $d.indexOf(b.keyCode);
          case "keydown":
            return 229 !== b.keyCode;
          case "keypress":
          case "mousedown":
          case "focusout":
            return true;
          default:
            return false;
        }
      }
      function he(a) {
        a = a.detail;
        return "object" === typeof a && "data" in a ? a.data : null;
      }
      var ie = false;
      function je(a, b) {
        switch (a) {
          case "compositionend":
            return he(b);
          case "keypress":
            if (32 !== b.which) return null;
            fe = true;
            return ee;
          case "textInput":
            return a = b.data, a === ee && fe ? null : a;
          default:
            return null;
        }
      }
      function ke(a, b) {
        if (ie) return "compositionend" === a || !ae && ge(a, b) ? (a = nd(), md = ld = kd = null, ie = false, a) : null;
        switch (a) {
          case "paste":
            return null;
          case "keypress":
            if (!(b.ctrlKey || b.altKey || b.metaKey) || b.ctrlKey && b.altKey) {
              if (b.char && 1 < b.char.length) return b.char;
              if (b.which) return String.fromCharCode(b.which);
            }
            return null;
          case "compositionend":
            return de && "ko" !== b.locale ? null : b.data;
          default:
            return null;
        }
      }
      var le = { color: true, date: true, datetime: true, "datetime-local": true, email: true, month: true, number: true, password: true, range: true, search: true, tel: true, text: true, time: true, url: true, week: true };
      function me(a) {
        var b = a && a.nodeName && a.nodeName.toLowerCase();
        return "input" === b ? !!le[a.type] : "textarea" === b ? true : false;
      }
      function ne(a, b, c, d) {
        Eb(d);
        b = oe(b, "onChange");
        0 < b.length && (c = new td("onChange", "change", null, c, d), a.push({ event: c, listeners: b }));
      }
      var pe = null;
      var qe = null;
      function re(a) {
        se(a, 0);
      }
      function te(a) {
        var b = ue(a);
        if (Wa(b)) return a;
      }
      function ve(a, b) {
        if ("change" === a) return b;
      }
      var we = false;
      if (ia) {
        if (ia) {
          ye = "oninput" in document;
          if (!ye) {
            ze = document.createElement("div");
            ze.setAttribute("oninput", "return;");
            ye = "function" === typeof ze.oninput;
          }
          xe = ye;
        } else xe = false;
        we = xe && (!document.documentMode || 9 < document.documentMode);
      }
      var xe;
      var ye;
      var ze;
      function Ae() {
        pe && (pe.detachEvent("onpropertychange", Be), qe = pe = null);
      }
      function Be(a) {
        if ("value" === a.propertyName && te(qe)) {
          var b = [];
          ne(b, qe, a, xb(a));
          Jb(re, b);
        }
      }
      function Ce(a, b, c) {
        "focusin" === a ? (Ae(), pe = b, qe = c, pe.attachEvent("onpropertychange", Be)) : "focusout" === a && Ae();
      }
      function De(a) {
        if ("selectionchange" === a || "keyup" === a || "keydown" === a) return te(qe);
      }
      function Ee(a, b) {
        if ("click" === a) return te(b);
      }
      function Fe(a, b) {
        if ("input" === a || "change" === a) return te(b);
      }
      function Ge(a, b) {
        return a === b && (0 !== a || 1 / a === 1 / b) || a !== a && b !== b;
      }
      var He = "function" === typeof Object.is ? Object.is : Ge;
      function Ie(a, b) {
        if (He(a, b)) return true;
        if ("object" !== typeof a || null === a || "object" !== typeof b || null === b) return false;
        var c = Object.keys(a), d = Object.keys(b);
        if (c.length !== d.length) return false;
        for (d = 0; d < c.length; d++) {
          var e = c[d];
          if (!ja.call(b, e) || !He(a[e], b[e])) return false;
        }
        return true;
      }
      function Je(a) {
        for (; a && a.firstChild; ) a = a.firstChild;
        return a;
      }
      function Ke(a, b) {
        var c = Je(a);
        a = 0;
        for (var d; c; ) {
          if (3 === c.nodeType) {
            d = a + c.textContent.length;
            if (a <= b && d >= b) return { node: c, offset: b - a };
            a = d;
          }
          a: {
            for (; c; ) {
              if (c.nextSibling) {
                c = c.nextSibling;
                break a;
              }
              c = c.parentNode;
            }
            c = void 0;
          }
          c = Je(c);
        }
      }
      function Le(a, b) {
        return a && b ? a === b ? true : a && 3 === a.nodeType ? false : b && 3 === b.nodeType ? Le(a, b.parentNode) : "contains" in a ? a.contains(b) : a.compareDocumentPosition ? !!(a.compareDocumentPosition(b) & 16) : false : false;
      }
      function Me() {
        for (var a = window, b = Xa(); b instanceof a.HTMLIFrameElement; ) {
          try {
            var c = "string" === typeof b.contentWindow.location.href;
          } catch (d) {
            c = false;
          }
          if (c) a = b.contentWindow;
          else break;
          b = Xa(a.document);
        }
        return b;
      }
      function Ne(a) {
        var b = a && a.nodeName && a.nodeName.toLowerCase();
        return b && ("input" === b && ("text" === a.type || "search" === a.type || "tel" === a.type || "url" === a.type || "password" === a.type) || "textarea" === b || "true" === a.contentEditable);
      }
      function Oe(a) {
        var b = Me(), c = a.focusedElem, d = a.selectionRange;
        if (b !== c && c && c.ownerDocument && Le(c.ownerDocument.documentElement, c)) {
          if (null !== d && Ne(c)) {
            if (b = d.start, a = d.end, void 0 === a && (a = b), "selectionStart" in c) c.selectionStart = b, c.selectionEnd = Math.min(a, c.value.length);
            else if (a = (b = c.ownerDocument || document) && b.defaultView || window, a.getSelection) {
              a = a.getSelection();
              var e = c.textContent.length, f = Math.min(d.start, e);
              d = void 0 === d.end ? f : Math.min(d.end, e);
              !a.extend && f > d && (e = d, d = f, f = e);
              e = Ke(c, f);
              var g = Ke(
                c,
                d
              );
              e && g && (1 !== a.rangeCount || a.anchorNode !== e.node || a.anchorOffset !== e.offset || a.focusNode !== g.node || a.focusOffset !== g.offset) && (b = b.createRange(), b.setStart(e.node, e.offset), a.removeAllRanges(), f > d ? (a.addRange(b), a.extend(g.node, g.offset)) : (b.setEnd(g.node, g.offset), a.addRange(b)));
            }
          }
          b = [];
          for (a = c; a = a.parentNode; ) 1 === a.nodeType && b.push({ element: a, left: a.scrollLeft, top: a.scrollTop });
          "function" === typeof c.focus && c.focus();
          for (c = 0; c < b.length; c++) a = b[c], a.element.scrollLeft = a.left, a.element.scrollTop = a.top;
        }
      }
      var Pe = ia && "documentMode" in document && 11 >= document.documentMode;
      var Qe = null;
      var Re = null;
      var Se = null;
      var Te = false;
      function Ue(a, b, c) {
        var d = c.window === c ? c.document : 9 === c.nodeType ? c : c.ownerDocument;
        Te || null == Qe || Qe !== Xa(d) || (d = Qe, "selectionStart" in d && Ne(d) ? d = { start: d.selectionStart, end: d.selectionEnd } : (d = (d.ownerDocument && d.ownerDocument.defaultView || window).getSelection(), d = { anchorNode: d.anchorNode, anchorOffset: d.anchorOffset, focusNode: d.focusNode, focusOffset: d.focusOffset }), Se && Ie(Se, d) || (Se = d, d = oe(Re, "onSelect"), 0 < d.length && (b = new td("onSelect", "select", null, b, c), a.push({ event: b, listeners: d }), b.target = Qe)));
      }
      function Ve(a, b) {
        var c = {};
        c[a.toLowerCase()] = b.toLowerCase();
        c["Webkit" + a] = "webkit" + b;
        c["Moz" + a] = "moz" + b;
        return c;
      }
      var We = { animationend: Ve("Animation", "AnimationEnd"), animationiteration: Ve("Animation", "AnimationIteration"), animationstart: Ve("Animation", "AnimationStart"), transitionend: Ve("Transition", "TransitionEnd") };
      var Xe = {};
      var Ye = {};
      ia && (Ye = document.createElement("div").style, "AnimationEvent" in window || (delete We.animationend.animation, delete We.animationiteration.animation, delete We.animationstart.animation), "TransitionEvent" in window || delete We.transitionend.transition);
      function Ze(a) {
        if (Xe[a]) return Xe[a];
        if (!We[a]) return a;
        var b = We[a], c;
        for (c in b) if (b.hasOwnProperty(c) && c in Ye) return Xe[a] = b[c];
        return a;
      }
      var $e = Ze("animationend");
      var af = Ze("animationiteration");
      var bf = Ze("animationstart");
      var cf = Ze("transitionend");
      var df = /* @__PURE__ */ new Map();
      var ef = "abort auxClick cancel canPlay canPlayThrough click close contextMenu copy cut drag dragEnd dragEnter dragExit dragLeave dragOver dragStart drop durationChange emptied encrypted ended error gotPointerCapture input invalid keyDown keyPress keyUp load loadedData loadedMetadata loadStart lostPointerCapture mouseDown mouseMove mouseOut mouseOver mouseUp paste pause play playing pointerCancel pointerDown pointerMove pointerOut pointerOver pointerUp progress rateChange reset resize seeked seeking stalled submit suspend timeUpdate touchCancel touchEnd touchStart volumeChange scroll toggle touchMove waiting wheel".split(" ");
      function ff(a, b) {
        df.set(a, b);
        fa(b, [a]);
      }
      for (gf = 0; gf < ef.length; gf++) {
        hf = ef[gf], jf = hf.toLowerCase(), kf = hf[0].toUpperCase() + hf.slice(1);
        ff(jf, "on" + kf);
      }
      var hf;
      var jf;
      var kf;
      var gf;
      ff($e, "onAnimationEnd");
      ff(af, "onAnimationIteration");
      ff(bf, "onAnimationStart");
      ff("dblclick", "onDoubleClick");
      ff("focusin", "onFocus");
      ff("focusout", "onBlur");
      ff(cf, "onTransitionEnd");
      ha("onMouseEnter", ["mouseout", "mouseover"]);
      ha("onMouseLeave", ["mouseout", "mouseover"]);
      ha("onPointerEnter", ["pointerout", "pointerover"]);
      ha("onPointerLeave", ["pointerout", "pointerover"]);
      fa("onChange", "change click focusin focusout input keydown keyup selectionchange".split(" "));
      fa("onSelect", "focusout contextmenu dragend focusin keydown keyup mousedown mouseup selectionchange".split(" "));
      fa("onBeforeInput", ["compositionend", "keypress", "textInput", "paste"]);
      fa("onCompositionEnd", "compositionend focusout keydown keypress keyup mousedown".split(" "));
      fa("onCompositionStart", "compositionstart focusout keydown keypress keyup mousedown".split(" "));
      fa("onCompositionUpdate", "compositionupdate focusout keydown keypress keyup mousedown".split(" "));
      var lf = "abort canplay canplaythrough durationchange emptied encrypted ended error loadeddata loadedmetadata loadstart pause play playing progress ratechange resize seeked seeking stalled suspend timeupdate volumechange waiting".split(" ");
      var mf = new Set("cancel close invalid load scroll toggle".split(" ").concat(lf));
      function nf(a, b, c) {
        var d = a.type || "unknown-event";
        a.currentTarget = c;
        Ub(d, b, void 0, a);
        a.currentTarget = null;
      }
      function se(a, b) {
        b = 0 !== (b & 4);
        for (var c = 0; c < a.length; c++) {
          var d = a[c], e = d.event;
          d = d.listeners;
          a: {
            var f = void 0;
            if (b) for (var g = d.length - 1; 0 <= g; g--) {
              var h = d[g], k = h.instance, l = h.currentTarget;
              h = h.listener;
              if (k !== f && e.isPropagationStopped()) break a;
              nf(e, h, l);
              f = k;
            }
            else for (g = 0; g < d.length; g++) {
              h = d[g];
              k = h.instance;
              l = h.currentTarget;
              h = h.listener;
              if (k !== f && e.isPropagationStopped()) break a;
              nf(e, h, l);
              f = k;
            }
          }
        }
        if (Qb) throw a = Rb, Qb = false, Rb = null, a;
      }
      function D(a, b) {
        var c = b[of];
        void 0 === c && (c = b[of] = /* @__PURE__ */ new Set());
        var d = a + "__bubble";
        c.has(d) || (pf(b, a, 2, false), c.add(d));
      }
      function qf(a, b, c) {
        var d = 0;
        b && (d |= 4);
        pf(c, a, d, b);
      }
      var rf = "_reactListening" + Math.random().toString(36).slice(2);
      function sf(a) {
        if (!a[rf]) {
          a[rf] = true;
          da.forEach(function(b2) {
            "selectionchange" !== b2 && (mf.has(b2) || qf(b2, false, a), qf(b2, true, a));
          });
          var b = 9 === a.nodeType ? a : a.ownerDocument;
          null === b || b[rf] || (b[rf] = true, qf("selectionchange", false, b));
        }
      }
      function pf(a, b, c, d) {
        switch (jd(b)) {
          case 1:
            var e = ed;
            break;
          case 4:
            e = gd;
            break;
          default:
            e = fd;
        }
        c = e.bind(null, b, c, a);
        e = void 0;
        !Lb || "touchstart" !== b && "touchmove" !== b && "wheel" !== b || (e = true);
        d ? void 0 !== e ? a.addEventListener(b, c, { capture: true, passive: e }) : a.addEventListener(b, c, true) : void 0 !== e ? a.addEventListener(b, c, { passive: e }) : a.addEventListener(b, c, false);
      }
      function hd(a, b, c, d, e) {
        var f = d;
        if (0 === (b & 1) && 0 === (b & 2) && null !== d) a: for (; ; ) {
          if (null === d) return;
          var g = d.tag;
          if (3 === g || 4 === g) {
            var h = d.stateNode.containerInfo;
            if (h === e || 8 === h.nodeType && h.parentNode === e) break;
            if (4 === g) for (g = d.return; null !== g; ) {
              var k = g.tag;
              if (3 === k || 4 === k) {
                if (k = g.stateNode.containerInfo, k === e || 8 === k.nodeType && k.parentNode === e) return;
              }
              g = g.return;
            }
            for (; null !== h; ) {
              g = Wc(h);
              if (null === g) return;
              k = g.tag;
              if (5 === k || 6 === k) {
                d = f = g;
                continue a;
              }
              h = h.parentNode;
            }
          }
          d = d.return;
        }
        Jb(function() {
          var d2 = f, e2 = xb(c), g2 = [];
          a: {
            var h2 = df.get(a);
            if (void 0 !== h2) {
              var k2 = td, n = a;
              switch (a) {
                case "keypress":
                  if (0 === od(c)) break a;
                case "keydown":
                case "keyup":
                  k2 = Rd;
                  break;
                case "focusin":
                  n = "focus";
                  k2 = Fd;
                  break;
                case "focusout":
                  n = "blur";
                  k2 = Fd;
                  break;
                case "beforeblur":
                case "afterblur":
                  k2 = Fd;
                  break;
                case "click":
                  if (2 === c.button) break a;
                case "auxclick":
                case "dblclick":
                case "mousedown":
                case "mousemove":
                case "mouseup":
                case "mouseout":
                case "mouseover":
                case "contextmenu":
                  k2 = Bd;
                  break;
                case "drag":
                case "dragend":
                case "dragenter":
                case "dragexit":
                case "dragleave":
                case "dragover":
                case "dragstart":
                case "drop":
                  k2 = Dd;
                  break;
                case "touchcancel":
                case "touchend":
                case "touchmove":
                case "touchstart":
                  k2 = Vd;
                  break;
                case $e:
                case af:
                case bf:
                  k2 = Hd;
                  break;
                case cf:
                  k2 = Xd;
                  break;
                case "scroll":
                  k2 = vd;
                  break;
                case "wheel":
                  k2 = Zd;
                  break;
                case "copy":
                case "cut":
                case "paste":
                  k2 = Jd;
                  break;
                case "gotpointercapture":
                case "lostpointercapture":
                case "pointercancel":
                case "pointerdown":
                case "pointermove":
                case "pointerout":
                case "pointerover":
                case "pointerup":
                  k2 = Td;
              }
              var t = 0 !== (b & 4), J = !t && "scroll" === a, x = t ? null !== h2 ? h2 + "Capture" : null : h2;
              t = [];
              for (var w = d2, u; null !== w; ) {
                u = w;
                var F = u.stateNode;
                5 === u.tag && null !== F && (u = F, null !== x && (F = Kb(w, x), null != F && t.push(tf(w, F, u))));
                if (J) break;
                w = w.return;
              }
              0 < t.length && (h2 = new k2(h2, n, null, c, e2), g2.push({ event: h2, listeners: t }));
            }
          }
          if (0 === (b & 7)) {
            a: {
              h2 = "mouseover" === a || "pointerover" === a;
              k2 = "mouseout" === a || "pointerout" === a;
              if (h2 && c !== wb && (n = c.relatedTarget || c.fromElement) && (Wc(n) || n[uf])) break a;
              if (k2 || h2) {
                h2 = e2.window === e2 ? e2 : (h2 = e2.ownerDocument) ? h2.defaultView || h2.parentWindow : window;
                if (k2) {
                  if (n = c.relatedTarget || c.toElement, k2 = d2, n = n ? Wc(n) : null, null !== n && (J = Vb(n), n !== J || 5 !== n.tag && 6 !== n.tag)) n = null;
                } else k2 = null, n = d2;
                if (k2 !== n) {
                  t = Bd;
                  F = "onMouseLeave";
                  x = "onMouseEnter";
                  w = "mouse";
                  if ("pointerout" === a || "pointerover" === a) t = Td, F = "onPointerLeave", x = "onPointerEnter", w = "pointer";
                  J = null == k2 ? h2 : ue(k2);
                  u = null == n ? h2 : ue(n);
                  h2 = new t(F, w + "leave", k2, c, e2);
                  h2.target = J;
                  h2.relatedTarget = u;
                  F = null;
                  Wc(e2) === d2 && (t = new t(x, w + "enter", n, c, e2), t.target = u, t.relatedTarget = J, F = t);
                  J = F;
                  if (k2 && n) b: {
                    t = k2;
                    x = n;
                    w = 0;
                    for (u = t; u; u = vf(u)) w++;
                    u = 0;
                    for (F = x; F; F = vf(F)) u++;
                    for (; 0 < w - u; ) t = vf(t), w--;
                    for (; 0 < u - w; ) x = vf(x), u--;
                    for (; w--; ) {
                      if (t === x || null !== x && t === x.alternate) break b;
                      t = vf(t);
                      x = vf(x);
                    }
                    t = null;
                  }
                  else t = null;
                  null !== k2 && wf(g2, h2, k2, t, false);
                  null !== n && null !== J && wf(g2, J, n, t, true);
                }
              }
            }
            a: {
              h2 = d2 ? ue(d2) : window;
              k2 = h2.nodeName && h2.nodeName.toLowerCase();
              if ("select" === k2 || "input" === k2 && "file" === h2.type) var na = ve;
              else if (me(h2)) if (we) na = Fe;
              else {
                na = De;
                var xa = Ce;
              }
              else (k2 = h2.nodeName) && "input" === k2.toLowerCase() && ("checkbox" === h2.type || "radio" === h2.type) && (na = Ee);
              if (na && (na = na(a, d2))) {
                ne(g2, na, c, e2);
                break a;
              }
              xa && xa(a, h2, d2);
              "focusout" === a && (xa = h2._wrapperState) && xa.controlled && "number" === h2.type && cb(h2, "number", h2.value);
            }
            xa = d2 ? ue(d2) : window;
            switch (a) {
              case "focusin":
                if (me(xa) || "true" === xa.contentEditable) Qe = xa, Re = d2, Se = null;
                break;
              case "focusout":
                Se = Re = Qe = null;
                break;
              case "mousedown":
                Te = true;
                break;
              case "contextmenu":
              case "mouseup":
              case "dragend":
                Te = false;
                Ue(g2, c, e2);
                break;
              case "selectionchange":
                if (Pe) break;
              case "keydown":
              case "keyup":
                Ue(g2, c, e2);
            }
            var $a;
            if (ae) b: {
              switch (a) {
                case "compositionstart":
                  var ba = "onCompositionStart";
                  break b;
                case "compositionend":
                  ba = "onCompositionEnd";
                  break b;
                case "compositionupdate":
                  ba = "onCompositionUpdate";
                  break b;
              }
              ba = void 0;
            }
            else ie ? ge(a, c) && (ba = "onCompositionEnd") : "keydown" === a && 229 === c.keyCode && (ba = "onCompositionStart");
            ba && (de && "ko" !== c.locale && (ie || "onCompositionStart" !== ba ? "onCompositionEnd" === ba && ie && ($a = nd()) : (kd = e2, ld = "value" in kd ? kd.value : kd.textContent, ie = true)), xa = oe(d2, ba), 0 < xa.length && (ba = new Ld(ba, a, null, c, e2), g2.push({ event: ba, listeners: xa }), $a ? ba.data = $a : ($a = he(c), null !== $a && (ba.data = $a))));
            if ($a = ce ? je(a, c) : ke(a, c)) d2 = oe(d2, "onBeforeInput"), 0 < d2.length && (e2 = new Ld("onBeforeInput", "beforeinput", null, c, e2), g2.push({ event: e2, listeners: d2 }), e2.data = $a);
          }
          se(g2, b);
        });
      }
      function tf(a, b, c) {
        return { instance: a, listener: b, currentTarget: c };
      }
      function oe(a, b) {
        for (var c = b + "Capture", d = []; null !== a; ) {
          var e = a, f = e.stateNode;
          5 === e.tag && null !== f && (e = f, f = Kb(a, c), null != f && d.unshift(tf(a, f, e)), f = Kb(a, b), null != f && d.push(tf(a, f, e)));
          a = a.return;
        }
        return d;
      }
      function vf(a) {
        if (null === a) return null;
        do
          a = a.return;
        while (a && 5 !== a.tag);
        return a ? a : null;
      }
      function wf(a, b, c, d, e) {
        for (var f = b._reactName, g = []; null !== c && c !== d; ) {
          var h = c, k = h.alternate, l = h.stateNode;
          if (null !== k && k === d) break;
          5 === h.tag && null !== l && (h = l, e ? (k = Kb(c, f), null != k && g.unshift(tf(c, k, h))) : e || (k = Kb(c, f), null != k && g.push(tf(c, k, h))));
          c = c.return;
        }
        0 !== g.length && a.push({ event: b, listeners: g });
      }
      var xf = /\r\n?/g;
      var yf = /\u0000|\uFFFD/g;
      function zf(a) {
        return ("string" === typeof a ? a : "" + a).replace(xf, "\n").replace(yf, "");
      }
      function Af(a, b, c) {
        b = zf(b);
        if (zf(a) !== b && c) throw Error(p(425));
      }
      function Bf() {
      }
      var Cf = null;
      var Df = null;
      function Ef(a, b) {
        return "textarea" === a || "noscript" === a || "string" === typeof b.children || "number" === typeof b.children || "object" === typeof b.dangerouslySetInnerHTML && null !== b.dangerouslySetInnerHTML && null != b.dangerouslySetInnerHTML.__html;
      }
      var Ff = "function" === typeof setTimeout ? setTimeout : void 0;
      var Gf = "function" === typeof clearTimeout ? clearTimeout : void 0;
      var Hf = "function" === typeof Promise ? Promise : void 0;
      var Jf = "function" === typeof queueMicrotask ? queueMicrotask : "undefined" !== typeof Hf ? function(a) {
        return Hf.resolve(null).then(a).catch(If);
      } : Ff;
      function If(a) {
        setTimeout(function() {
          throw a;
        });
      }
      function Kf(a, b) {
        var c = b, d = 0;
        do {
          var e = c.nextSibling;
          a.removeChild(c);
          if (e && 8 === e.nodeType) if (c = e.data, "/$" === c) {
            if (0 === d) {
              a.removeChild(e);
              bd(b);
              return;
            }
            d--;
          } else "$" !== c && "$?" !== c && "$!" !== c || d++;
          c = e;
        } while (c);
        bd(b);
      }
      function Lf(a) {
        for (; null != a; a = a.nextSibling) {
          var b = a.nodeType;
          if (1 === b || 3 === b) break;
          if (8 === b) {
            b = a.data;
            if ("$" === b || "$!" === b || "$?" === b) break;
            if ("/$" === b) return null;
          }
        }
        return a;
      }
      function Mf(a) {
        a = a.previousSibling;
        for (var b = 0; a; ) {
          if (8 === a.nodeType) {
            var c = a.data;
            if ("$" === c || "$!" === c || "$?" === c) {
              if (0 === b) return a;
              b--;
            } else "/$" === c && b++;
          }
          a = a.previousSibling;
        }
        return null;
      }
      var Nf = Math.random().toString(36).slice(2);
      var Of = "__reactFiber$" + Nf;
      var Pf = "__reactProps$" + Nf;
      var uf = "__reactContainer$" + Nf;
      var of = "__reactEvents$" + Nf;
      var Qf = "__reactListeners$" + Nf;
      var Rf = "__reactHandles$" + Nf;
      function Wc(a) {
        var b = a[Of];
        if (b) return b;
        for (var c = a.parentNode; c; ) {
          if (b = c[uf] || c[Of]) {
            c = b.alternate;
            if (null !== b.child || null !== c && null !== c.child) for (a = Mf(a); null !== a; ) {
              if (c = a[Of]) return c;
              a = Mf(a);
            }
            return b;
          }
          a = c;
          c = a.parentNode;
        }
        return null;
      }
      function Cb(a) {
        a = a[Of] || a[uf];
        return !a || 5 !== a.tag && 6 !== a.tag && 13 !== a.tag && 3 !== a.tag ? null : a;
      }
      function ue(a) {
        if (5 === a.tag || 6 === a.tag) return a.stateNode;
        throw Error(p(33));
      }
      function Db(a) {
        return a[Pf] || null;
      }
      var Sf = [];
      var Tf = -1;
      function Uf(a) {
        return { current: a };
      }
      function E(a) {
        0 > Tf || (a.current = Sf[Tf], Sf[Tf] = null, Tf--);
      }
      function G(a, b) {
        Tf++;
        Sf[Tf] = a.current;
        a.current = b;
      }
      var Vf = {};
      var H = Uf(Vf);
      var Wf = Uf(false);
      var Xf = Vf;
      function Yf(a, b) {
        var c = a.type.contextTypes;
        if (!c) return Vf;
        var d = a.stateNode;
        if (d && d.__reactInternalMemoizedUnmaskedChildContext === b) return d.__reactInternalMemoizedMaskedChildContext;
        var e = {}, f;
        for (f in c) e[f] = b[f];
        d && (a = a.stateNode, a.__reactInternalMemoizedUnmaskedChildContext = b, a.__reactInternalMemoizedMaskedChildContext = e);
        return e;
      }
      function Zf(a) {
        a = a.childContextTypes;
        return null !== a && void 0 !== a;
      }
      function $f() {
        E(Wf);
        E(H);
      }
      function ag(a, b, c) {
        if (H.current !== Vf) throw Error(p(168));
        G(H, b);
        G(Wf, c);
      }
      function bg(a, b, c) {
        var d = a.stateNode;
        b = b.childContextTypes;
        if ("function" !== typeof d.getChildContext) return c;
        d = d.getChildContext();
        for (var e in d) if (!(e in b)) throw Error(p(108, Ra(a) || "Unknown", e));
        return A({}, c, d);
      }
      function cg(a) {
        a = (a = a.stateNode) && a.__reactInternalMemoizedMergedChildContext || Vf;
        Xf = H.current;
        G(H, a);
        G(Wf, Wf.current);
        return true;
      }
      function dg(a, b, c) {
        var d = a.stateNode;
        if (!d) throw Error(p(169));
        c ? (a = bg(a, b, Xf), d.__reactInternalMemoizedMergedChildContext = a, E(Wf), E(H), G(H, a)) : E(Wf);
        G(Wf, c);
      }
      var eg = null;
      var fg = false;
      var gg = false;
      function hg(a) {
        null === eg ? eg = [a] : eg.push(a);
      }
      function ig(a) {
        fg = true;
        hg(a);
      }
      function jg() {
        if (!gg && null !== eg) {
          gg = true;
          var a = 0, b = C;
          try {
            var c = eg;
            for (C = 1; a < c.length; a++) {
              var d = c[a];
              do
                d = d(true);
              while (null !== d);
            }
            eg = null;
            fg = false;
          } catch (e) {
            throw null !== eg && (eg = eg.slice(a + 1)), ac(fc, jg), e;
          } finally {
            C = b, gg = false;
          }
        }
        return null;
      }
      var kg = [];
      var lg = 0;
      var mg = null;
      var ng = 0;
      var og = [];
      var pg = 0;
      var qg = null;
      var rg = 1;
      var sg = "";
      function tg(a, b) {
        kg[lg++] = ng;
        kg[lg++] = mg;
        mg = a;
        ng = b;
      }
      function ug(a, b, c) {
        og[pg++] = rg;
        og[pg++] = sg;
        og[pg++] = qg;
        qg = a;
        var d = rg;
        a = sg;
        var e = 32 - oc(d) - 1;
        d &= ~(1 << e);
        c += 1;
        var f = 32 - oc(b) + e;
        if (30 < f) {
          var g = e - e % 5;
          f = (d & (1 << g) - 1).toString(32);
          d >>= g;
          e -= g;
          rg = 1 << 32 - oc(b) + e | c << e | d;
          sg = f + a;
        } else rg = 1 << f | c << e | d, sg = a;
      }
      function vg(a) {
        null !== a.return && (tg(a, 1), ug(a, 1, 0));
      }
      function wg(a) {
        for (; a === mg; ) mg = kg[--lg], kg[lg] = null, ng = kg[--lg], kg[lg] = null;
        for (; a === qg; ) qg = og[--pg], og[pg] = null, sg = og[--pg], og[pg] = null, rg = og[--pg], og[pg] = null;
      }
      var xg = null;
      var yg = null;
      var I = false;
      var zg = null;
      function Ag(a, b) {
        var c = Bg(5, null, null, 0);
        c.elementType = "DELETED";
        c.stateNode = b;
        c.return = a;
        b = a.deletions;
        null === b ? (a.deletions = [c], a.flags |= 16) : b.push(c);
      }
      function Cg(a, b) {
        switch (a.tag) {
          case 5:
            var c = a.type;
            b = 1 !== b.nodeType || c.toLowerCase() !== b.nodeName.toLowerCase() ? null : b;
            return null !== b ? (a.stateNode = b, xg = a, yg = Lf(b.firstChild), true) : false;
          case 6:
            return b = "" === a.pendingProps || 3 !== b.nodeType ? null : b, null !== b ? (a.stateNode = b, xg = a, yg = null, true) : false;
          case 13:
            return b = 8 !== b.nodeType ? null : b, null !== b ? (c = null !== qg ? { id: rg, overflow: sg } : null, a.memoizedState = { dehydrated: b, treeContext: c, retryLane: 1073741824 }, c = Bg(18, null, null, 0), c.stateNode = b, c.return = a, a.child = c, xg = a, yg = null, true) : false;
          default:
            return false;
        }
      }
      function Dg(a) {
        return 0 !== (a.mode & 1) && 0 === (a.flags & 128);
      }
      function Eg(a) {
        if (I) {
          var b = yg;
          if (b) {
            var c = b;
            if (!Cg(a, b)) {
              if (Dg(a)) throw Error(p(418));
              b = Lf(c.nextSibling);
              var d = xg;
              b && Cg(a, b) ? Ag(d, c) : (a.flags = a.flags & -4097 | 2, I = false, xg = a);
            }
          } else {
            if (Dg(a)) throw Error(p(418));
            a.flags = a.flags & -4097 | 2;
            I = false;
            xg = a;
          }
        }
      }
      function Fg(a) {
        for (a = a.return; null !== a && 5 !== a.tag && 3 !== a.tag && 13 !== a.tag; ) a = a.return;
        xg = a;
      }
      function Gg(a) {
        if (a !== xg) return false;
        if (!I) return Fg(a), I = true, false;
        var b;
        (b = 3 !== a.tag) && !(b = 5 !== a.tag) && (b = a.type, b = "head" !== b && "body" !== b && !Ef(a.type, a.memoizedProps));
        if (b && (b = yg)) {
          if (Dg(a)) throw Hg(), Error(p(418));
          for (; b; ) Ag(a, b), b = Lf(b.nextSibling);
        }
        Fg(a);
        if (13 === a.tag) {
          a = a.memoizedState;
          a = null !== a ? a.dehydrated : null;
          if (!a) throw Error(p(317));
          a: {
            a = a.nextSibling;
            for (b = 0; a; ) {
              if (8 === a.nodeType) {
                var c = a.data;
                if ("/$" === c) {
                  if (0 === b) {
                    yg = Lf(a.nextSibling);
                    break a;
                  }
                  b--;
                } else "$" !== c && "$!" !== c && "$?" !== c || b++;
              }
              a = a.nextSibling;
            }
            yg = null;
          }
        } else yg = xg ? Lf(a.stateNode.nextSibling) : null;
        return true;
      }
      function Hg() {
        for (var a = yg; a; ) a = Lf(a.nextSibling);
      }
      function Ig() {
        yg = xg = null;
        I = false;
      }
      function Jg(a) {
        null === zg ? zg = [a] : zg.push(a);
      }
      var Kg = ua.ReactCurrentBatchConfig;
      function Lg(a, b, c) {
        a = c.ref;
        if (null !== a && "function" !== typeof a && "object" !== typeof a) {
          if (c._owner) {
            c = c._owner;
            if (c) {
              if (1 !== c.tag) throw Error(p(309));
              var d = c.stateNode;
            }
            if (!d) throw Error(p(147, a));
            var e = d, f = "" + a;
            if (null !== b && null !== b.ref && "function" === typeof b.ref && b.ref._stringRef === f) return b.ref;
            b = function(a2) {
              var b2 = e.refs;
              null === a2 ? delete b2[f] : b2[f] = a2;
            };
            b._stringRef = f;
            return b;
          }
          if ("string" !== typeof a) throw Error(p(284));
          if (!c._owner) throw Error(p(290, a));
        }
        return a;
      }
      function Mg(a, b) {
        a = Object.prototype.toString.call(b);
        throw Error(p(31, "[object Object]" === a ? "object with keys {" + Object.keys(b).join(", ") + "}" : a));
      }
      function Ng(a) {
        var b = a._init;
        return b(a._payload);
      }
      function Og(a) {
        function b(b2, c2) {
          if (a) {
            var d2 = b2.deletions;
            null === d2 ? (b2.deletions = [c2], b2.flags |= 16) : d2.push(c2);
          }
        }
        function c(c2, d2) {
          if (!a) return null;
          for (; null !== d2; ) b(c2, d2), d2 = d2.sibling;
          return null;
        }
        function d(a2, b2) {
          for (a2 = /* @__PURE__ */ new Map(); null !== b2; ) null !== b2.key ? a2.set(b2.key, b2) : a2.set(b2.index, b2), b2 = b2.sibling;
          return a2;
        }
        function e(a2, b2) {
          a2 = Pg(a2, b2);
          a2.index = 0;
          a2.sibling = null;
          return a2;
        }
        function f(b2, c2, d2) {
          b2.index = d2;
          if (!a) return b2.flags |= 1048576, c2;
          d2 = b2.alternate;
          if (null !== d2) return d2 = d2.index, d2 < c2 ? (b2.flags |= 2, c2) : d2;
          b2.flags |= 2;
          return c2;
        }
        function g(b2) {
          a && null === b2.alternate && (b2.flags |= 2);
          return b2;
        }
        function h(a2, b2, c2, d2) {
          if (null === b2 || 6 !== b2.tag) return b2 = Qg(c2, a2.mode, d2), b2.return = a2, b2;
          b2 = e(b2, c2);
          b2.return = a2;
          return b2;
        }
        function k(a2, b2, c2, d2) {
          var f2 = c2.type;
          if (f2 === ya) return m(a2, b2, c2.props.children, d2, c2.key);
          if (null !== b2 && (b2.elementType === f2 || "object" === typeof f2 && null !== f2 && f2.$$typeof === Ha && Ng(f2) === b2.type)) return d2 = e(b2, c2.props), d2.ref = Lg(a2, b2, c2), d2.return = a2, d2;
          d2 = Rg(c2.type, c2.key, c2.props, null, a2.mode, d2);
          d2.ref = Lg(a2, b2, c2);
          d2.return = a2;
          return d2;
        }
        function l(a2, b2, c2, d2) {
          if (null === b2 || 4 !== b2.tag || b2.stateNode.containerInfo !== c2.containerInfo || b2.stateNode.implementation !== c2.implementation) return b2 = Sg(c2, a2.mode, d2), b2.return = a2, b2;
          b2 = e(b2, c2.children || []);
          b2.return = a2;
          return b2;
        }
        function m(a2, b2, c2, d2, f2) {
          if (null === b2 || 7 !== b2.tag) return b2 = Tg(c2, a2.mode, d2, f2), b2.return = a2, b2;
          b2 = e(b2, c2);
          b2.return = a2;
          return b2;
        }
        function q(a2, b2, c2) {
          if ("string" === typeof b2 && "" !== b2 || "number" === typeof b2) return b2 = Qg("" + b2, a2.mode, c2), b2.return = a2, b2;
          if ("object" === typeof b2 && null !== b2) {
            switch (b2.$$typeof) {
              case va:
                return c2 = Rg(b2.type, b2.key, b2.props, null, a2.mode, c2), c2.ref = Lg(a2, null, b2), c2.return = a2, c2;
              case wa:
                return b2 = Sg(b2, a2.mode, c2), b2.return = a2, b2;
              case Ha:
                var d2 = b2._init;
                return q(a2, d2(b2._payload), c2);
            }
            if (eb(b2) || Ka(b2)) return b2 = Tg(b2, a2.mode, c2, null), b2.return = a2, b2;
            Mg(a2, b2);
          }
          return null;
        }
        function r(a2, b2, c2, d2) {
          var e2 = null !== b2 ? b2.key : null;
          if ("string" === typeof c2 && "" !== c2 || "number" === typeof c2) return null !== e2 ? null : h(a2, b2, "" + c2, d2);
          if ("object" === typeof c2 && null !== c2) {
            switch (c2.$$typeof) {
              case va:
                return c2.key === e2 ? k(a2, b2, c2, d2) : null;
              case wa:
                return c2.key === e2 ? l(a2, b2, c2, d2) : null;
              case Ha:
                return e2 = c2._init, r(
                  a2,
                  b2,
                  e2(c2._payload),
                  d2
                );
            }
            if (eb(c2) || Ka(c2)) return null !== e2 ? null : m(a2, b2, c2, d2, null);
            Mg(a2, c2);
          }
          return null;
        }
        function y(a2, b2, c2, d2, e2) {
          if ("string" === typeof d2 && "" !== d2 || "number" === typeof d2) return a2 = a2.get(c2) || null, h(b2, a2, "" + d2, e2);
          if ("object" === typeof d2 && null !== d2) {
            switch (d2.$$typeof) {
              case va:
                return a2 = a2.get(null === d2.key ? c2 : d2.key) || null, k(b2, a2, d2, e2);
              case wa:
                return a2 = a2.get(null === d2.key ? c2 : d2.key) || null, l(b2, a2, d2, e2);
              case Ha:
                var f2 = d2._init;
                return y(a2, b2, c2, f2(d2._payload), e2);
            }
            if (eb(d2) || Ka(d2)) return a2 = a2.get(c2) || null, m(b2, a2, d2, e2, null);
            Mg(b2, d2);
          }
          return null;
        }
        function n(e2, g2, h2, k2) {
          for (var l2 = null, m2 = null, u = g2, w = g2 = 0, x = null; null !== u && w < h2.length; w++) {
            u.index > w ? (x = u, u = null) : x = u.sibling;
            var n2 = r(e2, u, h2[w], k2);
            if (null === n2) {
              null === u && (u = x);
              break;
            }
            a && u && null === n2.alternate && b(e2, u);
            g2 = f(n2, g2, w);
            null === m2 ? l2 = n2 : m2.sibling = n2;
            m2 = n2;
            u = x;
          }
          if (w === h2.length) return c(e2, u), I && tg(e2, w), l2;
          if (null === u) {
            for (; w < h2.length; w++) u = q(e2, h2[w], k2), null !== u && (g2 = f(u, g2, w), null === m2 ? l2 = u : m2.sibling = u, m2 = u);
            I && tg(e2, w);
            return l2;
          }
          for (u = d(e2, u); w < h2.length; w++) x = y(u, e2, w, h2[w], k2), null !== x && (a && null !== x.alternate && u.delete(null === x.key ? w : x.key), g2 = f(x, g2, w), null === m2 ? l2 = x : m2.sibling = x, m2 = x);
          a && u.forEach(function(a2) {
            return b(e2, a2);
          });
          I && tg(e2, w);
          return l2;
        }
        function t(e2, g2, h2, k2) {
          var l2 = Ka(h2);
          if ("function" !== typeof l2) throw Error(p(150));
          h2 = l2.call(h2);
          if (null == h2) throw Error(p(151));
          for (var u = l2 = null, m2 = g2, w = g2 = 0, x = null, n2 = h2.next(); null !== m2 && !n2.done; w++, n2 = h2.next()) {
            m2.index > w ? (x = m2, m2 = null) : x = m2.sibling;
            var t2 = r(e2, m2, n2.value, k2);
            if (null === t2) {
              null === m2 && (m2 = x);
              break;
            }
            a && m2 && null === t2.alternate && b(e2, m2);
            g2 = f(t2, g2, w);
            null === u ? l2 = t2 : u.sibling = t2;
            u = t2;
            m2 = x;
          }
          if (n2.done) return c(
            e2,
            m2
          ), I && tg(e2, w), l2;
          if (null === m2) {
            for (; !n2.done; w++, n2 = h2.next()) n2 = q(e2, n2.value, k2), null !== n2 && (g2 = f(n2, g2, w), null === u ? l2 = n2 : u.sibling = n2, u = n2);
            I && tg(e2, w);
            return l2;
          }
          for (m2 = d(e2, m2); !n2.done; w++, n2 = h2.next()) n2 = y(m2, e2, w, n2.value, k2), null !== n2 && (a && null !== n2.alternate && m2.delete(null === n2.key ? w : n2.key), g2 = f(n2, g2, w), null === u ? l2 = n2 : u.sibling = n2, u = n2);
          a && m2.forEach(function(a2) {
            return b(e2, a2);
          });
          I && tg(e2, w);
          return l2;
        }
        function J(a2, d2, f2, h2) {
          "object" === typeof f2 && null !== f2 && f2.type === ya && null === f2.key && (f2 = f2.props.children);
          if ("object" === typeof f2 && null !== f2) {
            switch (f2.$$typeof) {
              case va:
                a: {
                  for (var k2 = f2.key, l2 = d2; null !== l2; ) {
                    if (l2.key === k2) {
                      k2 = f2.type;
                      if (k2 === ya) {
                        if (7 === l2.tag) {
                          c(a2, l2.sibling);
                          d2 = e(l2, f2.props.children);
                          d2.return = a2;
                          a2 = d2;
                          break a;
                        }
                      } else if (l2.elementType === k2 || "object" === typeof k2 && null !== k2 && k2.$$typeof === Ha && Ng(k2) === l2.type) {
                        c(a2, l2.sibling);
                        d2 = e(l2, f2.props);
                        d2.ref = Lg(a2, l2, f2);
                        d2.return = a2;
                        a2 = d2;
                        break a;
                      }
                      c(a2, l2);
                      break;
                    } else b(a2, l2);
                    l2 = l2.sibling;
                  }
                  f2.type === ya ? (d2 = Tg(f2.props.children, a2.mode, h2, f2.key), d2.return = a2, a2 = d2) : (h2 = Rg(f2.type, f2.key, f2.props, null, a2.mode, h2), h2.ref = Lg(a2, d2, f2), h2.return = a2, a2 = h2);
                }
                return g(a2);
              case wa:
                a: {
                  for (l2 = f2.key; null !== d2; ) {
                    if (d2.key === l2) if (4 === d2.tag && d2.stateNode.containerInfo === f2.containerInfo && d2.stateNode.implementation === f2.implementation) {
                      c(a2, d2.sibling);
                      d2 = e(d2, f2.children || []);
                      d2.return = a2;
                      a2 = d2;
                      break a;
                    } else {
                      c(a2, d2);
                      break;
                    }
                    else b(a2, d2);
                    d2 = d2.sibling;
                  }
                  d2 = Sg(f2, a2.mode, h2);
                  d2.return = a2;
                  a2 = d2;
                }
                return g(a2);
              case Ha:
                return l2 = f2._init, J(a2, d2, l2(f2._payload), h2);
            }
            if (eb(f2)) return n(a2, d2, f2, h2);
            if (Ka(f2)) return t(a2, d2, f2, h2);
            Mg(a2, f2);
          }
          return "string" === typeof f2 && "" !== f2 || "number" === typeof f2 ? (f2 = "" + f2, null !== d2 && 6 === d2.tag ? (c(a2, d2.sibling), d2 = e(d2, f2), d2.return = a2, a2 = d2) : (c(a2, d2), d2 = Qg(f2, a2.mode, h2), d2.return = a2, a2 = d2), g(a2)) : c(a2, d2);
        }
        return J;
      }
      var Ug = Og(true);
      var Vg = Og(false);
      var Wg = Uf(null);
      var Xg = null;
      var Yg = null;
      var Zg = null;
      function $g() {
        Zg = Yg = Xg = null;
      }
      function ah(a) {
        var b = Wg.current;
        E(Wg);
        a._currentValue = b;
      }
      function bh(a, b, c) {
        for (; null !== a; ) {
          var d = a.alternate;
          (a.childLanes & b) !== b ? (a.childLanes |= b, null !== d && (d.childLanes |= b)) : null !== d && (d.childLanes & b) !== b && (d.childLanes |= b);
          if (a === c) break;
          a = a.return;
        }
      }
      function ch(a, b) {
        Xg = a;
        Zg = Yg = null;
        a = a.dependencies;
        null !== a && null !== a.firstContext && (0 !== (a.lanes & b) && (dh = true), a.firstContext = null);
      }
      function eh(a) {
        var b = a._currentValue;
        if (Zg !== a) if (a = { context: a, memoizedValue: b, next: null }, null === Yg) {
          if (null === Xg) throw Error(p(308));
          Yg = a;
          Xg.dependencies = { lanes: 0, firstContext: a };
        } else Yg = Yg.next = a;
        return b;
      }
      var fh = null;
      function gh(a) {
        null === fh ? fh = [a] : fh.push(a);
      }
      function hh(a, b, c, d) {
        var e = b.interleaved;
        null === e ? (c.next = c, gh(b)) : (c.next = e.next, e.next = c);
        b.interleaved = c;
        return ih(a, d);
      }
      function ih(a, b) {
        a.lanes |= b;
        var c = a.alternate;
        null !== c && (c.lanes |= b);
        c = a;
        for (a = a.return; null !== a; ) a.childLanes |= b, c = a.alternate, null !== c && (c.childLanes |= b), c = a, a = a.return;
        return 3 === c.tag ? c.stateNode : null;
      }
      var jh = false;
      function kh(a) {
        a.updateQueue = { baseState: a.memoizedState, firstBaseUpdate: null, lastBaseUpdate: null, shared: { pending: null, interleaved: null, lanes: 0 }, effects: null };
      }
      function lh(a, b) {
        a = a.updateQueue;
        b.updateQueue === a && (b.updateQueue = { baseState: a.baseState, firstBaseUpdate: a.firstBaseUpdate, lastBaseUpdate: a.lastBaseUpdate, shared: a.shared, effects: a.effects });
      }
      function mh(a, b) {
        return { eventTime: a, lane: b, tag: 0, payload: null, callback: null, next: null };
      }
      function nh(a, b, c) {
        var d = a.updateQueue;
        if (null === d) return null;
        d = d.shared;
        if (0 !== (K & 2)) {
          var e = d.pending;
          null === e ? b.next = b : (b.next = e.next, e.next = b);
          d.pending = b;
          return ih(a, c);
        }
        e = d.interleaved;
        null === e ? (b.next = b, gh(d)) : (b.next = e.next, e.next = b);
        d.interleaved = b;
        return ih(a, c);
      }
      function oh(a, b, c) {
        b = b.updateQueue;
        if (null !== b && (b = b.shared, 0 !== (c & 4194240))) {
          var d = b.lanes;
          d &= a.pendingLanes;
          c |= d;
          b.lanes = c;
          Cc(a, c);
        }
      }
      function ph(a, b) {
        var c = a.updateQueue, d = a.alternate;
        if (null !== d && (d = d.updateQueue, c === d)) {
          var e = null, f = null;
          c = c.firstBaseUpdate;
          if (null !== c) {
            do {
              var g = { eventTime: c.eventTime, lane: c.lane, tag: c.tag, payload: c.payload, callback: c.callback, next: null };
              null === f ? e = f = g : f = f.next = g;
              c = c.next;
            } while (null !== c);
            null === f ? e = f = b : f = f.next = b;
          } else e = f = b;
          c = { baseState: d.baseState, firstBaseUpdate: e, lastBaseUpdate: f, shared: d.shared, effects: d.effects };
          a.updateQueue = c;
          return;
        }
        a = c.lastBaseUpdate;
        null === a ? c.firstBaseUpdate = b : a.next = b;
        c.lastBaseUpdate = b;
      }
      function qh(a, b, c, d) {
        var e = a.updateQueue;
        jh = false;
        var f = e.firstBaseUpdate, g = e.lastBaseUpdate, h = e.shared.pending;
        if (null !== h) {
          e.shared.pending = null;
          var k = h, l = k.next;
          k.next = null;
          null === g ? f = l : g.next = l;
          g = k;
          var m = a.alternate;
          null !== m && (m = m.updateQueue, h = m.lastBaseUpdate, h !== g && (null === h ? m.firstBaseUpdate = l : h.next = l, m.lastBaseUpdate = k));
        }
        if (null !== f) {
          var q = e.baseState;
          g = 0;
          m = l = k = null;
          h = f;
          do {
            var r = h.lane, y = h.eventTime;
            if ((d & r) === r) {
              null !== m && (m = m.next = {
                eventTime: y,
                lane: 0,
                tag: h.tag,
                payload: h.payload,
                callback: h.callback,
                next: null
              });
              a: {
                var n = a, t = h;
                r = b;
                y = c;
                switch (t.tag) {
                  case 1:
                    n = t.payload;
                    if ("function" === typeof n) {
                      q = n.call(y, q, r);
                      break a;
                    }
                    q = n;
                    break a;
                  case 3:
                    n.flags = n.flags & -65537 | 128;
                  case 0:
                    n = t.payload;
                    r = "function" === typeof n ? n.call(y, q, r) : n;
                    if (null === r || void 0 === r) break a;
                    q = A({}, q, r);
                    break a;
                  case 2:
                    jh = true;
                }
              }
              null !== h.callback && 0 !== h.lane && (a.flags |= 64, r = e.effects, null === r ? e.effects = [h] : r.push(h));
            } else y = { eventTime: y, lane: r, tag: h.tag, payload: h.payload, callback: h.callback, next: null }, null === m ? (l = m = y, k = q) : m = m.next = y, g |= r;
            h = h.next;
            if (null === h) if (h = e.shared.pending, null === h) break;
            else r = h, h = r.next, r.next = null, e.lastBaseUpdate = r, e.shared.pending = null;
          } while (1);
          null === m && (k = q);
          e.baseState = k;
          e.firstBaseUpdate = l;
          e.lastBaseUpdate = m;
          b = e.shared.interleaved;
          if (null !== b) {
            e = b;
            do
              g |= e.lane, e = e.next;
            while (e !== b);
          } else null === f && (e.shared.lanes = 0);
          rh |= g;
          a.lanes = g;
          a.memoizedState = q;
        }
      }
      function sh(a, b, c) {
        a = b.effects;
        b.effects = null;
        if (null !== a) for (b = 0; b < a.length; b++) {
          var d = a[b], e = d.callback;
          if (null !== e) {
            d.callback = null;
            d = c;
            if ("function" !== typeof e) throw Error(p(191, e));
            e.call(d);
          }
        }
      }
      var th = {};
      var uh = Uf(th);
      var vh = Uf(th);
      var wh = Uf(th);
      function xh(a) {
        if (a === th) throw Error(p(174));
        return a;
      }
      function yh(a, b) {
        G(wh, b);
        G(vh, a);
        G(uh, th);
        a = b.nodeType;
        switch (a) {
          case 9:
          case 11:
            b = (b = b.documentElement) ? b.namespaceURI : lb(null, "");
            break;
          default:
            a = 8 === a ? b.parentNode : b, b = a.namespaceURI || null, a = a.tagName, b = lb(b, a);
        }
        E(uh);
        G(uh, b);
      }
      function zh() {
        E(uh);
        E(vh);
        E(wh);
      }
      function Ah(a) {
        xh(wh.current);
        var b = xh(uh.current);
        var c = lb(b, a.type);
        b !== c && (G(vh, a), G(uh, c));
      }
      function Bh(a) {
        vh.current === a && (E(uh), E(vh));
      }
      var L = Uf(0);
      function Ch(a) {
        for (var b = a; null !== b; ) {
          if (13 === b.tag) {
            var c = b.memoizedState;
            if (null !== c && (c = c.dehydrated, null === c || "$?" === c.data || "$!" === c.data)) return b;
          } else if (19 === b.tag && void 0 !== b.memoizedProps.revealOrder) {
            if (0 !== (b.flags & 128)) return b;
          } else if (null !== b.child) {
            b.child.return = b;
            b = b.child;
            continue;
          }
          if (b === a) break;
          for (; null === b.sibling; ) {
            if (null === b.return || b.return === a) return null;
            b = b.return;
          }
          b.sibling.return = b.return;
          b = b.sibling;
        }
        return null;
      }
      var Dh = [];
      function Eh() {
        for (var a = 0; a < Dh.length; a++) Dh[a]._workInProgressVersionPrimary = null;
        Dh.length = 0;
      }
      var Fh = ua.ReactCurrentDispatcher;
      var Gh = ua.ReactCurrentBatchConfig;
      var Hh = 0;
      var M = null;
      var N = null;
      var O = null;
      var Ih = false;
      var Jh = false;
      var Kh = 0;
      var Lh = 0;
      function P() {
        throw Error(p(321));
      }
      function Mh(a, b) {
        if (null === b) return false;
        for (var c = 0; c < b.length && c < a.length; c++) if (!He(a[c], b[c])) return false;
        return true;
      }
      function Nh(a, b, c, d, e, f) {
        Hh = f;
        M = b;
        b.memoizedState = null;
        b.updateQueue = null;
        b.lanes = 0;
        Fh.current = null === a || null === a.memoizedState ? Oh : Ph;
        a = c(d, e);
        if (Jh) {
          f = 0;
          do {
            Jh = false;
            Kh = 0;
            if (25 <= f) throw Error(p(301));
            f += 1;
            O = N = null;
            b.updateQueue = null;
            Fh.current = Qh;
            a = c(d, e);
          } while (Jh);
        }
        Fh.current = Rh;
        b = null !== N && null !== N.next;
        Hh = 0;
        O = N = M = null;
        Ih = false;
        if (b) throw Error(p(300));
        return a;
      }
      function Sh() {
        var a = 0 !== Kh;
        Kh = 0;
        return a;
      }
      function Th() {
        var a = { memoizedState: null, baseState: null, baseQueue: null, queue: null, next: null };
        null === O ? M.memoizedState = O = a : O = O.next = a;
        return O;
      }
      function Uh() {
        if (null === N) {
          var a = M.alternate;
          a = null !== a ? a.memoizedState : null;
        } else a = N.next;
        var b = null === O ? M.memoizedState : O.next;
        if (null !== b) O = b, N = a;
        else {
          if (null === a) throw Error(p(310));
          N = a;
          a = { memoizedState: N.memoizedState, baseState: N.baseState, baseQueue: N.baseQueue, queue: N.queue, next: null };
          null === O ? M.memoizedState = O = a : O = O.next = a;
        }
        return O;
      }
      function Vh(a, b) {
        return "function" === typeof b ? b(a) : b;
      }
      function Wh(a) {
        var b = Uh(), c = b.queue;
        if (null === c) throw Error(p(311));
        c.lastRenderedReducer = a;
        var d = N, e = d.baseQueue, f = c.pending;
        if (null !== f) {
          if (null !== e) {
            var g = e.next;
            e.next = f.next;
            f.next = g;
          }
          d.baseQueue = e = f;
          c.pending = null;
        }
        if (null !== e) {
          f = e.next;
          d = d.baseState;
          var h = g = null, k = null, l = f;
          do {
            var m = l.lane;
            if ((Hh & m) === m) null !== k && (k = k.next = { lane: 0, action: l.action, hasEagerState: l.hasEagerState, eagerState: l.eagerState, next: null }), d = l.hasEagerState ? l.eagerState : a(d, l.action);
            else {
              var q = {
                lane: m,
                action: l.action,
                hasEagerState: l.hasEagerState,
                eagerState: l.eagerState,
                next: null
              };
              null === k ? (h = k = q, g = d) : k = k.next = q;
              M.lanes |= m;
              rh |= m;
            }
            l = l.next;
          } while (null !== l && l !== f);
          null === k ? g = d : k.next = h;
          He(d, b.memoizedState) || (dh = true);
          b.memoizedState = d;
          b.baseState = g;
          b.baseQueue = k;
          c.lastRenderedState = d;
        }
        a = c.interleaved;
        if (null !== a) {
          e = a;
          do
            f = e.lane, M.lanes |= f, rh |= f, e = e.next;
          while (e !== a);
        } else null === e && (c.lanes = 0);
        return [b.memoizedState, c.dispatch];
      }
      function Xh(a) {
        var b = Uh(), c = b.queue;
        if (null === c) throw Error(p(311));
        c.lastRenderedReducer = a;
        var d = c.dispatch, e = c.pending, f = b.memoizedState;
        if (null !== e) {
          c.pending = null;
          var g = e = e.next;
          do
            f = a(f, g.action), g = g.next;
          while (g !== e);
          He(f, b.memoizedState) || (dh = true);
          b.memoizedState = f;
          null === b.baseQueue && (b.baseState = f);
          c.lastRenderedState = f;
        }
        return [f, d];
      }
      function Yh() {
      }
      function Zh(a, b) {
        var c = M, d = Uh(), e = b(), f = !He(d.memoizedState, e);
        f && (d.memoizedState = e, dh = true);
        d = d.queue;
        $h(ai.bind(null, c, d, a), [a]);
        if (d.getSnapshot !== b || f || null !== O && O.memoizedState.tag & 1) {
          c.flags |= 2048;
          bi(9, ci.bind(null, c, d, e, b), void 0, null);
          if (null === Q) throw Error(p(349));
          0 !== (Hh & 30) || di(c, b, e);
        }
        return e;
      }
      function di(a, b, c) {
        a.flags |= 16384;
        a = { getSnapshot: b, value: c };
        b = M.updateQueue;
        null === b ? (b = { lastEffect: null, stores: null }, M.updateQueue = b, b.stores = [a]) : (c = b.stores, null === c ? b.stores = [a] : c.push(a));
      }
      function ci(a, b, c, d) {
        b.value = c;
        b.getSnapshot = d;
        ei(b) && fi(a);
      }
      function ai(a, b, c) {
        return c(function() {
          ei(b) && fi(a);
        });
      }
      function ei(a) {
        var b = a.getSnapshot;
        a = a.value;
        try {
          var c = b();
          return !He(a, c);
        } catch (d) {
          return true;
        }
      }
      function fi(a) {
        var b = ih(a, 1);
        null !== b && gi(b, a, 1, -1);
      }
      function hi(a) {
        var b = Th();
        "function" === typeof a && (a = a());
        b.memoizedState = b.baseState = a;
        a = { pending: null, interleaved: null, lanes: 0, dispatch: null, lastRenderedReducer: Vh, lastRenderedState: a };
        b.queue = a;
        a = a.dispatch = ii.bind(null, M, a);
        return [b.memoizedState, a];
      }
      function bi(a, b, c, d) {
        a = { tag: a, create: b, destroy: c, deps: d, next: null };
        b = M.updateQueue;
        null === b ? (b = { lastEffect: null, stores: null }, M.updateQueue = b, b.lastEffect = a.next = a) : (c = b.lastEffect, null === c ? b.lastEffect = a.next = a : (d = c.next, c.next = a, a.next = d, b.lastEffect = a));
        return a;
      }
      function ji() {
        return Uh().memoizedState;
      }
      function ki(a, b, c, d) {
        var e = Th();
        M.flags |= a;
        e.memoizedState = bi(1 | b, c, void 0, void 0 === d ? null : d);
      }
      function li(a, b, c, d) {
        var e = Uh();
        d = void 0 === d ? null : d;
        var f = void 0;
        if (null !== N) {
          var g = N.memoizedState;
          f = g.destroy;
          if (null !== d && Mh(d, g.deps)) {
            e.memoizedState = bi(b, c, f, d);
            return;
          }
        }
        M.flags |= a;
        e.memoizedState = bi(1 | b, c, f, d);
      }
      function mi(a, b) {
        return ki(8390656, 8, a, b);
      }
      function $h(a, b) {
        return li(2048, 8, a, b);
      }
      function ni(a, b) {
        return li(4, 2, a, b);
      }
      function oi(a, b) {
        return li(4, 4, a, b);
      }
      function pi(a, b) {
        if ("function" === typeof b) return a = a(), b(a), function() {
          b(null);
        };
        if (null !== b && void 0 !== b) return a = a(), b.current = a, function() {
          b.current = null;
        };
      }
      function qi(a, b, c) {
        c = null !== c && void 0 !== c ? c.concat([a]) : null;
        return li(4, 4, pi.bind(null, b, a), c);
      }
      function ri() {
      }
      function si(a, b) {
        var c = Uh();
        b = void 0 === b ? null : b;
        var d = c.memoizedState;
        if (null !== d && null !== b && Mh(b, d[1])) return d[0];
        c.memoizedState = [a, b];
        return a;
      }
      function ti(a, b) {
        var c = Uh();
        b = void 0 === b ? null : b;
        var d = c.memoizedState;
        if (null !== d && null !== b && Mh(b, d[1])) return d[0];
        a = a();
        c.memoizedState = [a, b];
        return a;
      }
      function ui(a, b, c) {
        if (0 === (Hh & 21)) return a.baseState && (a.baseState = false, dh = true), a.memoizedState = c;
        He(c, b) || (c = yc(), M.lanes |= c, rh |= c, a.baseState = true);
        return b;
      }
      function vi(a, b) {
        var c = C;
        C = 0 !== c && 4 > c ? c : 4;
        a(true);
        var d = Gh.transition;
        Gh.transition = {};
        try {
          a(false), b();
        } finally {
          C = c, Gh.transition = d;
        }
      }
      function wi() {
        return Uh().memoizedState;
      }
      function xi(a, b, c) {
        var d = yi(a);
        c = { lane: d, action: c, hasEagerState: false, eagerState: null, next: null };
        if (zi(a)) Ai(b, c);
        else if (c = hh(a, b, c, d), null !== c) {
          var e = R();
          gi(c, a, d, e);
          Bi(c, b, d);
        }
      }
      function ii(a, b, c) {
        var d = yi(a), e = { lane: d, action: c, hasEagerState: false, eagerState: null, next: null };
        if (zi(a)) Ai(b, e);
        else {
          var f = a.alternate;
          if (0 === a.lanes && (null === f || 0 === f.lanes) && (f = b.lastRenderedReducer, null !== f)) try {
            var g = b.lastRenderedState, h = f(g, c);
            e.hasEagerState = true;
            e.eagerState = h;
            if (He(h, g)) {
              var k = b.interleaved;
              null === k ? (e.next = e, gh(b)) : (e.next = k.next, k.next = e);
              b.interleaved = e;
              return;
            }
          } catch (l) {
          } finally {
          }
          c = hh(a, b, e, d);
          null !== c && (e = R(), gi(c, a, d, e), Bi(c, b, d));
        }
      }
      function zi(a) {
        var b = a.alternate;
        return a === M || null !== b && b === M;
      }
      function Ai(a, b) {
        Jh = Ih = true;
        var c = a.pending;
        null === c ? b.next = b : (b.next = c.next, c.next = b);
        a.pending = b;
      }
      function Bi(a, b, c) {
        if (0 !== (c & 4194240)) {
          var d = b.lanes;
          d &= a.pendingLanes;
          c |= d;
          b.lanes = c;
          Cc(a, c);
        }
      }
      var Rh = { readContext: eh, useCallback: P, useContext: P, useEffect: P, useImperativeHandle: P, useInsertionEffect: P, useLayoutEffect: P, useMemo: P, useReducer: P, useRef: P, useState: P, useDebugValue: P, useDeferredValue: P, useTransition: P, useMutableSource: P, useSyncExternalStore: P, useId: P, unstable_isNewReconciler: false };
      var Oh = { readContext: eh, useCallback: function(a, b) {
        Th().memoizedState = [a, void 0 === b ? null : b];
        return a;
      }, useContext: eh, useEffect: mi, useImperativeHandle: function(a, b, c) {
        c = null !== c && void 0 !== c ? c.concat([a]) : null;
        return ki(
          4194308,
          4,
          pi.bind(null, b, a),
          c
        );
      }, useLayoutEffect: function(a, b) {
        return ki(4194308, 4, a, b);
      }, useInsertionEffect: function(a, b) {
        return ki(4, 2, a, b);
      }, useMemo: function(a, b) {
        var c = Th();
        b = void 0 === b ? null : b;
        a = a();
        c.memoizedState = [a, b];
        return a;
      }, useReducer: function(a, b, c) {
        var d = Th();
        b = void 0 !== c ? c(b) : b;
        d.memoizedState = d.baseState = b;
        a = { pending: null, interleaved: null, lanes: 0, dispatch: null, lastRenderedReducer: a, lastRenderedState: b };
        d.queue = a;
        a = a.dispatch = xi.bind(null, M, a);
        return [d.memoizedState, a];
      }, useRef: function(a) {
        var b = Th();
        a = { current: a };
        return b.memoizedState = a;
      }, useState: hi, useDebugValue: ri, useDeferredValue: function(a) {
        return Th().memoizedState = a;
      }, useTransition: function() {
        var a = hi(false), b = a[0];
        a = vi.bind(null, a[1]);
        Th().memoizedState = a;
        return [b, a];
      }, useMutableSource: function() {
      }, useSyncExternalStore: function(a, b, c) {
        var d = M, e = Th();
        if (I) {
          if (void 0 === c) throw Error(p(407));
          c = c();
        } else {
          c = b();
          if (null === Q) throw Error(p(349));
          0 !== (Hh & 30) || di(d, b, c);
        }
        e.memoizedState = c;
        var f = { value: c, getSnapshot: b };
        e.queue = f;
        mi(ai.bind(
          null,
          d,
          f,
          a
        ), [a]);
        d.flags |= 2048;
        bi(9, ci.bind(null, d, f, c, b), void 0, null);
        return c;
      }, useId: function() {
        var a = Th(), b = Q.identifierPrefix;
        if (I) {
          var c = sg;
          var d = rg;
          c = (d & ~(1 << 32 - oc(d) - 1)).toString(32) + c;
          b = ":" + b + "R" + c;
          c = Kh++;
          0 < c && (b += "H" + c.toString(32));
          b += ":";
        } else c = Lh++, b = ":" + b + "r" + c.toString(32) + ":";
        return a.memoizedState = b;
      }, unstable_isNewReconciler: false };
      var Ph = {
        readContext: eh,
        useCallback: si,
        useContext: eh,
        useEffect: $h,
        useImperativeHandle: qi,
        useInsertionEffect: ni,
        useLayoutEffect: oi,
        useMemo: ti,
        useReducer: Wh,
        useRef: ji,
        useState: function() {
          return Wh(Vh);
        },
        useDebugValue: ri,
        useDeferredValue: function(a) {
          var b = Uh();
          return ui(b, N.memoizedState, a);
        },
        useTransition: function() {
          var a = Wh(Vh)[0], b = Uh().memoizedState;
          return [a, b];
        },
        useMutableSource: Yh,
        useSyncExternalStore: Zh,
        useId: wi,
        unstable_isNewReconciler: false
      };
      var Qh = { readContext: eh, useCallback: si, useContext: eh, useEffect: $h, useImperativeHandle: qi, useInsertionEffect: ni, useLayoutEffect: oi, useMemo: ti, useReducer: Xh, useRef: ji, useState: function() {
        return Xh(Vh);
      }, useDebugValue: ri, useDeferredValue: function(a) {
        var b = Uh();
        return null === N ? b.memoizedState = a : ui(b, N.memoizedState, a);
      }, useTransition: function() {
        var a = Xh(Vh)[0], b = Uh().memoizedState;
        return [a, b];
      }, useMutableSource: Yh, useSyncExternalStore: Zh, useId: wi, unstable_isNewReconciler: false };
      function Ci(a, b) {
        if (a && a.defaultProps) {
          b = A({}, b);
          a = a.defaultProps;
          for (var c in a) void 0 === b[c] && (b[c] = a[c]);
          return b;
        }
        return b;
      }
      function Di(a, b, c, d) {
        b = a.memoizedState;
        c = c(d, b);
        c = null === c || void 0 === c ? b : A({}, b, c);
        a.memoizedState = c;
        0 === a.lanes && (a.updateQueue.baseState = c);
      }
      var Ei = { isMounted: function(a) {
        return (a = a._reactInternals) ? Vb(a) === a : false;
      }, enqueueSetState: function(a, b, c) {
        a = a._reactInternals;
        var d = R(), e = yi(a), f = mh(d, e);
        f.payload = b;
        void 0 !== c && null !== c && (f.callback = c);
        b = nh(a, f, e);
        null !== b && (gi(b, a, e, d), oh(b, a, e));
      }, enqueueReplaceState: function(a, b, c) {
        a = a._reactInternals;
        var d = R(), e = yi(a), f = mh(d, e);
        f.tag = 1;
        f.payload = b;
        void 0 !== c && null !== c && (f.callback = c);
        b = nh(a, f, e);
        null !== b && (gi(b, a, e, d), oh(b, a, e));
      }, enqueueForceUpdate: function(a, b) {
        a = a._reactInternals;
        var c = R(), d = yi(a), e = mh(c, d);
        e.tag = 2;
        void 0 !== b && null !== b && (e.callback = b);
        b = nh(a, e, d);
        null !== b && (gi(b, a, d, c), oh(b, a, d));
      } };
      function Fi(a, b, c, d, e, f, g) {
        a = a.stateNode;
        return "function" === typeof a.shouldComponentUpdate ? a.shouldComponentUpdate(d, f, g) : b.prototype && b.prototype.isPureReactComponent ? !Ie(c, d) || !Ie(e, f) : true;
      }
      function Gi(a, b, c) {
        var d = false, e = Vf;
        var f = b.contextType;
        "object" === typeof f && null !== f ? f = eh(f) : (e = Zf(b) ? Xf : H.current, d = b.contextTypes, f = (d = null !== d && void 0 !== d) ? Yf(a, e) : Vf);
        b = new b(c, f);
        a.memoizedState = null !== b.state && void 0 !== b.state ? b.state : null;
        b.updater = Ei;
        a.stateNode = b;
        b._reactInternals = a;
        d && (a = a.stateNode, a.__reactInternalMemoizedUnmaskedChildContext = e, a.__reactInternalMemoizedMaskedChildContext = f);
        return b;
      }
      function Hi(a, b, c, d) {
        a = b.state;
        "function" === typeof b.componentWillReceiveProps && b.componentWillReceiveProps(c, d);
        "function" === typeof b.UNSAFE_componentWillReceiveProps && b.UNSAFE_componentWillReceiveProps(c, d);
        b.state !== a && Ei.enqueueReplaceState(b, b.state, null);
      }
      function Ii(a, b, c, d) {
        var e = a.stateNode;
        e.props = c;
        e.state = a.memoizedState;
        e.refs = {};
        kh(a);
        var f = b.contextType;
        "object" === typeof f && null !== f ? e.context = eh(f) : (f = Zf(b) ? Xf : H.current, e.context = Yf(a, f));
        e.state = a.memoizedState;
        f = b.getDerivedStateFromProps;
        "function" === typeof f && (Di(a, b, f, c), e.state = a.memoizedState);
        "function" === typeof b.getDerivedStateFromProps || "function" === typeof e.getSnapshotBeforeUpdate || "function" !== typeof e.UNSAFE_componentWillMount && "function" !== typeof e.componentWillMount || (b = e.state, "function" === typeof e.componentWillMount && e.componentWillMount(), "function" === typeof e.UNSAFE_componentWillMount && e.UNSAFE_componentWillMount(), b !== e.state && Ei.enqueueReplaceState(e, e.state, null), qh(a, c, e, d), e.state = a.memoizedState);
        "function" === typeof e.componentDidMount && (a.flags |= 4194308);
      }
      function Ji(a, b) {
        try {
          var c = "", d = b;
          do
            c += Pa(d), d = d.return;
          while (d);
          var e = c;
        } catch (f) {
          e = "\nError generating stack: " + f.message + "\n" + f.stack;
        }
        return { value: a, source: b, stack: e, digest: null };
      }
      function Ki(a, b, c) {
        return { value: a, source: null, stack: null != c ? c : null, digest: null != b ? b : null };
      }
      function Li(a, b) {
        try {
          console.error(b.value);
        } catch (c) {
          setTimeout(function() {
            throw c;
          });
        }
      }
      var Mi = "function" === typeof WeakMap ? WeakMap : Map;
      function Ni(a, b, c) {
        c = mh(-1, c);
        c.tag = 3;
        c.payload = { element: null };
        var d = b.value;
        c.callback = function() {
          Oi || (Oi = true, Pi = d);
          Li(a, b);
        };
        return c;
      }
      function Qi(a, b, c) {
        c = mh(-1, c);
        c.tag = 3;
        var d = a.type.getDerivedStateFromError;
        if ("function" === typeof d) {
          var e = b.value;
          c.payload = function() {
            return d(e);
          };
          c.callback = function() {
            Li(a, b);
          };
        }
        var f = a.stateNode;
        null !== f && "function" === typeof f.componentDidCatch && (c.callback = function() {
          Li(a, b);
          "function" !== typeof d && (null === Ri ? Ri = /* @__PURE__ */ new Set([this]) : Ri.add(this));
          var c2 = b.stack;
          this.componentDidCatch(b.value, { componentStack: null !== c2 ? c2 : "" });
        });
        return c;
      }
      function Si(a, b, c) {
        var d = a.pingCache;
        if (null === d) {
          d = a.pingCache = new Mi();
          var e = /* @__PURE__ */ new Set();
          d.set(b, e);
        } else e = d.get(b), void 0 === e && (e = /* @__PURE__ */ new Set(), d.set(b, e));
        e.has(c) || (e.add(c), a = Ti.bind(null, a, b, c), b.then(a, a));
      }
      function Ui(a) {
        do {
          var b;
          if (b = 13 === a.tag) b = a.memoizedState, b = null !== b ? null !== b.dehydrated ? true : false : true;
          if (b) return a;
          a = a.return;
        } while (null !== a);
        return null;
      }
      function Vi(a, b, c, d, e) {
        if (0 === (a.mode & 1)) return a === b ? a.flags |= 65536 : (a.flags |= 128, c.flags |= 131072, c.flags &= -52805, 1 === c.tag && (null === c.alternate ? c.tag = 17 : (b = mh(-1, 1), b.tag = 2, nh(c, b, 1))), c.lanes |= 1), a;
        a.flags |= 65536;
        a.lanes = e;
        return a;
      }
      var Wi = ua.ReactCurrentOwner;
      var dh = false;
      function Xi(a, b, c, d) {
        b.child = null === a ? Vg(b, null, c, d) : Ug(b, a.child, c, d);
      }
      function Yi(a, b, c, d, e) {
        c = c.render;
        var f = b.ref;
        ch(b, e);
        d = Nh(a, b, c, d, f, e);
        c = Sh();
        if (null !== a && !dh) return b.updateQueue = a.updateQueue, b.flags &= -2053, a.lanes &= ~e, Zi(a, b, e);
        I && c && vg(b);
        b.flags |= 1;
        Xi(a, b, d, e);
        return b.child;
      }
      function $i(a, b, c, d, e) {
        if (null === a) {
          var f = c.type;
          if ("function" === typeof f && !aj(f) && void 0 === f.defaultProps && null === c.compare && void 0 === c.defaultProps) return b.tag = 15, b.type = f, bj(a, b, f, d, e);
          a = Rg(c.type, null, d, b, b.mode, e);
          a.ref = b.ref;
          a.return = b;
          return b.child = a;
        }
        f = a.child;
        if (0 === (a.lanes & e)) {
          var g = f.memoizedProps;
          c = c.compare;
          c = null !== c ? c : Ie;
          if (c(g, d) && a.ref === b.ref) return Zi(a, b, e);
        }
        b.flags |= 1;
        a = Pg(f, d);
        a.ref = b.ref;
        a.return = b;
        return b.child = a;
      }
      function bj(a, b, c, d, e) {
        if (null !== a) {
          var f = a.memoizedProps;
          if (Ie(f, d) && a.ref === b.ref) if (dh = false, b.pendingProps = d = f, 0 !== (a.lanes & e)) 0 !== (a.flags & 131072) && (dh = true);
          else return b.lanes = a.lanes, Zi(a, b, e);
        }
        return cj(a, b, c, d, e);
      }
      function dj(a, b, c) {
        var d = b.pendingProps, e = d.children, f = null !== a ? a.memoizedState : null;
        if ("hidden" === d.mode) if (0 === (b.mode & 1)) b.memoizedState = { baseLanes: 0, cachePool: null, transitions: null }, G(ej, fj), fj |= c;
        else {
          if (0 === (c & 1073741824)) return a = null !== f ? f.baseLanes | c : c, b.lanes = b.childLanes = 1073741824, b.memoizedState = { baseLanes: a, cachePool: null, transitions: null }, b.updateQueue = null, G(ej, fj), fj |= a, null;
          b.memoizedState = { baseLanes: 0, cachePool: null, transitions: null };
          d = null !== f ? f.baseLanes : c;
          G(ej, fj);
          fj |= d;
        }
        else null !== f ? (d = f.baseLanes | c, b.memoizedState = null) : d = c, G(ej, fj), fj |= d;
        Xi(a, b, e, c);
        return b.child;
      }
      function gj(a, b) {
        var c = b.ref;
        if (null === a && null !== c || null !== a && a.ref !== c) b.flags |= 512, b.flags |= 2097152;
      }
      function cj(a, b, c, d, e) {
        var f = Zf(c) ? Xf : H.current;
        f = Yf(b, f);
        ch(b, e);
        c = Nh(a, b, c, d, f, e);
        d = Sh();
        if (null !== a && !dh) return b.updateQueue = a.updateQueue, b.flags &= -2053, a.lanes &= ~e, Zi(a, b, e);
        I && d && vg(b);
        b.flags |= 1;
        Xi(a, b, c, e);
        return b.child;
      }
      function hj(a, b, c, d, e) {
        if (Zf(c)) {
          var f = true;
          cg(b);
        } else f = false;
        ch(b, e);
        if (null === b.stateNode) ij(a, b), Gi(b, c, d), Ii(b, c, d, e), d = true;
        else if (null === a) {
          var g = b.stateNode, h = b.memoizedProps;
          g.props = h;
          var k = g.context, l = c.contextType;
          "object" === typeof l && null !== l ? l = eh(l) : (l = Zf(c) ? Xf : H.current, l = Yf(b, l));
          var m = c.getDerivedStateFromProps, q = "function" === typeof m || "function" === typeof g.getSnapshotBeforeUpdate;
          q || "function" !== typeof g.UNSAFE_componentWillReceiveProps && "function" !== typeof g.componentWillReceiveProps || (h !== d || k !== l) && Hi(b, g, d, l);
          jh = false;
          var r = b.memoizedState;
          g.state = r;
          qh(b, d, g, e);
          k = b.memoizedState;
          h !== d || r !== k || Wf.current || jh ? ("function" === typeof m && (Di(b, c, m, d), k = b.memoizedState), (h = jh || Fi(b, c, h, d, r, k, l)) ? (q || "function" !== typeof g.UNSAFE_componentWillMount && "function" !== typeof g.componentWillMount || ("function" === typeof g.componentWillMount && g.componentWillMount(), "function" === typeof g.UNSAFE_componentWillMount && g.UNSAFE_componentWillMount()), "function" === typeof g.componentDidMount && (b.flags |= 4194308)) : ("function" === typeof g.componentDidMount && (b.flags |= 4194308), b.memoizedProps = d, b.memoizedState = k), g.props = d, g.state = k, g.context = l, d = h) : ("function" === typeof g.componentDidMount && (b.flags |= 4194308), d = false);
        } else {
          g = b.stateNode;
          lh(a, b);
          h = b.memoizedProps;
          l = b.type === b.elementType ? h : Ci(b.type, h);
          g.props = l;
          q = b.pendingProps;
          r = g.context;
          k = c.contextType;
          "object" === typeof k && null !== k ? k = eh(k) : (k = Zf(c) ? Xf : H.current, k = Yf(b, k));
          var y = c.getDerivedStateFromProps;
          (m = "function" === typeof y || "function" === typeof g.getSnapshotBeforeUpdate) || "function" !== typeof g.UNSAFE_componentWillReceiveProps && "function" !== typeof g.componentWillReceiveProps || (h !== q || r !== k) && Hi(b, g, d, k);
          jh = false;
          r = b.memoizedState;
          g.state = r;
          qh(b, d, g, e);
          var n = b.memoizedState;
          h !== q || r !== n || Wf.current || jh ? ("function" === typeof y && (Di(b, c, y, d), n = b.memoizedState), (l = jh || Fi(b, c, l, d, r, n, k) || false) ? (m || "function" !== typeof g.UNSAFE_componentWillUpdate && "function" !== typeof g.componentWillUpdate || ("function" === typeof g.componentWillUpdate && g.componentWillUpdate(d, n, k), "function" === typeof g.UNSAFE_componentWillUpdate && g.UNSAFE_componentWillUpdate(d, n, k)), "function" === typeof g.componentDidUpdate && (b.flags |= 4), "function" === typeof g.getSnapshotBeforeUpdate && (b.flags |= 1024)) : ("function" !== typeof g.componentDidUpdate || h === a.memoizedProps && r === a.memoizedState || (b.flags |= 4), "function" !== typeof g.getSnapshotBeforeUpdate || h === a.memoizedProps && r === a.memoizedState || (b.flags |= 1024), b.memoizedProps = d, b.memoizedState = n), g.props = d, g.state = n, g.context = k, d = l) : ("function" !== typeof g.componentDidUpdate || h === a.memoizedProps && r === a.memoizedState || (b.flags |= 4), "function" !== typeof g.getSnapshotBeforeUpdate || h === a.memoizedProps && r === a.memoizedState || (b.flags |= 1024), d = false);
        }
        return jj(a, b, c, d, f, e);
      }
      function jj(a, b, c, d, e, f) {
        gj(a, b);
        var g = 0 !== (b.flags & 128);
        if (!d && !g) return e && dg(b, c, false), Zi(a, b, f);
        d = b.stateNode;
        Wi.current = b;
        var h = g && "function" !== typeof c.getDerivedStateFromError ? null : d.render();
        b.flags |= 1;
        null !== a && g ? (b.child = Ug(b, a.child, null, f), b.child = Ug(b, null, h, f)) : Xi(a, b, h, f);
        b.memoizedState = d.state;
        e && dg(b, c, true);
        return b.child;
      }
      function kj(a) {
        var b = a.stateNode;
        b.pendingContext ? ag(a, b.pendingContext, b.pendingContext !== b.context) : b.context && ag(a, b.context, false);
        yh(a, b.containerInfo);
      }
      function lj(a, b, c, d, e) {
        Ig();
        Jg(e);
        b.flags |= 256;
        Xi(a, b, c, d);
        return b.child;
      }
      var mj = { dehydrated: null, treeContext: null, retryLane: 0 };
      function nj(a) {
        return { baseLanes: a, cachePool: null, transitions: null };
      }
      function oj(a, b, c) {
        var d = b.pendingProps, e = L.current, f = false, g = 0 !== (b.flags & 128), h;
        (h = g) || (h = null !== a && null === a.memoizedState ? false : 0 !== (e & 2));
        if (h) f = true, b.flags &= -129;
        else if (null === a || null !== a.memoizedState) e |= 1;
        G(L, e & 1);
        if (null === a) {
          Eg(b);
          a = b.memoizedState;
          if (null !== a && (a = a.dehydrated, null !== a)) return 0 === (b.mode & 1) ? b.lanes = 1 : "$!" === a.data ? b.lanes = 8 : b.lanes = 1073741824, null;
          g = d.children;
          a = d.fallback;
          return f ? (d = b.mode, f = b.child, g = { mode: "hidden", children: g }, 0 === (d & 1) && null !== f ? (f.childLanes = 0, f.pendingProps = g) : f = pj(g, d, 0, null), a = Tg(a, d, c, null), f.return = b, a.return = b, f.sibling = a, b.child = f, b.child.memoizedState = nj(c), b.memoizedState = mj, a) : qj(b, g);
        }
        e = a.memoizedState;
        if (null !== e && (h = e.dehydrated, null !== h)) return rj(a, b, g, d, h, e, c);
        if (f) {
          f = d.fallback;
          g = b.mode;
          e = a.child;
          h = e.sibling;
          var k = { mode: "hidden", children: d.children };
          0 === (g & 1) && b.child !== e ? (d = b.child, d.childLanes = 0, d.pendingProps = k, b.deletions = null) : (d = Pg(e, k), d.subtreeFlags = e.subtreeFlags & 14680064);
          null !== h ? f = Pg(h, f) : (f = Tg(f, g, c, null), f.flags |= 2);
          f.return = b;
          d.return = b;
          d.sibling = f;
          b.child = d;
          d = f;
          f = b.child;
          g = a.child.memoizedState;
          g = null === g ? nj(c) : { baseLanes: g.baseLanes | c, cachePool: null, transitions: g.transitions };
          f.memoizedState = g;
          f.childLanes = a.childLanes & ~c;
          b.memoizedState = mj;
          return d;
        }
        f = a.child;
        a = f.sibling;
        d = Pg(f, { mode: "visible", children: d.children });
        0 === (b.mode & 1) && (d.lanes = c);
        d.return = b;
        d.sibling = null;
        null !== a && (c = b.deletions, null === c ? (b.deletions = [a], b.flags |= 16) : c.push(a));
        b.child = d;
        b.memoizedState = null;
        return d;
      }
      function qj(a, b) {
        b = pj({ mode: "visible", children: b }, a.mode, 0, null);
        b.return = a;
        return a.child = b;
      }
      function sj(a, b, c, d) {
        null !== d && Jg(d);
        Ug(b, a.child, null, c);
        a = qj(b, b.pendingProps.children);
        a.flags |= 2;
        b.memoizedState = null;
        return a;
      }
      function rj(a, b, c, d, e, f, g) {
        if (c) {
          if (b.flags & 256) return b.flags &= -257, d = Ki(Error(p(422))), sj(a, b, g, d);
          if (null !== b.memoizedState) return b.child = a.child, b.flags |= 128, null;
          f = d.fallback;
          e = b.mode;
          d = pj({ mode: "visible", children: d.children }, e, 0, null);
          f = Tg(f, e, g, null);
          f.flags |= 2;
          d.return = b;
          f.return = b;
          d.sibling = f;
          b.child = d;
          0 !== (b.mode & 1) && Ug(b, a.child, null, g);
          b.child.memoizedState = nj(g);
          b.memoizedState = mj;
          return f;
        }
        if (0 === (b.mode & 1)) return sj(a, b, g, null);
        if ("$!" === e.data) {
          d = e.nextSibling && e.nextSibling.dataset;
          if (d) var h = d.dgst;
          d = h;
          f = Error(p(419));
          d = Ki(f, d, void 0);
          return sj(a, b, g, d);
        }
        h = 0 !== (g & a.childLanes);
        if (dh || h) {
          d = Q;
          if (null !== d) {
            switch (g & -g) {
              case 4:
                e = 2;
                break;
              case 16:
                e = 8;
                break;
              case 64:
              case 128:
              case 256:
              case 512:
              case 1024:
              case 2048:
              case 4096:
              case 8192:
              case 16384:
              case 32768:
              case 65536:
              case 131072:
              case 262144:
              case 524288:
              case 1048576:
              case 2097152:
              case 4194304:
              case 8388608:
              case 16777216:
              case 33554432:
              case 67108864:
                e = 32;
                break;
              case 536870912:
                e = 268435456;
                break;
              default:
                e = 0;
            }
            e = 0 !== (e & (d.suspendedLanes | g)) ? 0 : e;
            0 !== e && e !== f.retryLane && (f.retryLane = e, ih(a, e), gi(d, a, e, -1));
          }
          tj();
          d = Ki(Error(p(421)));
          return sj(a, b, g, d);
        }
        if ("$?" === e.data) return b.flags |= 128, b.child = a.child, b = uj.bind(null, a), e._reactRetry = b, null;
        a = f.treeContext;
        yg = Lf(e.nextSibling);
        xg = b;
        I = true;
        zg = null;
        null !== a && (og[pg++] = rg, og[pg++] = sg, og[pg++] = qg, rg = a.id, sg = a.overflow, qg = b);
        b = qj(b, d.children);
        b.flags |= 4096;
        return b;
      }
      function vj(a, b, c) {
        a.lanes |= b;
        var d = a.alternate;
        null !== d && (d.lanes |= b);
        bh(a.return, b, c);
      }
      function wj(a, b, c, d, e) {
        var f = a.memoizedState;
        null === f ? a.memoizedState = { isBackwards: b, rendering: null, renderingStartTime: 0, last: d, tail: c, tailMode: e } : (f.isBackwards = b, f.rendering = null, f.renderingStartTime = 0, f.last = d, f.tail = c, f.tailMode = e);
      }
      function xj(a, b, c) {
        var d = b.pendingProps, e = d.revealOrder, f = d.tail;
        Xi(a, b, d.children, c);
        d = L.current;
        if (0 !== (d & 2)) d = d & 1 | 2, b.flags |= 128;
        else {
          if (null !== a && 0 !== (a.flags & 128)) a: for (a = b.child; null !== a; ) {
            if (13 === a.tag) null !== a.memoizedState && vj(a, c, b);
            else if (19 === a.tag) vj(a, c, b);
            else if (null !== a.child) {
              a.child.return = a;
              a = a.child;
              continue;
            }
            if (a === b) break a;
            for (; null === a.sibling; ) {
              if (null === a.return || a.return === b) break a;
              a = a.return;
            }
            a.sibling.return = a.return;
            a = a.sibling;
          }
          d &= 1;
        }
        G(L, d);
        if (0 === (b.mode & 1)) b.memoizedState = null;
        else switch (e) {
          case "forwards":
            c = b.child;
            for (e = null; null !== c; ) a = c.alternate, null !== a && null === Ch(a) && (e = c), c = c.sibling;
            c = e;
            null === c ? (e = b.child, b.child = null) : (e = c.sibling, c.sibling = null);
            wj(b, false, e, c, f);
            break;
          case "backwards":
            c = null;
            e = b.child;
            for (b.child = null; null !== e; ) {
              a = e.alternate;
              if (null !== a && null === Ch(a)) {
                b.child = e;
                break;
              }
              a = e.sibling;
              e.sibling = c;
              c = e;
              e = a;
            }
            wj(b, true, c, null, f);
            break;
          case "together":
            wj(b, false, null, null, void 0);
            break;
          default:
            b.memoizedState = null;
        }
        return b.child;
      }
      function ij(a, b) {
        0 === (b.mode & 1) && null !== a && (a.alternate = null, b.alternate = null, b.flags |= 2);
      }
      function Zi(a, b, c) {
        null !== a && (b.dependencies = a.dependencies);
        rh |= b.lanes;
        if (0 === (c & b.childLanes)) return null;
        if (null !== a && b.child !== a.child) throw Error(p(153));
        if (null !== b.child) {
          a = b.child;
          c = Pg(a, a.pendingProps);
          b.child = c;
          for (c.return = b; null !== a.sibling; ) a = a.sibling, c = c.sibling = Pg(a, a.pendingProps), c.return = b;
          c.sibling = null;
        }
        return b.child;
      }
      function yj(a, b, c) {
        switch (b.tag) {
          case 3:
            kj(b);
            Ig();
            break;
          case 5:
            Ah(b);
            break;
          case 1:
            Zf(b.type) && cg(b);
            break;
          case 4:
            yh(b, b.stateNode.containerInfo);
            break;
          case 10:
            var d = b.type._context, e = b.memoizedProps.value;
            G(Wg, d._currentValue);
            d._currentValue = e;
            break;
          case 13:
            d = b.memoizedState;
            if (null !== d) {
              if (null !== d.dehydrated) return G(L, L.current & 1), b.flags |= 128, null;
              if (0 !== (c & b.child.childLanes)) return oj(a, b, c);
              G(L, L.current & 1);
              a = Zi(a, b, c);
              return null !== a ? a.sibling : null;
            }
            G(L, L.current & 1);
            break;
          case 19:
            d = 0 !== (c & b.childLanes);
            if (0 !== (a.flags & 128)) {
              if (d) return xj(a, b, c);
              b.flags |= 128;
            }
            e = b.memoizedState;
            null !== e && (e.rendering = null, e.tail = null, e.lastEffect = null);
            G(L, L.current);
            if (d) break;
            else return null;
          case 22:
          case 23:
            return b.lanes = 0, dj(a, b, c);
        }
        return Zi(a, b, c);
      }
      var zj;
      var Aj;
      var Bj;
      var Cj;
      zj = function(a, b) {
        for (var c = b.child; null !== c; ) {
          if (5 === c.tag || 6 === c.tag) a.appendChild(c.stateNode);
          else if (4 !== c.tag && null !== c.child) {
            c.child.return = c;
            c = c.child;
            continue;
          }
          if (c === b) break;
          for (; null === c.sibling; ) {
            if (null === c.return || c.return === b) return;
            c = c.return;
          }
          c.sibling.return = c.return;
          c = c.sibling;
        }
      };
      Aj = function() {
      };
      Bj = function(a, b, c, d) {
        var e = a.memoizedProps;
        if (e !== d) {
          a = b.stateNode;
          xh(uh.current);
          var f = null;
          switch (c) {
            case "input":
              e = Ya(a, e);
              d = Ya(a, d);
              f = [];
              break;
            case "select":
              e = A({}, e, { value: void 0 });
              d = A({}, d, { value: void 0 });
              f = [];
              break;
            case "textarea":
              e = gb(a, e);
              d = gb(a, d);
              f = [];
              break;
            default:
              "function" !== typeof e.onClick && "function" === typeof d.onClick && (a.onclick = Bf);
          }
          ub(c, d);
          var g;
          c = null;
          for (l in e) if (!d.hasOwnProperty(l) && e.hasOwnProperty(l) && null != e[l]) if ("style" === l) {
            var h = e[l];
            for (g in h) h.hasOwnProperty(g) && (c || (c = {}), c[g] = "");
          } else "dangerouslySetInnerHTML" !== l && "children" !== l && "suppressContentEditableWarning" !== l && "suppressHydrationWarning" !== l && "autoFocus" !== l && (ea.hasOwnProperty(l) ? f || (f = []) : (f = f || []).push(l, null));
          for (l in d) {
            var k = d[l];
            h = null != e ? e[l] : void 0;
            if (d.hasOwnProperty(l) && k !== h && (null != k || null != h)) if ("style" === l) if (h) {
              for (g in h) !h.hasOwnProperty(g) || k && k.hasOwnProperty(g) || (c || (c = {}), c[g] = "");
              for (g in k) k.hasOwnProperty(g) && h[g] !== k[g] && (c || (c = {}), c[g] = k[g]);
            } else c || (f || (f = []), f.push(
              l,
              c
            )), c = k;
            else "dangerouslySetInnerHTML" === l ? (k = k ? k.__html : void 0, h = h ? h.__html : void 0, null != k && h !== k && (f = f || []).push(l, k)) : "children" === l ? "string" !== typeof k && "number" !== typeof k || (f = f || []).push(l, "" + k) : "suppressContentEditableWarning" !== l && "suppressHydrationWarning" !== l && (ea.hasOwnProperty(l) ? (null != k && "onScroll" === l && D("scroll", a), f || h === k || (f = [])) : (f = f || []).push(l, k));
          }
          c && (f = f || []).push("style", c);
          var l = f;
          if (b.updateQueue = l) b.flags |= 4;
        }
      };
      Cj = function(a, b, c, d) {
        c !== d && (b.flags |= 4);
      };
      function Dj(a, b) {
        if (!I) switch (a.tailMode) {
          case "hidden":
            b = a.tail;
            for (var c = null; null !== b; ) null !== b.alternate && (c = b), b = b.sibling;
            null === c ? a.tail = null : c.sibling = null;
            break;
          case "collapsed":
            c = a.tail;
            for (var d = null; null !== c; ) null !== c.alternate && (d = c), c = c.sibling;
            null === d ? b || null === a.tail ? a.tail = null : a.tail.sibling = null : d.sibling = null;
        }
      }
      function S(a) {
        var b = null !== a.alternate && a.alternate.child === a.child, c = 0, d = 0;
        if (b) for (var e = a.child; null !== e; ) c |= e.lanes | e.childLanes, d |= e.subtreeFlags & 14680064, d |= e.flags & 14680064, e.return = a, e = e.sibling;
        else for (e = a.child; null !== e; ) c |= e.lanes | e.childLanes, d |= e.subtreeFlags, d |= e.flags, e.return = a, e = e.sibling;
        a.subtreeFlags |= d;
        a.childLanes = c;
        return b;
      }
      function Ej(a, b, c) {
        var d = b.pendingProps;
        wg(b);
        switch (b.tag) {
          case 2:
          case 16:
          case 15:
          case 0:
          case 11:
          case 7:
          case 8:
          case 12:
          case 9:
          case 14:
            return S(b), null;
          case 1:
            return Zf(b.type) && $f(), S(b), null;
          case 3:
            d = b.stateNode;
            zh();
            E(Wf);
            E(H);
            Eh();
            d.pendingContext && (d.context = d.pendingContext, d.pendingContext = null);
            if (null === a || null === a.child) Gg(b) ? b.flags |= 4 : null === a || a.memoizedState.isDehydrated && 0 === (b.flags & 256) || (b.flags |= 1024, null !== zg && (Fj(zg), zg = null));
            Aj(a, b);
            S(b);
            return null;
          case 5:
            Bh(b);
            var e = xh(wh.current);
            c = b.type;
            if (null !== a && null != b.stateNode) Bj(a, b, c, d, e), a.ref !== b.ref && (b.flags |= 512, b.flags |= 2097152);
            else {
              if (!d) {
                if (null === b.stateNode) throw Error(p(166));
                S(b);
                return null;
              }
              a = xh(uh.current);
              if (Gg(b)) {
                d = b.stateNode;
                c = b.type;
                var f = b.memoizedProps;
                d[Of] = b;
                d[Pf] = f;
                a = 0 !== (b.mode & 1);
                switch (c) {
                  case "dialog":
                    D("cancel", d);
                    D("close", d);
                    break;
                  case "iframe":
                  case "object":
                  case "embed":
                    D("load", d);
                    break;
                  case "video":
                  case "audio":
                    for (e = 0; e < lf.length; e++) D(lf[e], d);
                    break;
                  case "source":
                    D("error", d);
                    break;
                  case "img":
                  case "image":
                  case "link":
                    D(
                      "error",
                      d
                    );
                    D("load", d);
                    break;
                  case "details":
                    D("toggle", d);
                    break;
                  case "input":
                    Za(d, f);
                    D("invalid", d);
                    break;
                  case "select":
                    d._wrapperState = { wasMultiple: !!f.multiple };
                    D("invalid", d);
                    break;
                  case "textarea":
                    hb(d, f), D("invalid", d);
                }
                ub(c, f);
                e = null;
                for (var g in f) if (f.hasOwnProperty(g)) {
                  var h = f[g];
                  "children" === g ? "string" === typeof h ? d.textContent !== h && (true !== f.suppressHydrationWarning && Af(d.textContent, h, a), e = ["children", h]) : "number" === typeof h && d.textContent !== "" + h && (true !== f.suppressHydrationWarning && Af(
                    d.textContent,
                    h,
                    a
                  ), e = ["children", "" + h]) : ea.hasOwnProperty(g) && null != h && "onScroll" === g && D("scroll", d);
                }
                switch (c) {
                  case "input":
                    Va(d);
                    db(d, f, true);
                    break;
                  case "textarea":
                    Va(d);
                    jb(d);
                    break;
                  case "select":
                  case "option":
                    break;
                  default:
                    "function" === typeof f.onClick && (d.onclick = Bf);
                }
                d = e;
                b.updateQueue = d;
                null !== d && (b.flags |= 4);
              } else {
                g = 9 === e.nodeType ? e : e.ownerDocument;
                "http://www.w3.org/1999/xhtml" === a && (a = kb(c));
                "http://www.w3.org/1999/xhtml" === a ? "script" === c ? (a = g.createElement("div"), a.innerHTML = "<script><\/script>", a = a.removeChild(a.firstChild)) : "string" === typeof d.is ? a = g.createElement(c, { is: d.is }) : (a = g.createElement(c), "select" === c && (g = a, d.multiple ? g.multiple = true : d.size && (g.size = d.size))) : a = g.createElementNS(a, c);
                a[Of] = b;
                a[Pf] = d;
                zj(a, b, false, false);
                b.stateNode = a;
                a: {
                  g = vb(c, d);
                  switch (c) {
                    case "dialog":
                      D("cancel", a);
                      D("close", a);
                      e = d;
                      break;
                    case "iframe":
                    case "object":
                    case "embed":
                      D("load", a);
                      e = d;
                      break;
                    case "video":
                    case "audio":
                      for (e = 0; e < lf.length; e++) D(lf[e], a);
                      e = d;
                      break;
                    case "source":
                      D("error", a);
                      e = d;
                      break;
                    case "img":
                    case "image":
                    case "link":
                      D(
                        "error",
                        a
                      );
                      D("load", a);
                      e = d;
                      break;
                    case "details":
                      D("toggle", a);
                      e = d;
                      break;
                    case "input":
                      Za(a, d);
                      e = Ya(a, d);
                      D("invalid", a);
                      break;
                    case "option":
                      e = d;
                      break;
                    case "select":
                      a._wrapperState = { wasMultiple: !!d.multiple };
                      e = A({}, d, { value: void 0 });
                      D("invalid", a);
                      break;
                    case "textarea":
                      hb(a, d);
                      e = gb(a, d);
                      D("invalid", a);
                      break;
                    default:
                      e = d;
                  }
                  ub(c, e);
                  h = e;
                  for (f in h) if (h.hasOwnProperty(f)) {
                    var k = h[f];
                    "style" === f ? sb(a, k) : "dangerouslySetInnerHTML" === f ? (k = k ? k.__html : void 0, null != k && nb(a, k)) : "children" === f ? "string" === typeof k ? ("textarea" !== c || "" !== k) && ob(a, k) : "number" === typeof k && ob(a, "" + k) : "suppressContentEditableWarning" !== f && "suppressHydrationWarning" !== f && "autoFocus" !== f && (ea.hasOwnProperty(f) ? null != k && "onScroll" === f && D("scroll", a) : null != k && ta(a, f, k, g));
                  }
                  switch (c) {
                    case "input":
                      Va(a);
                      db(a, d, false);
                      break;
                    case "textarea":
                      Va(a);
                      jb(a);
                      break;
                    case "option":
                      null != d.value && a.setAttribute("value", "" + Sa(d.value));
                      break;
                    case "select":
                      a.multiple = !!d.multiple;
                      f = d.value;
                      null != f ? fb(a, !!d.multiple, f, false) : null != d.defaultValue && fb(
                        a,
                        !!d.multiple,
                        d.defaultValue,
                        true
                      );
                      break;
                    default:
                      "function" === typeof e.onClick && (a.onclick = Bf);
                  }
                  switch (c) {
                    case "button":
                    case "input":
                    case "select":
                    case "textarea":
                      d = !!d.autoFocus;
                      break a;
                    case "img":
                      d = true;
                      break a;
                    default:
                      d = false;
                  }
                }
                d && (b.flags |= 4);
              }
              null !== b.ref && (b.flags |= 512, b.flags |= 2097152);
            }
            S(b);
            return null;
          case 6:
            if (a && null != b.stateNode) Cj(a, b, a.memoizedProps, d);
            else {
              if ("string" !== typeof d && null === b.stateNode) throw Error(p(166));
              c = xh(wh.current);
              xh(uh.current);
              if (Gg(b)) {
                d = b.stateNode;
                c = b.memoizedProps;
                d[Of] = b;
                if (f = d.nodeValue !== c) {
                  if (a = xg, null !== a) switch (a.tag) {
                    case 3:
                      Af(d.nodeValue, c, 0 !== (a.mode & 1));
                      break;
                    case 5:
                      true !== a.memoizedProps.suppressHydrationWarning && Af(d.nodeValue, c, 0 !== (a.mode & 1));
                  }
                }
                f && (b.flags |= 4);
              } else d = (9 === c.nodeType ? c : c.ownerDocument).createTextNode(d), d[Of] = b, b.stateNode = d;
            }
            S(b);
            return null;
          case 13:
            E(L);
            d = b.memoizedState;
            if (null === a || null !== a.memoizedState && null !== a.memoizedState.dehydrated) {
              if (I && null !== yg && 0 !== (b.mode & 1) && 0 === (b.flags & 128)) Hg(), Ig(), b.flags |= 98560, f = false;
              else if (f = Gg(b), null !== d && null !== d.dehydrated) {
                if (null === a) {
                  if (!f) throw Error(p(318));
                  f = b.memoizedState;
                  f = null !== f ? f.dehydrated : null;
                  if (!f) throw Error(p(317));
                  f[Of] = b;
                } else Ig(), 0 === (b.flags & 128) && (b.memoizedState = null), b.flags |= 4;
                S(b);
                f = false;
              } else null !== zg && (Fj(zg), zg = null), f = true;
              if (!f) return b.flags & 65536 ? b : null;
            }
            if (0 !== (b.flags & 128)) return b.lanes = c, b;
            d = null !== d;
            d !== (null !== a && null !== a.memoizedState) && d && (b.child.flags |= 8192, 0 !== (b.mode & 1) && (null === a || 0 !== (L.current & 1) ? 0 === T && (T = 3) : tj()));
            null !== b.updateQueue && (b.flags |= 4);
            S(b);
            return null;
          case 4:
            return zh(), Aj(a, b), null === a && sf(b.stateNode.containerInfo), S(b), null;
          case 10:
            return ah(b.type._context), S(b), null;
          case 17:
            return Zf(b.type) && $f(), S(b), null;
          case 19:
            E(L);
            f = b.memoizedState;
            if (null === f) return S(b), null;
            d = 0 !== (b.flags & 128);
            g = f.rendering;
            if (null === g) if (d) Dj(f, false);
            else {
              if (0 !== T || null !== a && 0 !== (a.flags & 128)) for (a = b.child; null !== a; ) {
                g = Ch(a);
                if (null !== g) {
                  b.flags |= 128;
                  Dj(f, false);
                  d = g.updateQueue;
                  null !== d && (b.updateQueue = d, b.flags |= 4);
                  b.subtreeFlags = 0;
                  d = c;
                  for (c = b.child; null !== c; ) f = c, a = d, f.flags &= 14680066, g = f.alternate, null === g ? (f.childLanes = 0, f.lanes = a, f.child = null, f.subtreeFlags = 0, f.memoizedProps = null, f.memoizedState = null, f.updateQueue = null, f.dependencies = null, f.stateNode = null) : (f.childLanes = g.childLanes, f.lanes = g.lanes, f.child = g.child, f.subtreeFlags = 0, f.deletions = null, f.memoizedProps = g.memoizedProps, f.memoizedState = g.memoizedState, f.updateQueue = g.updateQueue, f.type = g.type, a = g.dependencies, f.dependencies = null === a ? null : { lanes: a.lanes, firstContext: a.firstContext }), c = c.sibling;
                  G(L, L.current & 1 | 2);
                  return b.child;
                }
                a = a.sibling;
              }
              null !== f.tail && B() > Gj && (b.flags |= 128, d = true, Dj(f, false), b.lanes = 4194304);
            }
            else {
              if (!d) if (a = Ch(g), null !== a) {
                if (b.flags |= 128, d = true, c = a.updateQueue, null !== c && (b.updateQueue = c, b.flags |= 4), Dj(f, true), null === f.tail && "hidden" === f.tailMode && !g.alternate && !I) return S(b), null;
              } else 2 * B() - f.renderingStartTime > Gj && 1073741824 !== c && (b.flags |= 128, d = true, Dj(f, false), b.lanes = 4194304);
              f.isBackwards ? (g.sibling = b.child, b.child = g) : (c = f.last, null !== c ? c.sibling = g : b.child = g, f.last = g);
            }
            if (null !== f.tail) return b = f.tail, f.rendering = b, f.tail = b.sibling, f.renderingStartTime = B(), b.sibling = null, c = L.current, G(L, d ? c & 1 | 2 : c & 1), b;
            S(b);
            return null;
          case 22:
          case 23:
            return Hj(), d = null !== b.memoizedState, null !== a && null !== a.memoizedState !== d && (b.flags |= 8192), d && 0 !== (b.mode & 1) ? 0 !== (fj & 1073741824) && (S(b), b.subtreeFlags & 6 && (b.flags |= 8192)) : S(b), null;
          case 24:
            return null;
          case 25:
            return null;
        }
        throw Error(p(156, b.tag));
      }
      function Ij(a, b) {
        wg(b);
        switch (b.tag) {
          case 1:
            return Zf(b.type) && $f(), a = b.flags, a & 65536 ? (b.flags = a & -65537 | 128, b) : null;
          case 3:
            return zh(), E(Wf), E(H), Eh(), a = b.flags, 0 !== (a & 65536) && 0 === (a & 128) ? (b.flags = a & -65537 | 128, b) : null;
          case 5:
            return Bh(b), null;
          case 13:
            E(L);
            a = b.memoizedState;
            if (null !== a && null !== a.dehydrated) {
              if (null === b.alternate) throw Error(p(340));
              Ig();
            }
            a = b.flags;
            return a & 65536 ? (b.flags = a & -65537 | 128, b) : null;
          case 19:
            return E(L), null;
          case 4:
            return zh(), null;
          case 10:
            return ah(b.type._context), null;
          case 22:
          case 23:
            return Hj(), null;
          case 24:
            return null;
          default:
            return null;
        }
      }
      var Jj = false;
      var U = false;
      var Kj = "function" === typeof WeakSet ? WeakSet : Set;
      var V = null;
      function Lj(a, b) {
        var c = a.ref;
        if (null !== c) if ("function" === typeof c) try {
          c(null);
        } catch (d) {
          W(a, b, d);
        }
        else c.current = null;
      }
      function Mj(a, b, c) {
        try {
          c();
        } catch (d) {
          W(a, b, d);
        }
      }
      var Nj = false;
      function Oj(a, b) {
        Cf = dd;
        a = Me();
        if (Ne(a)) {
          if ("selectionStart" in a) var c = { start: a.selectionStart, end: a.selectionEnd };
          else a: {
            c = (c = a.ownerDocument) && c.defaultView || window;
            var d = c.getSelection && c.getSelection();
            if (d && 0 !== d.rangeCount) {
              c = d.anchorNode;
              var e = d.anchorOffset, f = d.focusNode;
              d = d.focusOffset;
              try {
                c.nodeType, f.nodeType;
              } catch (F) {
                c = null;
                break a;
              }
              var g = 0, h = -1, k = -1, l = 0, m = 0, q = a, r = null;
              b: for (; ; ) {
                for (var y; ; ) {
                  q !== c || 0 !== e && 3 !== q.nodeType || (h = g + e);
                  q !== f || 0 !== d && 3 !== q.nodeType || (k = g + d);
                  3 === q.nodeType && (g += q.nodeValue.length);
                  if (null === (y = q.firstChild)) break;
                  r = q;
                  q = y;
                }
                for (; ; ) {
                  if (q === a) break b;
                  r === c && ++l === e && (h = g);
                  r === f && ++m === d && (k = g);
                  if (null !== (y = q.nextSibling)) break;
                  q = r;
                  r = q.parentNode;
                }
                q = y;
              }
              c = -1 === h || -1 === k ? null : { start: h, end: k };
            } else c = null;
          }
          c = c || { start: 0, end: 0 };
        } else c = null;
        Df = { focusedElem: a, selectionRange: c };
        dd = false;
        for (V = b; null !== V; ) if (b = V, a = b.child, 0 !== (b.subtreeFlags & 1028) && null !== a) a.return = b, V = a;
        else for (; null !== V; ) {
          b = V;
          try {
            var n = b.alternate;
            if (0 !== (b.flags & 1024)) switch (b.tag) {
              case 0:
              case 11:
              case 15:
                break;
              case 1:
                if (null !== n) {
                  var t = n.memoizedProps, J = n.memoizedState, x = b.stateNode, w = x.getSnapshotBeforeUpdate(b.elementType === b.type ? t : Ci(b.type, t), J);
                  x.__reactInternalSnapshotBeforeUpdate = w;
                }
                break;
              case 3:
                var u = b.stateNode.containerInfo;
                1 === u.nodeType ? u.textContent = "" : 9 === u.nodeType && u.documentElement && u.removeChild(u.documentElement);
                break;
              case 5:
              case 6:
              case 4:
              case 17:
                break;
              default:
                throw Error(p(163));
            }
          } catch (F) {
            W(b, b.return, F);
          }
          a = b.sibling;
          if (null !== a) {
            a.return = b.return;
            V = a;
            break;
          }
          V = b.return;
        }
        n = Nj;
        Nj = false;
        return n;
      }
      function Pj(a, b, c) {
        var d = b.updateQueue;
        d = null !== d ? d.lastEffect : null;
        if (null !== d) {
          var e = d = d.next;
          do {
            if ((e.tag & a) === a) {
              var f = e.destroy;
              e.destroy = void 0;
              void 0 !== f && Mj(b, c, f);
            }
            e = e.next;
          } while (e !== d);
        }
      }
      function Qj(a, b) {
        b = b.updateQueue;
        b = null !== b ? b.lastEffect : null;
        if (null !== b) {
          var c = b = b.next;
          do {
            if ((c.tag & a) === a) {
              var d = c.create;
              c.destroy = d();
            }
            c = c.next;
          } while (c !== b);
        }
      }
      function Rj(a) {
        var b = a.ref;
        if (null !== b) {
          var c = a.stateNode;
          switch (a.tag) {
            case 5:
              a = c;
              break;
            default:
              a = c;
          }
          "function" === typeof b ? b(a) : b.current = a;
        }
      }
      function Sj(a) {
        var b = a.alternate;
        null !== b && (a.alternate = null, Sj(b));
        a.child = null;
        a.deletions = null;
        a.sibling = null;
        5 === a.tag && (b = a.stateNode, null !== b && (delete b[Of], delete b[Pf], delete b[of], delete b[Qf], delete b[Rf]));
        a.stateNode = null;
        a.return = null;
        a.dependencies = null;
        a.memoizedProps = null;
        a.memoizedState = null;
        a.pendingProps = null;
        a.stateNode = null;
        a.updateQueue = null;
      }
      function Tj(a) {
        return 5 === a.tag || 3 === a.tag || 4 === a.tag;
      }
      function Uj(a) {
        a: for (; ; ) {
          for (; null === a.sibling; ) {
            if (null === a.return || Tj(a.return)) return null;
            a = a.return;
          }
          a.sibling.return = a.return;
          for (a = a.sibling; 5 !== a.tag && 6 !== a.tag && 18 !== a.tag; ) {
            if (a.flags & 2) continue a;
            if (null === a.child || 4 === a.tag) continue a;
            else a.child.return = a, a = a.child;
          }
          if (!(a.flags & 2)) return a.stateNode;
        }
      }
      function Vj(a, b, c) {
        var d = a.tag;
        if (5 === d || 6 === d) a = a.stateNode, b ? 8 === c.nodeType ? c.parentNode.insertBefore(a, b) : c.insertBefore(a, b) : (8 === c.nodeType ? (b = c.parentNode, b.insertBefore(a, c)) : (b = c, b.appendChild(a)), c = c._reactRootContainer, null !== c && void 0 !== c || null !== b.onclick || (b.onclick = Bf));
        else if (4 !== d && (a = a.child, null !== a)) for (Vj(a, b, c), a = a.sibling; null !== a; ) Vj(a, b, c), a = a.sibling;
      }
      function Wj(a, b, c) {
        var d = a.tag;
        if (5 === d || 6 === d) a = a.stateNode, b ? c.insertBefore(a, b) : c.appendChild(a);
        else if (4 !== d && (a = a.child, null !== a)) for (Wj(a, b, c), a = a.sibling; null !== a; ) Wj(a, b, c), a = a.sibling;
      }
      var X = null;
      var Xj = false;
      function Yj(a, b, c) {
        for (c = c.child; null !== c; ) Zj(a, b, c), c = c.sibling;
      }
      function Zj(a, b, c) {
        if (lc && "function" === typeof lc.onCommitFiberUnmount) try {
          lc.onCommitFiberUnmount(kc, c);
        } catch (h) {
        }
        switch (c.tag) {
          case 5:
            U || Lj(c, b);
          case 6:
            var d = X, e = Xj;
            X = null;
            Yj(a, b, c);
            X = d;
            Xj = e;
            null !== X && (Xj ? (a = X, c = c.stateNode, 8 === a.nodeType ? a.parentNode.removeChild(c) : a.removeChild(c)) : X.removeChild(c.stateNode));
            break;
          case 18:
            null !== X && (Xj ? (a = X, c = c.stateNode, 8 === a.nodeType ? Kf(a.parentNode, c) : 1 === a.nodeType && Kf(a, c), bd(a)) : Kf(X, c.stateNode));
            break;
          case 4:
            d = X;
            e = Xj;
            X = c.stateNode.containerInfo;
            Xj = true;
            Yj(a, b, c);
            X = d;
            Xj = e;
            break;
          case 0:
          case 11:
          case 14:
          case 15:
            if (!U && (d = c.updateQueue, null !== d && (d = d.lastEffect, null !== d))) {
              e = d = d.next;
              do {
                var f = e, g = f.destroy;
                f = f.tag;
                void 0 !== g && (0 !== (f & 2) ? Mj(c, b, g) : 0 !== (f & 4) && Mj(c, b, g));
                e = e.next;
              } while (e !== d);
            }
            Yj(a, b, c);
            break;
          case 1:
            if (!U && (Lj(c, b), d = c.stateNode, "function" === typeof d.componentWillUnmount)) try {
              d.props = c.memoizedProps, d.state = c.memoizedState, d.componentWillUnmount();
            } catch (h) {
              W(c, b, h);
            }
            Yj(a, b, c);
            break;
          case 21:
            Yj(a, b, c);
            break;
          case 22:
            c.mode & 1 ? (U = (d = U) || null !== c.memoizedState, Yj(a, b, c), U = d) : Yj(a, b, c);
            break;
          default:
            Yj(a, b, c);
        }
      }
      function ak(a) {
        var b = a.updateQueue;
        if (null !== b) {
          a.updateQueue = null;
          var c = a.stateNode;
          null === c && (c = a.stateNode = new Kj());
          b.forEach(function(b2) {
            var d = bk.bind(null, a, b2);
            c.has(b2) || (c.add(b2), b2.then(d, d));
          });
        }
      }
      function ck(a, b) {
        var c = b.deletions;
        if (null !== c) for (var d = 0; d < c.length; d++) {
          var e = c[d];
          try {
            var f = a, g = b, h = g;
            a: for (; null !== h; ) {
              switch (h.tag) {
                case 5:
                  X = h.stateNode;
                  Xj = false;
                  break a;
                case 3:
                  X = h.stateNode.containerInfo;
                  Xj = true;
                  break a;
                case 4:
                  X = h.stateNode.containerInfo;
                  Xj = true;
                  break a;
              }
              h = h.return;
            }
            if (null === X) throw Error(p(160));
            Zj(f, g, e);
            X = null;
            Xj = false;
            var k = e.alternate;
            null !== k && (k.return = null);
            e.return = null;
          } catch (l) {
            W(e, b, l);
          }
        }
        if (b.subtreeFlags & 12854) for (b = b.child; null !== b; ) dk(b, a), b = b.sibling;
      }
      function dk(a, b) {
        var c = a.alternate, d = a.flags;
        switch (a.tag) {
          case 0:
          case 11:
          case 14:
          case 15:
            ck(b, a);
            ek(a);
            if (d & 4) {
              try {
                Pj(3, a, a.return), Qj(3, a);
              } catch (t) {
                W(a, a.return, t);
              }
              try {
                Pj(5, a, a.return);
              } catch (t) {
                W(a, a.return, t);
              }
            }
            break;
          case 1:
            ck(b, a);
            ek(a);
            d & 512 && null !== c && Lj(c, c.return);
            break;
          case 5:
            ck(b, a);
            ek(a);
            d & 512 && null !== c && Lj(c, c.return);
            if (a.flags & 32) {
              var e = a.stateNode;
              try {
                ob(e, "");
              } catch (t) {
                W(a, a.return, t);
              }
            }
            if (d & 4 && (e = a.stateNode, null != e)) {
              var f = a.memoizedProps, g = null !== c ? c.memoizedProps : f, h = a.type, k = a.updateQueue;
              a.updateQueue = null;
              if (null !== k) try {
                "input" === h && "radio" === f.type && null != f.name && ab(e, f);
                vb(h, g);
                var l = vb(h, f);
                for (g = 0; g < k.length; g += 2) {
                  var m = k[g], q = k[g + 1];
                  "style" === m ? sb(e, q) : "dangerouslySetInnerHTML" === m ? nb(e, q) : "children" === m ? ob(e, q) : ta(e, m, q, l);
                }
                switch (h) {
                  case "input":
                    bb(e, f);
                    break;
                  case "textarea":
                    ib(e, f);
                    break;
                  case "select":
                    var r = e._wrapperState.wasMultiple;
                    e._wrapperState.wasMultiple = !!f.multiple;
                    var y = f.value;
                    null != y ? fb(e, !!f.multiple, y, false) : r !== !!f.multiple && (null != f.defaultValue ? fb(
                      e,
                      !!f.multiple,
                      f.defaultValue,
                      true
                    ) : fb(e, !!f.multiple, f.multiple ? [] : "", false));
                }
                e[Pf] = f;
              } catch (t) {
                W(a, a.return, t);
              }
            }
            break;
          case 6:
            ck(b, a);
            ek(a);
            if (d & 4) {
              if (null === a.stateNode) throw Error(p(162));
              e = a.stateNode;
              f = a.memoizedProps;
              try {
                e.nodeValue = f;
              } catch (t) {
                W(a, a.return, t);
              }
            }
            break;
          case 3:
            ck(b, a);
            ek(a);
            if (d & 4 && null !== c && c.memoizedState.isDehydrated) try {
              bd(b.containerInfo);
            } catch (t) {
              W(a, a.return, t);
            }
            break;
          case 4:
            ck(b, a);
            ek(a);
            break;
          case 13:
            ck(b, a);
            ek(a);
            e = a.child;
            e.flags & 8192 && (f = null !== e.memoizedState, e.stateNode.isHidden = f, !f || null !== e.alternate && null !== e.alternate.memoizedState || (fk = B()));
            d & 4 && ak(a);
            break;
          case 22:
            m = null !== c && null !== c.memoizedState;
            a.mode & 1 ? (U = (l = U) || m, ck(b, a), U = l) : ck(b, a);
            ek(a);
            if (d & 8192) {
              l = null !== a.memoizedState;
              if ((a.stateNode.isHidden = l) && !m && 0 !== (a.mode & 1)) for (V = a, m = a.child; null !== m; ) {
                for (q = V = m; null !== V; ) {
                  r = V;
                  y = r.child;
                  switch (r.tag) {
                    case 0:
                    case 11:
                    case 14:
                    case 15:
                      Pj(4, r, r.return);
                      break;
                    case 1:
                      Lj(r, r.return);
                      var n = r.stateNode;
                      if ("function" === typeof n.componentWillUnmount) {
                        d = r;
                        c = r.return;
                        try {
                          b = d, n.props = b.memoizedProps, n.state = b.memoizedState, n.componentWillUnmount();
                        } catch (t) {
                          W(d, c, t);
                        }
                      }
                      break;
                    case 5:
                      Lj(r, r.return);
                      break;
                    case 22:
                      if (null !== r.memoizedState) {
                        gk(q);
                        continue;
                      }
                  }
                  null !== y ? (y.return = r, V = y) : gk(q);
                }
                m = m.sibling;
              }
              a: for (m = null, q = a; ; ) {
                if (5 === q.tag) {
                  if (null === m) {
                    m = q;
                    try {
                      e = q.stateNode, l ? (f = e.style, "function" === typeof f.setProperty ? f.setProperty("display", "none", "important") : f.display = "none") : (h = q.stateNode, k = q.memoizedProps.style, g = void 0 !== k && null !== k && k.hasOwnProperty("display") ? k.display : null, h.style.display = rb("display", g));
                    } catch (t) {
                      W(a, a.return, t);
                    }
                  }
                } else if (6 === q.tag) {
                  if (null === m) try {
                    q.stateNode.nodeValue = l ? "" : q.memoizedProps;
                  } catch (t) {
                    W(a, a.return, t);
                  }
                } else if ((22 !== q.tag && 23 !== q.tag || null === q.memoizedState || q === a) && null !== q.child) {
                  q.child.return = q;
                  q = q.child;
                  continue;
                }
                if (q === a) break a;
                for (; null === q.sibling; ) {
                  if (null === q.return || q.return === a) break a;
                  m === q && (m = null);
                  q = q.return;
                }
                m === q && (m = null);
                q.sibling.return = q.return;
                q = q.sibling;
              }
            }
            break;
          case 19:
            ck(b, a);
            ek(a);
            d & 4 && ak(a);
            break;
          case 21:
            break;
          default:
            ck(
              b,
              a
            ), ek(a);
        }
      }
      function ek(a) {
        var b = a.flags;
        if (b & 2) {
          try {
            a: {
              for (var c = a.return; null !== c; ) {
                if (Tj(c)) {
                  var d = c;
                  break a;
                }
                c = c.return;
              }
              throw Error(p(160));
            }
            switch (d.tag) {
              case 5:
                var e = d.stateNode;
                d.flags & 32 && (ob(e, ""), d.flags &= -33);
                var f = Uj(a);
                Wj(a, f, e);
                break;
              case 3:
              case 4:
                var g = d.stateNode.containerInfo, h = Uj(a);
                Vj(a, h, g);
                break;
              default:
                throw Error(p(161));
            }
          } catch (k) {
            W(a, a.return, k);
          }
          a.flags &= -3;
        }
        b & 4096 && (a.flags &= -4097);
      }
      function hk(a, b, c) {
        V = a;
        ik(a, b, c);
      }
      function ik(a, b, c) {
        for (var d = 0 !== (a.mode & 1); null !== V; ) {
          var e = V, f = e.child;
          if (22 === e.tag && d) {
            var g = null !== e.memoizedState || Jj;
            if (!g) {
              var h = e.alternate, k = null !== h && null !== h.memoizedState || U;
              h = Jj;
              var l = U;
              Jj = g;
              if ((U = k) && !l) for (V = e; null !== V; ) g = V, k = g.child, 22 === g.tag && null !== g.memoizedState ? jk(e) : null !== k ? (k.return = g, V = k) : jk(e);
              for (; null !== f; ) V = f, ik(f, b, c), f = f.sibling;
              V = e;
              Jj = h;
              U = l;
            }
            kk(a, b, c);
          } else 0 !== (e.subtreeFlags & 8772) && null !== f ? (f.return = e, V = f) : kk(a, b, c);
        }
      }
      function kk(a) {
        for (; null !== V; ) {
          var b = V;
          if (0 !== (b.flags & 8772)) {
            var c = b.alternate;
            try {
              if (0 !== (b.flags & 8772)) switch (b.tag) {
                case 0:
                case 11:
                case 15:
                  U || Qj(5, b);
                  break;
                case 1:
                  var d = b.stateNode;
                  if (b.flags & 4 && !U) if (null === c) d.componentDidMount();
                  else {
                    var e = b.elementType === b.type ? c.memoizedProps : Ci(b.type, c.memoizedProps);
                    d.componentDidUpdate(e, c.memoizedState, d.__reactInternalSnapshotBeforeUpdate);
                  }
                  var f = b.updateQueue;
                  null !== f && sh(b, f, d);
                  break;
                case 3:
                  var g = b.updateQueue;
                  if (null !== g) {
                    c = null;
                    if (null !== b.child) switch (b.child.tag) {
                      case 5:
                        c = b.child.stateNode;
                        break;
                      case 1:
                        c = b.child.stateNode;
                    }
                    sh(b, g, c);
                  }
                  break;
                case 5:
                  var h = b.stateNode;
                  if (null === c && b.flags & 4) {
                    c = h;
                    var k = b.memoizedProps;
                    switch (b.type) {
                      case "button":
                      case "input":
                      case "select":
                      case "textarea":
                        k.autoFocus && c.focus();
                        break;
                      case "img":
                        k.src && (c.src = k.src);
                    }
                  }
                  break;
                case 6:
                  break;
                case 4:
                  break;
                case 12:
                  break;
                case 13:
                  if (null === b.memoizedState) {
                    var l = b.alternate;
                    if (null !== l) {
                      var m = l.memoizedState;
                      if (null !== m) {
                        var q = m.dehydrated;
                        null !== q && bd(q);
                      }
                    }
                  }
                  break;
                case 19:
                case 17:
                case 21:
                case 22:
                case 23:
                case 25:
                  break;
                default:
                  throw Error(p(163));
              }
              U || b.flags & 512 && Rj(b);
            } catch (r) {
              W(b, b.return, r);
            }
          }
          if (b === a) {
            V = null;
            break;
          }
          c = b.sibling;
          if (null !== c) {
            c.return = b.return;
            V = c;
            break;
          }
          V = b.return;
        }
      }
      function gk(a) {
        for (; null !== V; ) {
          var b = V;
          if (b === a) {
            V = null;
            break;
          }
          var c = b.sibling;
          if (null !== c) {
            c.return = b.return;
            V = c;
            break;
          }
          V = b.return;
        }
      }
      function jk(a) {
        for (; null !== V; ) {
          var b = V;
          try {
            switch (b.tag) {
              case 0:
              case 11:
              case 15:
                var c = b.return;
                try {
                  Qj(4, b);
                } catch (k) {
                  W(b, c, k);
                }
                break;
              case 1:
                var d = b.stateNode;
                if ("function" === typeof d.componentDidMount) {
                  var e = b.return;
                  try {
                    d.componentDidMount();
                  } catch (k) {
                    W(b, e, k);
                  }
                }
                var f = b.return;
                try {
                  Rj(b);
                } catch (k) {
                  W(b, f, k);
                }
                break;
              case 5:
                var g = b.return;
                try {
                  Rj(b);
                } catch (k) {
                  W(b, g, k);
                }
            }
          } catch (k) {
            W(b, b.return, k);
          }
          if (b === a) {
            V = null;
            break;
          }
          var h = b.sibling;
          if (null !== h) {
            h.return = b.return;
            V = h;
            break;
          }
          V = b.return;
        }
      }
      var lk = Math.ceil;
      var mk = ua.ReactCurrentDispatcher;
      var nk = ua.ReactCurrentOwner;
      var ok = ua.ReactCurrentBatchConfig;
      var K = 0;
      var Q = null;
      var Y = null;
      var Z = 0;
      var fj = 0;
      var ej = Uf(0);
      var T = 0;
      var pk = null;
      var rh = 0;
      var qk = 0;
      var rk = 0;
      var sk = null;
      var tk = null;
      var fk = 0;
      var Gj = Infinity;
      var uk = null;
      var Oi = false;
      var Pi = null;
      var Ri = null;
      var vk = false;
      var wk = null;
      var xk = 0;
      var yk = 0;
      var zk = null;
      var Ak = -1;
      var Bk = 0;
      function R() {
        return 0 !== (K & 6) ? B() : -1 !== Ak ? Ak : Ak = B();
      }
      function yi(a) {
        if (0 === (a.mode & 1)) return 1;
        if (0 !== (K & 2) && 0 !== Z) return Z & -Z;
        if (null !== Kg.transition) return 0 === Bk && (Bk = yc()), Bk;
        a = C;
        if (0 !== a) return a;
        a = window.event;
        a = void 0 === a ? 16 : jd(a.type);
        return a;
      }
      function gi(a, b, c, d) {
        if (50 < yk) throw yk = 0, zk = null, Error(p(185));
        Ac(a, c, d);
        if (0 === (K & 2) || a !== Q) a === Q && (0 === (K & 2) && (qk |= c), 4 === T && Ck(a, Z)), Dk(a, d), 1 === c && 0 === K && 0 === (b.mode & 1) && (Gj = B() + 500, fg && jg());
      }
      function Dk(a, b) {
        var c = a.callbackNode;
        wc(a, b);
        var d = uc(a, a === Q ? Z : 0);
        if (0 === d) null !== c && bc(c), a.callbackNode = null, a.callbackPriority = 0;
        else if (b = d & -d, a.callbackPriority !== b) {
          null != c && bc(c);
          if (1 === b) 0 === a.tag ? ig(Ek.bind(null, a)) : hg(Ek.bind(null, a)), Jf(function() {
            0 === (K & 6) && jg();
          }), c = null;
          else {
            switch (Dc(d)) {
              case 1:
                c = fc;
                break;
              case 4:
                c = gc;
                break;
              case 16:
                c = hc;
                break;
              case 536870912:
                c = jc;
                break;
              default:
                c = hc;
            }
            c = Fk(c, Gk.bind(null, a));
          }
          a.callbackPriority = b;
          a.callbackNode = c;
        }
      }
      function Gk(a, b) {
        Ak = -1;
        Bk = 0;
        if (0 !== (K & 6)) throw Error(p(327));
        var c = a.callbackNode;
        if (Hk() && a.callbackNode !== c) return null;
        var d = uc(a, a === Q ? Z : 0);
        if (0 === d) return null;
        if (0 !== (d & 30) || 0 !== (d & a.expiredLanes) || b) b = Ik(a, d);
        else {
          b = d;
          var e = K;
          K |= 2;
          var f = Jk();
          if (Q !== a || Z !== b) uk = null, Gj = B() + 500, Kk(a, b);
          do
            try {
              Lk();
              break;
            } catch (h) {
              Mk(a, h);
            }
          while (1);
          $g();
          mk.current = f;
          K = e;
          null !== Y ? b = 0 : (Q = null, Z = 0, b = T);
        }
        if (0 !== b) {
          2 === b && (e = xc(a), 0 !== e && (d = e, b = Nk(a, e)));
          if (1 === b) throw c = pk, Kk(a, 0), Ck(a, d), Dk(a, B()), c;
          if (6 === b) Ck(a, d);
          else {
            e = a.current.alternate;
            if (0 === (d & 30) && !Ok(e) && (b = Ik(a, d), 2 === b && (f = xc(a), 0 !== f && (d = f, b = Nk(a, f))), 1 === b)) throw c = pk, Kk(a, 0), Ck(a, d), Dk(a, B()), c;
            a.finishedWork = e;
            a.finishedLanes = d;
            switch (b) {
              case 0:
              case 1:
                throw Error(p(345));
              case 2:
                Pk(a, tk, uk);
                break;
              case 3:
                Ck(a, d);
                if ((d & 130023424) === d && (b = fk + 500 - B(), 10 < b)) {
                  if (0 !== uc(a, 0)) break;
                  e = a.suspendedLanes;
                  if ((e & d) !== d) {
                    R();
                    a.pingedLanes |= a.suspendedLanes & e;
                    break;
                  }
                  a.timeoutHandle = Ff(Pk.bind(null, a, tk, uk), b);
                  break;
                }
                Pk(a, tk, uk);
                break;
              case 4:
                Ck(a, d);
                if ((d & 4194240) === d) break;
                b = a.eventTimes;
                for (e = -1; 0 < d; ) {
                  var g = 31 - oc(d);
                  f = 1 << g;
                  g = b[g];
                  g > e && (e = g);
                  d &= ~f;
                }
                d = e;
                d = B() - d;
                d = (120 > d ? 120 : 480 > d ? 480 : 1080 > d ? 1080 : 1920 > d ? 1920 : 3e3 > d ? 3e3 : 4320 > d ? 4320 : 1960 * lk(d / 1960)) - d;
                if (10 < d) {
                  a.timeoutHandle = Ff(Pk.bind(null, a, tk, uk), d);
                  break;
                }
                Pk(a, tk, uk);
                break;
              case 5:
                Pk(a, tk, uk);
                break;
              default:
                throw Error(p(329));
            }
          }
        }
        Dk(a, B());
        return a.callbackNode === c ? Gk.bind(null, a) : null;
      }
      function Nk(a, b) {
        var c = sk;
        a.current.memoizedState.isDehydrated && (Kk(a, b).flags |= 256);
        a = Ik(a, b);
        2 !== a && (b = tk, tk = c, null !== b && Fj(b));
        return a;
      }
      function Fj(a) {
        null === tk ? tk = a : tk.push.apply(tk, a);
      }
      function Ok(a) {
        for (var b = a; ; ) {
          if (b.flags & 16384) {
            var c = b.updateQueue;
            if (null !== c && (c = c.stores, null !== c)) for (var d = 0; d < c.length; d++) {
              var e = c[d], f = e.getSnapshot;
              e = e.value;
              try {
                if (!He(f(), e)) return false;
              } catch (g) {
                return false;
              }
            }
          }
          c = b.child;
          if (b.subtreeFlags & 16384 && null !== c) c.return = b, b = c;
          else {
            if (b === a) break;
            for (; null === b.sibling; ) {
              if (null === b.return || b.return === a) return true;
              b = b.return;
            }
            b.sibling.return = b.return;
            b = b.sibling;
          }
        }
        return true;
      }
      function Ck(a, b) {
        b &= ~rk;
        b &= ~qk;
        a.suspendedLanes |= b;
        a.pingedLanes &= ~b;
        for (a = a.expirationTimes; 0 < b; ) {
          var c = 31 - oc(b), d = 1 << c;
          a[c] = -1;
          b &= ~d;
        }
      }
      function Ek(a) {
        if (0 !== (K & 6)) throw Error(p(327));
        Hk();
        var b = uc(a, 0);
        if (0 === (b & 1)) return Dk(a, B()), null;
        var c = Ik(a, b);
        if (0 !== a.tag && 2 === c) {
          var d = xc(a);
          0 !== d && (b = d, c = Nk(a, d));
        }
        if (1 === c) throw c = pk, Kk(a, 0), Ck(a, b), Dk(a, B()), c;
        if (6 === c) throw Error(p(345));
        a.finishedWork = a.current.alternate;
        a.finishedLanes = b;
        Pk(a, tk, uk);
        Dk(a, B());
        return null;
      }
      function Qk(a, b) {
        var c = K;
        K |= 1;
        try {
          return a(b);
        } finally {
          K = c, 0 === K && (Gj = B() + 500, fg && jg());
        }
      }
      function Rk(a) {
        null !== wk && 0 === wk.tag && 0 === (K & 6) && Hk();
        var b = K;
        K |= 1;
        var c = ok.transition, d = C;
        try {
          if (ok.transition = null, C = 1, a) return a();
        } finally {
          C = d, ok.transition = c, K = b, 0 === (K & 6) && jg();
        }
      }
      function Hj() {
        fj = ej.current;
        E(ej);
      }
      function Kk(a, b) {
        a.finishedWork = null;
        a.finishedLanes = 0;
        var c = a.timeoutHandle;
        -1 !== c && (a.timeoutHandle = -1, Gf(c));
        if (null !== Y) for (c = Y.return; null !== c; ) {
          var d = c;
          wg(d);
          switch (d.tag) {
            case 1:
              d = d.type.childContextTypes;
              null !== d && void 0 !== d && $f();
              break;
            case 3:
              zh();
              E(Wf);
              E(H);
              Eh();
              break;
            case 5:
              Bh(d);
              break;
            case 4:
              zh();
              break;
            case 13:
              E(L);
              break;
            case 19:
              E(L);
              break;
            case 10:
              ah(d.type._context);
              break;
            case 22:
            case 23:
              Hj();
          }
          c = c.return;
        }
        Q = a;
        Y = a = Pg(a.current, null);
        Z = fj = b;
        T = 0;
        pk = null;
        rk = qk = rh = 0;
        tk = sk = null;
        if (null !== fh) {
          for (b = 0; b < fh.length; b++) if (c = fh[b], d = c.interleaved, null !== d) {
            c.interleaved = null;
            var e = d.next, f = c.pending;
            if (null !== f) {
              var g = f.next;
              f.next = e;
              d.next = g;
            }
            c.pending = d;
          }
          fh = null;
        }
        return a;
      }
      function Mk(a, b) {
        do {
          var c = Y;
          try {
            $g();
            Fh.current = Rh;
            if (Ih) {
              for (var d = M.memoizedState; null !== d; ) {
                var e = d.queue;
                null !== e && (e.pending = null);
                d = d.next;
              }
              Ih = false;
            }
            Hh = 0;
            O = N = M = null;
            Jh = false;
            Kh = 0;
            nk.current = null;
            if (null === c || null === c.return) {
              T = 1;
              pk = b;
              Y = null;
              break;
            }
            a: {
              var f = a, g = c.return, h = c, k = b;
              b = Z;
              h.flags |= 32768;
              if (null !== k && "object" === typeof k && "function" === typeof k.then) {
                var l = k, m = h, q = m.tag;
                if (0 === (m.mode & 1) && (0 === q || 11 === q || 15 === q)) {
                  var r = m.alternate;
                  r ? (m.updateQueue = r.updateQueue, m.memoizedState = r.memoizedState, m.lanes = r.lanes) : (m.updateQueue = null, m.memoizedState = null);
                }
                var y = Ui(g);
                if (null !== y) {
                  y.flags &= -257;
                  Vi(y, g, h, f, b);
                  y.mode & 1 && Si(f, l, b);
                  b = y;
                  k = l;
                  var n = b.updateQueue;
                  if (null === n) {
                    var t = /* @__PURE__ */ new Set();
                    t.add(k);
                    b.updateQueue = t;
                  } else n.add(k);
                  break a;
                } else {
                  if (0 === (b & 1)) {
                    Si(f, l, b);
                    tj();
                    break a;
                  }
                  k = Error(p(426));
                }
              } else if (I && h.mode & 1) {
                var J = Ui(g);
                if (null !== J) {
                  0 === (J.flags & 65536) && (J.flags |= 256);
                  Vi(J, g, h, f, b);
                  Jg(Ji(k, h));
                  break a;
                }
              }
              f = k = Ji(k, h);
              4 !== T && (T = 2);
              null === sk ? sk = [f] : sk.push(f);
              f = g;
              do {
                switch (f.tag) {
                  case 3:
                    f.flags |= 65536;
                    b &= -b;
                    f.lanes |= b;
                    var x = Ni(f, k, b);
                    ph(f, x);
                    break a;
                  case 1:
                    h = k;
                    var w = f.type, u = f.stateNode;
                    if (0 === (f.flags & 128) && ("function" === typeof w.getDerivedStateFromError || null !== u && "function" === typeof u.componentDidCatch && (null === Ri || !Ri.has(u)))) {
                      f.flags |= 65536;
                      b &= -b;
                      f.lanes |= b;
                      var F = Qi(f, h, b);
                      ph(f, F);
                      break a;
                    }
                }
                f = f.return;
              } while (null !== f);
            }
            Sk(c);
          } catch (na) {
            b = na;
            Y === c && null !== c && (Y = c = c.return);
            continue;
          }
          break;
        } while (1);
      }
      function Jk() {
        var a = mk.current;
        mk.current = Rh;
        return null === a ? Rh : a;
      }
      function tj() {
        if (0 === T || 3 === T || 2 === T) T = 4;
        null === Q || 0 === (rh & 268435455) && 0 === (qk & 268435455) || Ck(Q, Z);
      }
      function Ik(a, b) {
        var c = K;
        K |= 2;
        var d = Jk();
        if (Q !== a || Z !== b) uk = null, Kk(a, b);
        do
          try {
            Tk();
            break;
          } catch (e) {
            Mk(a, e);
          }
        while (1);
        $g();
        K = c;
        mk.current = d;
        if (null !== Y) throw Error(p(261));
        Q = null;
        Z = 0;
        return T;
      }
      function Tk() {
        for (; null !== Y; ) Uk(Y);
      }
      function Lk() {
        for (; null !== Y && !cc(); ) Uk(Y);
      }
      function Uk(a) {
        var b = Vk(a.alternate, a, fj);
        a.memoizedProps = a.pendingProps;
        null === b ? Sk(a) : Y = b;
        nk.current = null;
      }
      function Sk(a) {
        var b = a;
        do {
          var c = b.alternate;
          a = b.return;
          if (0 === (b.flags & 32768)) {
            if (c = Ej(c, b, fj), null !== c) {
              Y = c;
              return;
            }
          } else {
            c = Ij(c, b);
            if (null !== c) {
              c.flags &= 32767;
              Y = c;
              return;
            }
            if (null !== a) a.flags |= 32768, a.subtreeFlags = 0, a.deletions = null;
            else {
              T = 6;
              Y = null;
              return;
            }
          }
          b = b.sibling;
          if (null !== b) {
            Y = b;
            return;
          }
          Y = b = a;
        } while (null !== b);
        0 === T && (T = 5);
      }
      function Pk(a, b, c) {
        var d = C, e = ok.transition;
        try {
          ok.transition = null, C = 1, Wk(a, b, c, d);
        } finally {
          ok.transition = e, C = d;
        }
        return null;
      }
      function Wk(a, b, c, d) {
        do
          Hk();
        while (null !== wk);
        if (0 !== (K & 6)) throw Error(p(327));
        c = a.finishedWork;
        var e = a.finishedLanes;
        if (null === c) return null;
        a.finishedWork = null;
        a.finishedLanes = 0;
        if (c === a.current) throw Error(p(177));
        a.callbackNode = null;
        a.callbackPriority = 0;
        var f = c.lanes | c.childLanes;
        Bc(a, f);
        a === Q && (Y = Q = null, Z = 0);
        0 === (c.subtreeFlags & 2064) && 0 === (c.flags & 2064) || vk || (vk = true, Fk(hc, function() {
          Hk();
          return null;
        }));
        f = 0 !== (c.flags & 15990);
        if (0 !== (c.subtreeFlags & 15990) || f) {
          f = ok.transition;
          ok.transition = null;
          var g = C;
          C = 1;
          var h = K;
          K |= 4;
          nk.current = null;
          Oj(a, c);
          dk(c, a);
          Oe(Df);
          dd = !!Cf;
          Df = Cf = null;
          a.current = c;
          hk(c, a, e);
          dc();
          K = h;
          C = g;
          ok.transition = f;
        } else a.current = c;
        vk && (vk = false, wk = a, xk = e);
        f = a.pendingLanes;
        0 === f && (Ri = null);
        mc(c.stateNode, d);
        Dk(a, B());
        if (null !== b) for (d = a.onRecoverableError, c = 0; c < b.length; c++) e = b[c], d(e.value, { componentStack: e.stack, digest: e.digest });
        if (Oi) throw Oi = false, a = Pi, Pi = null, a;
        0 !== (xk & 1) && 0 !== a.tag && Hk();
        f = a.pendingLanes;
        0 !== (f & 1) ? a === zk ? yk++ : (yk = 0, zk = a) : yk = 0;
        jg();
        return null;
      }
      function Hk() {
        if (null !== wk) {
          var a = Dc(xk), b = ok.transition, c = C;
          try {
            ok.transition = null;
            C = 16 > a ? 16 : a;
            if (null === wk) var d = false;
            else {
              a = wk;
              wk = null;
              xk = 0;
              if (0 !== (K & 6)) throw Error(p(331));
              var e = K;
              K |= 4;
              for (V = a.current; null !== V; ) {
                var f = V, g = f.child;
                if (0 !== (V.flags & 16)) {
                  var h = f.deletions;
                  if (null !== h) {
                    for (var k = 0; k < h.length; k++) {
                      var l = h[k];
                      for (V = l; null !== V; ) {
                        var m = V;
                        switch (m.tag) {
                          case 0:
                          case 11:
                          case 15:
                            Pj(8, m, f);
                        }
                        var q = m.child;
                        if (null !== q) q.return = m, V = q;
                        else for (; null !== V; ) {
                          m = V;
                          var r = m.sibling, y = m.return;
                          Sj(m);
                          if (m === l) {
                            V = null;
                            break;
                          }
                          if (null !== r) {
                            r.return = y;
                            V = r;
                            break;
                          }
                          V = y;
                        }
                      }
                    }
                    var n = f.alternate;
                    if (null !== n) {
                      var t = n.child;
                      if (null !== t) {
                        n.child = null;
                        do {
                          var J = t.sibling;
                          t.sibling = null;
                          t = J;
                        } while (null !== t);
                      }
                    }
                    V = f;
                  }
                }
                if (0 !== (f.subtreeFlags & 2064) && null !== g) g.return = f, V = g;
                else b: for (; null !== V; ) {
                  f = V;
                  if (0 !== (f.flags & 2048)) switch (f.tag) {
                    case 0:
                    case 11:
                    case 15:
                      Pj(9, f, f.return);
                  }
                  var x = f.sibling;
                  if (null !== x) {
                    x.return = f.return;
                    V = x;
                    break b;
                  }
                  V = f.return;
                }
              }
              var w = a.current;
              for (V = w; null !== V; ) {
                g = V;
                var u = g.child;
                if (0 !== (g.subtreeFlags & 2064) && null !== u) u.return = g, V = u;
                else b: for (g = w; null !== V; ) {
                  h = V;
                  if (0 !== (h.flags & 2048)) try {
                    switch (h.tag) {
                      case 0:
                      case 11:
                      case 15:
                        Qj(9, h);
                    }
                  } catch (na) {
                    W(h, h.return, na);
                  }
                  if (h === g) {
                    V = null;
                    break b;
                  }
                  var F = h.sibling;
                  if (null !== F) {
                    F.return = h.return;
                    V = F;
                    break b;
                  }
                  V = h.return;
                }
              }
              K = e;
              jg();
              if (lc && "function" === typeof lc.onPostCommitFiberRoot) try {
                lc.onPostCommitFiberRoot(kc, a);
              } catch (na) {
              }
              d = true;
            }
            return d;
          } finally {
            C = c, ok.transition = b;
          }
        }
        return false;
      }
      function Xk(a, b, c) {
        b = Ji(c, b);
        b = Ni(a, b, 1);
        a = nh(a, b, 1);
        b = R();
        null !== a && (Ac(a, 1, b), Dk(a, b));
      }
      function W(a, b, c) {
        if (3 === a.tag) Xk(a, a, c);
        else for (; null !== b; ) {
          if (3 === b.tag) {
            Xk(b, a, c);
            break;
          } else if (1 === b.tag) {
            var d = b.stateNode;
            if ("function" === typeof b.type.getDerivedStateFromError || "function" === typeof d.componentDidCatch && (null === Ri || !Ri.has(d))) {
              a = Ji(c, a);
              a = Qi(b, a, 1);
              b = nh(b, a, 1);
              a = R();
              null !== b && (Ac(b, 1, a), Dk(b, a));
              break;
            }
          }
          b = b.return;
        }
      }
      function Ti(a, b, c) {
        var d = a.pingCache;
        null !== d && d.delete(b);
        b = R();
        a.pingedLanes |= a.suspendedLanes & c;
        Q === a && (Z & c) === c && (4 === T || 3 === T && (Z & 130023424) === Z && 500 > B() - fk ? Kk(a, 0) : rk |= c);
        Dk(a, b);
      }
      function Yk(a, b) {
        0 === b && (0 === (a.mode & 1) ? b = 1 : (b = sc, sc <<= 1, 0 === (sc & 130023424) && (sc = 4194304)));
        var c = R();
        a = ih(a, b);
        null !== a && (Ac(a, b, c), Dk(a, c));
      }
      function uj(a) {
        var b = a.memoizedState, c = 0;
        null !== b && (c = b.retryLane);
        Yk(a, c);
      }
      function bk(a, b) {
        var c = 0;
        switch (a.tag) {
          case 13:
            var d = a.stateNode;
            var e = a.memoizedState;
            null !== e && (c = e.retryLane);
            break;
          case 19:
            d = a.stateNode;
            break;
          default:
            throw Error(p(314));
        }
        null !== d && d.delete(b);
        Yk(a, c);
      }
      var Vk;
      Vk = function(a, b, c) {
        if (null !== a) if (a.memoizedProps !== b.pendingProps || Wf.current) dh = true;
        else {
          if (0 === (a.lanes & c) && 0 === (b.flags & 128)) return dh = false, yj(a, b, c);
          dh = 0 !== (a.flags & 131072) ? true : false;
        }
        else dh = false, I && 0 !== (b.flags & 1048576) && ug(b, ng, b.index);
        b.lanes = 0;
        switch (b.tag) {
          case 2:
            var d = b.type;
            ij(a, b);
            a = b.pendingProps;
            var e = Yf(b, H.current);
            ch(b, c);
            e = Nh(null, b, d, a, e, c);
            var f = Sh();
            b.flags |= 1;
            "object" === typeof e && null !== e && "function" === typeof e.render && void 0 === e.$$typeof ? (b.tag = 1, b.memoizedState = null, b.updateQueue = null, Zf(d) ? (f = true, cg(b)) : f = false, b.memoizedState = null !== e.state && void 0 !== e.state ? e.state : null, kh(b), e.updater = Ei, b.stateNode = e, e._reactInternals = b, Ii(b, d, a, c), b = jj(null, b, d, true, f, c)) : (b.tag = 0, I && f && vg(b), Xi(null, b, e, c), b = b.child);
            return b;
          case 16:
            d = b.elementType;
            a: {
              ij(a, b);
              a = b.pendingProps;
              e = d._init;
              d = e(d._payload);
              b.type = d;
              e = b.tag = Zk(d);
              a = Ci(d, a);
              switch (e) {
                case 0:
                  b = cj(null, b, d, a, c);
                  break a;
                case 1:
                  b = hj(null, b, d, a, c);
                  break a;
                case 11:
                  b = Yi(null, b, d, a, c);
                  break a;
                case 14:
                  b = $i(null, b, d, Ci(d.type, a), c);
                  break a;
              }
              throw Error(p(
                306,
                d,
                ""
              ));
            }
            return b;
          case 0:
            return d = b.type, e = b.pendingProps, e = b.elementType === d ? e : Ci(d, e), cj(a, b, d, e, c);
          case 1:
            return d = b.type, e = b.pendingProps, e = b.elementType === d ? e : Ci(d, e), hj(a, b, d, e, c);
          case 3:
            a: {
              kj(b);
              if (null === a) throw Error(p(387));
              d = b.pendingProps;
              f = b.memoizedState;
              e = f.element;
              lh(a, b);
              qh(b, d, null, c);
              var g = b.memoizedState;
              d = g.element;
              if (f.isDehydrated) if (f = { element: d, isDehydrated: false, cache: g.cache, pendingSuspenseBoundaries: g.pendingSuspenseBoundaries, transitions: g.transitions }, b.updateQueue.baseState = f, b.memoizedState = f, b.flags & 256) {
                e = Ji(Error(p(423)), b);
                b = lj(a, b, d, c, e);
                break a;
              } else if (d !== e) {
                e = Ji(Error(p(424)), b);
                b = lj(a, b, d, c, e);
                break a;
              } else for (yg = Lf(b.stateNode.containerInfo.firstChild), xg = b, I = true, zg = null, c = Vg(b, null, d, c), b.child = c; c; ) c.flags = c.flags & -3 | 4096, c = c.sibling;
              else {
                Ig();
                if (d === e) {
                  b = Zi(a, b, c);
                  break a;
                }
                Xi(a, b, d, c);
              }
              b = b.child;
            }
            return b;
          case 5:
            return Ah(b), null === a && Eg(b), d = b.type, e = b.pendingProps, f = null !== a ? a.memoizedProps : null, g = e.children, Ef(d, e) ? g = null : null !== f && Ef(d, f) && (b.flags |= 32), gj(a, b), Xi(a, b, g, c), b.child;
          case 6:
            return null === a && Eg(b), null;
          case 13:
            return oj(a, b, c);
          case 4:
            return yh(b, b.stateNode.containerInfo), d = b.pendingProps, null === a ? b.child = Ug(b, null, d, c) : Xi(a, b, d, c), b.child;
          case 11:
            return d = b.type, e = b.pendingProps, e = b.elementType === d ? e : Ci(d, e), Yi(a, b, d, e, c);
          case 7:
            return Xi(a, b, b.pendingProps, c), b.child;
          case 8:
            return Xi(a, b, b.pendingProps.children, c), b.child;
          case 12:
            return Xi(a, b, b.pendingProps.children, c), b.child;
          case 10:
            a: {
              d = b.type._context;
              e = b.pendingProps;
              f = b.memoizedProps;
              g = e.value;
              G(Wg, d._currentValue);
              d._currentValue = g;
              if (null !== f) if (He(f.value, g)) {
                if (f.children === e.children && !Wf.current) {
                  b = Zi(a, b, c);
                  break a;
                }
              } else for (f = b.child, null !== f && (f.return = b); null !== f; ) {
                var h = f.dependencies;
                if (null !== h) {
                  g = f.child;
                  for (var k = h.firstContext; null !== k; ) {
                    if (k.context === d) {
                      if (1 === f.tag) {
                        k = mh(-1, c & -c);
                        k.tag = 2;
                        var l = f.updateQueue;
                        if (null !== l) {
                          l = l.shared;
                          var m = l.pending;
                          null === m ? k.next = k : (k.next = m.next, m.next = k);
                          l.pending = k;
                        }
                      }
                      f.lanes |= c;
                      k = f.alternate;
                      null !== k && (k.lanes |= c);
                      bh(
                        f.return,
                        c,
                        b
                      );
                      h.lanes |= c;
                      break;
                    }
                    k = k.next;
                  }
                } else if (10 === f.tag) g = f.type === b.type ? null : f.child;
                else if (18 === f.tag) {
                  g = f.return;
                  if (null === g) throw Error(p(341));
                  g.lanes |= c;
                  h = g.alternate;
                  null !== h && (h.lanes |= c);
                  bh(g, c, b);
                  g = f.sibling;
                } else g = f.child;
                if (null !== g) g.return = f;
                else for (g = f; null !== g; ) {
                  if (g === b) {
                    g = null;
                    break;
                  }
                  f = g.sibling;
                  if (null !== f) {
                    f.return = g.return;
                    g = f;
                    break;
                  }
                  g = g.return;
                }
                f = g;
              }
              Xi(a, b, e.children, c);
              b = b.child;
            }
            return b;
          case 9:
            return e = b.type, d = b.pendingProps.children, ch(b, c), e = eh(e), d = d(e), b.flags |= 1, Xi(a, b, d, c), b.child;
          case 14:
            return d = b.type, e = Ci(d, b.pendingProps), e = Ci(d.type, e), $i(a, b, d, e, c);
          case 15:
            return bj(a, b, b.type, b.pendingProps, c);
          case 17:
            return d = b.type, e = b.pendingProps, e = b.elementType === d ? e : Ci(d, e), ij(a, b), b.tag = 1, Zf(d) ? (a = true, cg(b)) : a = false, ch(b, c), Gi(b, d, e), Ii(b, d, e, c), jj(null, b, d, true, a, c);
          case 19:
            return xj(a, b, c);
          case 22:
            return dj(a, b, c);
        }
        throw Error(p(156, b.tag));
      };
      function Fk(a, b) {
        return ac(a, b);
      }
      function $k(a, b, c, d) {
        this.tag = a;
        this.key = c;
        this.sibling = this.child = this.return = this.stateNode = this.type = this.elementType = null;
        this.index = 0;
        this.ref = null;
        this.pendingProps = b;
        this.dependencies = this.memoizedState = this.updateQueue = this.memoizedProps = null;
        this.mode = d;
        this.subtreeFlags = this.flags = 0;
        this.deletions = null;
        this.childLanes = this.lanes = 0;
        this.alternate = null;
      }
      function Bg(a, b, c, d) {
        return new $k(a, b, c, d);
      }
      function aj(a) {
        a = a.prototype;
        return !(!a || !a.isReactComponent);
      }
      function Zk(a) {
        if ("function" === typeof a) return aj(a) ? 1 : 0;
        if (void 0 !== a && null !== a) {
          a = a.$$typeof;
          if (a === Da) return 11;
          if (a === Ga) return 14;
        }
        return 2;
      }
      function Pg(a, b) {
        var c = a.alternate;
        null === c ? (c = Bg(a.tag, b, a.key, a.mode), c.elementType = a.elementType, c.type = a.type, c.stateNode = a.stateNode, c.alternate = a, a.alternate = c) : (c.pendingProps = b, c.type = a.type, c.flags = 0, c.subtreeFlags = 0, c.deletions = null);
        c.flags = a.flags & 14680064;
        c.childLanes = a.childLanes;
        c.lanes = a.lanes;
        c.child = a.child;
        c.memoizedProps = a.memoizedProps;
        c.memoizedState = a.memoizedState;
        c.updateQueue = a.updateQueue;
        b = a.dependencies;
        c.dependencies = null === b ? null : { lanes: b.lanes, firstContext: b.firstContext };
        c.sibling = a.sibling;
        c.index = a.index;
        c.ref = a.ref;
        return c;
      }
      function Rg(a, b, c, d, e, f) {
        var g = 2;
        d = a;
        if ("function" === typeof a) aj(a) && (g = 1);
        else if ("string" === typeof a) g = 5;
        else a: switch (a) {
          case ya:
            return Tg(c.children, e, f, b);
          case za:
            g = 8;
            e |= 8;
            break;
          case Aa:
            return a = Bg(12, c, b, e | 2), a.elementType = Aa, a.lanes = f, a;
          case Ea:
            return a = Bg(13, c, b, e), a.elementType = Ea, a.lanes = f, a;
          case Fa:
            return a = Bg(19, c, b, e), a.elementType = Fa, a.lanes = f, a;
          case Ia:
            return pj(c, e, f, b);
          default:
            if ("object" === typeof a && null !== a) switch (a.$$typeof) {
              case Ba:
                g = 10;
                break a;
              case Ca:
                g = 9;
                break a;
              case Da:
                g = 11;
                break a;
              case Ga:
                g = 14;
                break a;
              case Ha:
                g = 16;
                d = null;
                break a;
            }
            throw Error(p(130, null == a ? a : typeof a, ""));
        }
        b = Bg(g, c, b, e);
        b.elementType = a;
        b.type = d;
        b.lanes = f;
        return b;
      }
      function Tg(a, b, c, d) {
        a = Bg(7, a, d, b);
        a.lanes = c;
        return a;
      }
      function pj(a, b, c, d) {
        a = Bg(22, a, d, b);
        a.elementType = Ia;
        a.lanes = c;
        a.stateNode = { isHidden: false };
        return a;
      }
      function Qg(a, b, c) {
        a = Bg(6, a, null, b);
        a.lanes = c;
        return a;
      }
      function Sg(a, b, c) {
        b = Bg(4, null !== a.children ? a.children : [], a.key, b);
        b.lanes = c;
        b.stateNode = { containerInfo: a.containerInfo, pendingChildren: null, implementation: a.implementation };
        return b;
      }
      function al(a, b, c, d, e) {
        this.tag = b;
        this.containerInfo = a;
        this.finishedWork = this.pingCache = this.current = this.pendingChildren = null;
        this.timeoutHandle = -1;
        this.callbackNode = this.pendingContext = this.context = null;
        this.callbackPriority = 0;
        this.eventTimes = zc(0);
        this.expirationTimes = zc(-1);
        this.entangledLanes = this.finishedLanes = this.mutableReadLanes = this.expiredLanes = this.pingedLanes = this.suspendedLanes = this.pendingLanes = 0;
        this.entanglements = zc(0);
        this.identifierPrefix = d;
        this.onRecoverableError = e;
        this.mutableSourceEagerHydrationData = null;
      }
      function bl(a, b, c, d, e, f, g, h, k) {
        a = new al(a, b, c, h, k);
        1 === b ? (b = 1, true === f && (b |= 8)) : b = 0;
        f = Bg(3, null, null, b);
        a.current = f;
        f.stateNode = a;
        f.memoizedState = { element: d, isDehydrated: c, cache: null, transitions: null, pendingSuspenseBoundaries: null };
        kh(f);
        return a;
      }
      function cl(a, b, c) {
        var d = 3 < arguments.length && void 0 !== arguments[3] ? arguments[3] : null;
        return { $$typeof: wa, key: null == d ? null : "" + d, children: a, containerInfo: b, implementation: c };
      }
      function dl(a) {
        if (!a) return Vf;
        a = a._reactInternals;
        a: {
          if (Vb(a) !== a || 1 !== a.tag) throw Error(p(170));
          var b = a;
          do {
            switch (b.tag) {
              case 3:
                b = b.stateNode.context;
                break a;
              case 1:
                if (Zf(b.type)) {
                  b = b.stateNode.__reactInternalMemoizedMergedChildContext;
                  break a;
                }
            }
            b = b.return;
          } while (null !== b);
          throw Error(p(171));
        }
        if (1 === a.tag) {
          var c = a.type;
          if (Zf(c)) return bg(a, c, b);
        }
        return b;
      }
      function el(a, b, c, d, e, f, g, h, k) {
        a = bl(c, d, true, a, e, f, g, h, k);
        a.context = dl(null);
        c = a.current;
        d = R();
        e = yi(c);
        f = mh(d, e);
        f.callback = void 0 !== b && null !== b ? b : null;
        nh(c, f, e);
        a.current.lanes = e;
        Ac(a, e, d);
        Dk(a, d);
        return a;
      }
      function fl(a, b, c, d) {
        var e = b.current, f = R(), g = yi(e);
        c = dl(c);
        null === b.context ? b.context = c : b.pendingContext = c;
        b = mh(f, g);
        b.payload = { element: a };
        d = void 0 === d ? null : d;
        null !== d && (b.callback = d);
        a = nh(e, b, g);
        null !== a && (gi(a, e, g, f), oh(a, e, g));
        return g;
      }
      function gl(a) {
        a = a.current;
        if (!a.child) return null;
        switch (a.child.tag) {
          case 5:
            return a.child.stateNode;
          default:
            return a.child.stateNode;
        }
      }
      function hl(a, b) {
        a = a.memoizedState;
        if (null !== a && null !== a.dehydrated) {
          var c = a.retryLane;
          a.retryLane = 0 !== c && c < b ? c : b;
        }
      }
      function il(a, b) {
        hl(a, b);
        (a = a.alternate) && hl(a, b);
      }
      function jl() {
        return null;
      }
      var kl = "function" === typeof reportError ? reportError : function(a) {
        console.error(a);
      };
      function ll(a) {
        this._internalRoot = a;
      }
      ml.prototype.render = ll.prototype.render = function(a) {
        var b = this._internalRoot;
        if (null === b) throw Error(p(409));
        fl(a, b, null, null);
      };
      ml.prototype.unmount = ll.prototype.unmount = function() {
        var a = this._internalRoot;
        if (null !== a) {
          this._internalRoot = null;
          var b = a.containerInfo;
          Rk(function() {
            fl(null, a, null, null);
          });
          b[uf] = null;
        }
      };
      function ml(a) {
        this._internalRoot = a;
      }
      ml.prototype.unstable_scheduleHydration = function(a) {
        if (a) {
          var b = Hc();
          a = { blockedOn: null, target: a, priority: b };
          for (var c = 0; c < Qc.length && 0 !== b && b < Qc[c].priority; c++) ;
          Qc.splice(c, 0, a);
          0 === c && Vc(a);
        }
      };
      function nl(a) {
        return !(!a || 1 !== a.nodeType && 9 !== a.nodeType && 11 !== a.nodeType);
      }
      function ol(a) {
        return !(!a || 1 !== a.nodeType && 9 !== a.nodeType && 11 !== a.nodeType && (8 !== a.nodeType || " react-mount-point-unstable " !== a.nodeValue));
      }
      function pl() {
      }
      function ql(a, b, c, d, e) {
        if (e) {
          if ("function" === typeof d) {
            var f = d;
            d = function() {
              var a2 = gl(g);
              f.call(a2);
            };
          }
          var g = el(b, d, a, 0, null, false, false, "", pl);
          a._reactRootContainer = g;
          a[uf] = g.current;
          sf(8 === a.nodeType ? a.parentNode : a);
          Rk();
          return g;
        }
        for (; e = a.lastChild; ) a.removeChild(e);
        if ("function" === typeof d) {
          var h = d;
          d = function() {
            var a2 = gl(k);
            h.call(a2);
          };
        }
        var k = bl(a, 0, false, null, null, false, false, "", pl);
        a._reactRootContainer = k;
        a[uf] = k.current;
        sf(8 === a.nodeType ? a.parentNode : a);
        Rk(function() {
          fl(b, k, c, d);
        });
        return k;
      }
      function rl(a, b, c, d, e) {
        var f = c._reactRootContainer;
        if (f) {
          var g = f;
          if ("function" === typeof e) {
            var h = e;
            e = function() {
              var a2 = gl(g);
              h.call(a2);
            };
          }
          fl(b, g, a, e);
        } else g = ql(c, b, a, e, d);
        return gl(g);
      }
      Ec = function(a) {
        switch (a.tag) {
          case 3:
            var b = a.stateNode;
            if (b.current.memoizedState.isDehydrated) {
              var c = tc(b.pendingLanes);
              0 !== c && (Cc(b, c | 1), Dk(b, B()), 0 === (K & 6) && (Gj = B() + 500, jg()));
            }
            break;
          case 13:
            Rk(function() {
              var b2 = ih(a, 1);
              if (null !== b2) {
                var c2 = R();
                gi(b2, a, 1, c2);
              }
            }), il(a, 1);
        }
      };
      Fc = function(a) {
        if (13 === a.tag) {
          var b = ih(a, 134217728);
          if (null !== b) {
            var c = R();
            gi(b, a, 134217728, c);
          }
          il(a, 134217728);
        }
      };
      Gc = function(a) {
        if (13 === a.tag) {
          var b = yi(a), c = ih(a, b);
          if (null !== c) {
            var d = R();
            gi(c, a, b, d);
          }
          il(a, b);
        }
      };
      Hc = function() {
        return C;
      };
      Ic = function(a, b) {
        var c = C;
        try {
          return C = a, b();
        } finally {
          C = c;
        }
      };
      yb = function(a, b, c) {
        switch (b) {
          case "input":
            bb(a, c);
            b = c.name;
            if ("radio" === c.type && null != b) {
              for (c = a; c.parentNode; ) c = c.parentNode;
              c = c.querySelectorAll("input[name=" + JSON.stringify("" + b) + '][type="radio"]');
              for (b = 0; b < c.length; b++) {
                var d = c[b];
                if (d !== a && d.form === a.form) {
                  var e = Db(d);
                  if (!e) throw Error(p(90));
                  Wa(d);
                  bb(d, e);
                }
              }
            }
            break;
          case "textarea":
            ib(a, c);
            break;
          case "select":
            b = c.value, null != b && fb(a, !!c.multiple, b, false);
        }
      };
      Gb = Qk;
      Hb = Rk;
      var sl = { usingClientEntryPoint: false, Events: [Cb, ue, Db, Eb, Fb, Qk] };
      var tl = { findFiberByHostInstance: Wc, bundleType: 0, version: "18.3.1", rendererPackageName: "react-dom" };
      var ul = { bundleType: tl.bundleType, version: tl.version, rendererPackageName: tl.rendererPackageName, rendererConfig: tl.rendererConfig, overrideHookState: null, overrideHookStateDeletePath: null, overrideHookStateRenamePath: null, overrideProps: null, overridePropsDeletePath: null, overridePropsRenamePath: null, setErrorHandler: null, setSuspenseHandler: null, scheduleUpdate: null, currentDispatcherRef: ua.ReactCurrentDispatcher, findHostInstanceByFiber: function(a) {
        a = Zb(a);
        return null === a ? null : a.stateNode;
      }, findFiberByHostInstance: tl.findFiberByHostInstance || jl, findHostInstancesForRefresh: null, scheduleRefresh: null, scheduleRoot: null, setRefreshHandler: null, getCurrentFiber: null, reconcilerVersion: "18.3.1-next-f1338f8080-20240426" };
      if ("undefined" !== typeof __REACT_DEVTOOLS_GLOBAL_HOOK__) {
        vl = __REACT_DEVTOOLS_GLOBAL_HOOK__;
        if (!vl.isDisabled && vl.supportsFiber) try {
          kc = vl.inject(ul), lc = vl;
        } catch (a) {
        }
      }
      var vl;
      exports.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED = sl;
      exports.createPortal = function(a, b) {
        var c = 2 < arguments.length && void 0 !== arguments[2] ? arguments[2] : null;
        if (!nl(b)) throw Error(p(200));
        return cl(a, b, null, c);
      };
      exports.createRoot = function(a, b) {
        if (!nl(a)) throw Error(p(299));
        var c = false, d = "", e = kl;
        null !== b && void 0 !== b && (true === b.unstable_strictMode && (c = true), void 0 !== b.identifierPrefix && (d = b.identifierPrefix), void 0 !== b.onRecoverableError && (e = b.onRecoverableError));
        b = bl(a, 1, false, null, null, c, false, d, e);
        a[uf] = b.current;
        sf(8 === a.nodeType ? a.parentNode : a);
        return new ll(b);
      };
      exports.findDOMNode = function(a) {
        if (null == a) return null;
        if (1 === a.nodeType) return a;
        var b = a._reactInternals;
        if (void 0 === b) {
          if ("function" === typeof a.render) throw Error(p(188));
          a = Object.keys(a).join(",");
          throw Error(p(268, a));
        }
        a = Zb(b);
        a = null === a ? null : a.stateNode;
        return a;
      };
      exports.flushSync = function(a) {
        return Rk(a);
      };
      exports.hydrate = function(a, b, c) {
        if (!ol(b)) throw Error(p(200));
        return rl(null, a, b, true, c);
      };
      exports.hydrateRoot = function(a, b, c) {
        if (!nl(a)) throw Error(p(405));
        var d = null != c && c.hydratedSources || null, e = false, f = "", g = kl;
        null !== c && void 0 !== c && (true === c.unstable_strictMode && (e = true), void 0 !== c.identifierPrefix && (f = c.identifierPrefix), void 0 !== c.onRecoverableError && (g = c.onRecoverableError));
        b = el(b, null, a, 1, null != c ? c : null, e, false, f, g);
        a[uf] = b.current;
        sf(a);
        if (d) for (a = 0; a < d.length; a++) c = d[a], e = c._getVersion, e = e(c._source), null == b.mutableSourceEagerHydrationData ? b.mutableSourceEagerHydrationData = [c, e] : b.mutableSourceEagerHydrationData.push(
          c,
          e
        );
        return new ml(b);
      };
      exports.render = function(a, b, c) {
        if (!ol(b)) throw Error(p(200));
        return rl(null, a, b, false, c);
      };
      exports.unmountComponentAtNode = function(a) {
        if (!ol(a)) throw Error(p(40));
        return a._reactRootContainer ? (Rk(function() {
          rl(null, null, a, false, function() {
            a._reactRootContainer = null;
            a[uf] = null;
          });
        }), true) : false;
      };
      exports.unstable_batchedUpdates = Qk;
      exports.unstable_renderSubtreeIntoContainer = function(a, b, c, d) {
        if (!ol(c)) throw Error(p(200));
        if (null == a || void 0 === a._reactInternals) throw Error(p(38));
        return rl(a, b, c, false, d);
      };
      exports.version = "18.3.1-next-f1338f8080-20240426";
    }
  });

  // node_modules/react-dom/index.js
  var require_react_dom = __commonJS({
    "node_modules/react-dom/index.js"(exports, module) {
      "use strict";
      function checkDCE() {
        if (typeof __REACT_DEVTOOLS_GLOBAL_HOOK__ === "undefined" || typeof __REACT_DEVTOOLS_GLOBAL_HOOK__.checkDCE !== "function") {
          return;
        }
        if (false) {
          throw new Error("^_^");
        }
        try {
          __REACT_DEVTOOLS_GLOBAL_HOOK__.checkDCE(checkDCE);
        } catch (err) {
          console.error(err);
        }
      }
      if (true) {
        checkDCE();
        module.exports = require_react_dom_production_min();
      } else {
        module.exports = null;
      }
    }
  });

  // node_modules/react-dom/client.js
  var require_client = __commonJS({
    "node_modules/react-dom/client.js"(exports) {
      "use strict";
      var m = require_react_dom();
      if (true) {
        exports.createRoot = m.createRoot;
        exports.hydrateRoot = m.hydrateRoot;
      } else {
        i = m.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED;
        exports.createRoot = function(c, o) {
          i.usingClientEntryPoint = true;
          try {
            return m.createRoot(c, o);
          } finally {
            i.usingClientEntryPoint = false;
          }
        };
        exports.hydrateRoot = function(c, h, o) {
          i.usingClientEntryPoint = true;
          try {
            return m.hydrateRoot(c, h, o);
          } finally {
            i.usingClientEntryPoint = false;
          }
        };
      }
      var i;
    }
  });

  // node_modules/react/cjs/react-jsx-runtime.production.min.js
  var require_react_jsx_runtime_production_min = __commonJS({
    "node_modules/react/cjs/react-jsx-runtime.production.min.js"(exports) {
      "use strict";
      var f = require_react();
      var k = Symbol.for("react.element");
      var l = Symbol.for("react.fragment");
      var m = Object.prototype.hasOwnProperty;
      var n = f.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED.ReactCurrentOwner;
      var p = { key: true, ref: true, __self: true, __source: true };
      function q(c, a, g) {
        var b, d = {}, e = null, h = null;
        void 0 !== g && (e = "" + g);
        void 0 !== a.key && (e = "" + a.key);
        void 0 !== a.ref && (h = a.ref);
        for (b in a) m.call(a, b) && !p.hasOwnProperty(b) && (d[b] = a[b]);
        if (c && c.defaultProps) for (b in a = c.defaultProps, a) void 0 === d[b] && (d[b] = a[b]);
        return { $$typeof: k, type: c, key: e, ref: h, props: d, _owner: n.current };
      }
      exports.Fragment = l;
      exports.jsx = q;
      exports.jsxs = q;
    }
  });

  // node_modules/react/jsx-runtime.js
  var require_jsx_runtime = __commonJS({
    "node_modules/react/jsx-runtime.js"(exports, module) {
      "use strict";
      if (true) {
        module.exports = require_react_jsx_runtime_production_min();
      } else {
        module.exports = null;
      }
    }
  });

  // views/react/app.jsx
  var import_react44 = __toESM(require_react());
  var import_client32 = __toESM(require_client());

  // node_modules/react-router-dom/dist/index.js
  var React2 = __toESM(require_react());
  var ReactDOM = __toESM(require_react_dom());

  // node_modules/react-router/dist/index.js
  var React = __toESM(require_react());

  // node_modules/@remix-run/router/dist/router.js
  function _extends() {
    _extends = Object.assign ? Object.assign.bind() : function(target) {
      for (var i = 1; i < arguments.length; i++) {
        var source = arguments[i];
        for (var key in source) {
          if (Object.prototype.hasOwnProperty.call(source, key)) {
            target[key] = source[key];
          }
        }
      }
      return target;
    };
    return _extends.apply(this, arguments);
  }
  var Action;
  (function(Action2) {
    Action2["Pop"] = "POP";
    Action2["Push"] = "PUSH";
    Action2["Replace"] = "REPLACE";
  })(Action || (Action = {}));
  var PopStateEventType = "popstate";
  function createBrowserHistory(options) {
    if (options === void 0) {
      options = {};
    }
    function createBrowserLocation(window2, globalHistory) {
      let {
        pathname,
        search,
        hash
      } = window2.location;
      return createLocation(
        "",
        {
          pathname,
          search,
          hash
        },
        // state defaults to `null` because `window.history.state` does
        globalHistory.state && globalHistory.state.usr || null,
        globalHistory.state && globalHistory.state.key || "default"
      );
    }
    function createBrowserHref(window2, to) {
      return typeof to === "string" ? to : createPath(to);
    }
    return getUrlBasedHistory(createBrowserLocation, createBrowserHref, null, options);
  }
  function invariant(value, message) {
    if (value === false || value === null || typeof value === "undefined") {
      throw new Error(message);
    }
  }
  function warning(cond, message) {
    if (!cond) {
      if (typeof console !== "undefined") console.warn(message);
      try {
        throw new Error(message);
      } catch (e) {
      }
    }
  }
  function createKey() {
    return Math.random().toString(36).substr(2, 8);
  }
  function getHistoryState(location, index) {
    return {
      usr: location.state,
      key: location.key,
      idx: index
    };
  }
  function createLocation(current, to, state, key) {
    if (state === void 0) {
      state = null;
    }
    let location = _extends({
      pathname: typeof current === "string" ? current : current.pathname,
      search: "",
      hash: ""
    }, typeof to === "string" ? parsePath(to) : to, {
      state,
      // TODO: This could be cleaned up.  push/replace should probably just take
      // full Locations now and avoid the need to run through this flow at all
      // But that's a pretty big refactor to the current test suite so going to
      // keep as is for the time being and just let any incoming keys take precedence
      key: to && to.key || key || createKey()
    });
    return location;
  }
  function createPath(_ref) {
    let {
      pathname = "/",
      search = "",
      hash = ""
    } = _ref;
    if (search && search !== "?") pathname += search.charAt(0) === "?" ? search : "?" + search;
    if (hash && hash !== "#") pathname += hash.charAt(0) === "#" ? hash : "#" + hash;
    return pathname;
  }
  function parsePath(path) {
    let parsedPath = {};
    if (path) {
      let hashIndex = path.indexOf("#");
      if (hashIndex >= 0) {
        parsedPath.hash = path.substr(hashIndex);
        path = path.substr(0, hashIndex);
      }
      let searchIndex = path.indexOf("?");
      if (searchIndex >= 0) {
        parsedPath.search = path.substr(searchIndex);
        path = path.substr(0, searchIndex);
      }
      if (path) {
        parsedPath.pathname = path;
      }
    }
    return parsedPath;
  }
  function getUrlBasedHistory(getLocation, createHref, validateLocation, options) {
    if (options === void 0) {
      options = {};
    }
    let {
      window: window2 = document.defaultView,
      v5Compat = false
    } = options;
    let globalHistory = window2.history;
    let action = Action.Pop;
    let listener = null;
    let index = getIndex();
    if (index == null) {
      index = 0;
      globalHistory.replaceState(_extends({}, globalHistory.state, {
        idx: index
      }), "");
    }
    function getIndex() {
      let state = globalHistory.state || {
        idx: null
      };
      return state.idx;
    }
    function handlePop() {
      action = Action.Pop;
      let nextIndex = getIndex();
      let delta = nextIndex == null ? null : nextIndex - index;
      index = nextIndex;
      if (listener) {
        listener({
          action,
          location: history.location,
          delta
        });
      }
    }
    function push(to, state) {
      action = Action.Push;
      let location = createLocation(history.location, to, state);
      if (validateLocation) validateLocation(location, to);
      index = getIndex() + 1;
      let historyState = getHistoryState(location, index);
      let url = history.createHref(location);
      try {
        globalHistory.pushState(historyState, "", url);
      } catch (error) {
        if (error instanceof DOMException && error.name === "DataCloneError") {
          throw error;
        }
        window2.location.assign(url);
      }
      if (v5Compat && listener) {
        listener({
          action,
          location: history.location,
          delta: 1
        });
      }
    }
    function replace2(to, state) {
      action = Action.Replace;
      let location = createLocation(history.location, to, state);
      if (validateLocation) validateLocation(location, to);
      index = getIndex();
      let historyState = getHistoryState(location, index);
      let url = history.createHref(location);
      globalHistory.replaceState(historyState, "", url);
      if (v5Compat && listener) {
        listener({
          action,
          location: history.location,
          delta: 0
        });
      }
    }
    function createURL(to) {
      let base = window2.location.origin !== "null" ? window2.location.origin : window2.location.href;
      let href = typeof to === "string" ? to : createPath(to);
      href = href.replace(/ $/, "%20");
      invariant(base, "No window.location.(origin|href) available to create URL for href: " + href);
      return new URL(href, base);
    }
    let history = {
      get action() {
        return action;
      },
      get location() {
        return getLocation(window2, globalHistory);
      },
      listen(fn) {
        if (listener) {
          throw new Error("A history only accepts one active listener");
        }
        window2.addEventListener(PopStateEventType, handlePop);
        listener = fn;
        return () => {
          window2.removeEventListener(PopStateEventType, handlePop);
          listener = null;
        };
      },
      createHref(to) {
        return createHref(window2, to);
      },
      createURL,
      encodeLocation(to) {
        let url = createURL(to);
        return {
          pathname: url.pathname,
          search: url.search,
          hash: url.hash
        };
      },
      push,
      replace: replace2,
      go(n) {
        return globalHistory.go(n);
      }
    };
    return history;
  }
  var ResultType;
  (function(ResultType2) {
    ResultType2["data"] = "data";
    ResultType2["deferred"] = "deferred";
    ResultType2["redirect"] = "redirect";
    ResultType2["error"] = "error";
  })(ResultType || (ResultType = {}));
  function matchRoutes(routes, locationArg, basename) {
    if (basename === void 0) {
      basename = "/";
    }
    return matchRoutesImpl(routes, locationArg, basename, false);
  }
  function matchRoutesImpl(routes, locationArg, basename, allowPartial) {
    let location = typeof locationArg === "string" ? parsePath(locationArg) : locationArg;
    let pathname = stripBasename(location.pathname || "/", basename);
    if (pathname == null) {
      return null;
    }
    let branches = flattenRoutes(routes);
    rankRouteBranches(branches);
    let matches = null;
    for (let i = 0; matches == null && i < branches.length; ++i) {
      let decoded = decodePath(pathname);
      matches = matchRouteBranch(branches[i], decoded, allowPartial);
    }
    return matches;
  }
  function flattenRoutes(routes, branches, parentsMeta, parentPath) {
    if (branches === void 0) {
      branches = [];
    }
    if (parentsMeta === void 0) {
      parentsMeta = [];
    }
    if (parentPath === void 0) {
      parentPath = "";
    }
    let flattenRoute = (route, index, relativePath) => {
      let meta = {
        relativePath: relativePath === void 0 ? route.path || "" : relativePath,
        caseSensitive: route.caseSensitive === true,
        childrenIndex: index,
        route
      };
      if (meta.relativePath.startsWith("/")) {
        invariant(meta.relativePath.startsWith(parentPath), 'Absolute route path "' + meta.relativePath + '" nested under path ' + ('"' + parentPath + '" is not valid. An absolute child route path ') + "must start with the combined path of all its parent routes.");
        meta.relativePath = meta.relativePath.slice(parentPath.length);
      }
      let path = joinPaths([parentPath, meta.relativePath]);
      let routesMeta = parentsMeta.concat(meta);
      if (route.children && route.children.length > 0) {
        invariant(
          // Our types know better, but runtime JS may not!
          // @ts-expect-error
          route.index !== true,
          "Index routes must not have child routes. Please remove " + ('all child routes from route path "' + path + '".')
        );
        flattenRoutes(route.children, branches, routesMeta, path);
      }
      if (route.path == null && !route.index) {
        return;
      }
      branches.push({
        path,
        score: computeScore(path, route.index),
        routesMeta
      });
    };
    routes.forEach((route, index) => {
      var _route$path;
      if (route.path === "" || !((_route$path = route.path) != null && _route$path.includes("?"))) {
        flattenRoute(route, index);
      } else {
        for (let exploded of explodeOptionalSegments(route.path)) {
          flattenRoute(route, index, exploded);
        }
      }
    });
    return branches;
  }
  function explodeOptionalSegments(path) {
    let segments = path.split("/");
    if (segments.length === 0) return [];
    let [first, ...rest] = segments;
    let isOptional = first.endsWith("?");
    let required = first.replace(/\?$/, "");
    if (rest.length === 0) {
      return isOptional ? [required, ""] : [required];
    }
    let restExploded = explodeOptionalSegments(rest.join("/"));
    let result = [];
    result.push(...restExploded.map((subpath) => subpath === "" ? required : [required, subpath].join("/")));
    if (isOptional) {
      result.push(...restExploded);
    }
    return result.map((exploded) => path.startsWith("/") && exploded === "" ? "/" : exploded);
  }
  function rankRouteBranches(branches) {
    branches.sort((a, b) => a.score !== b.score ? b.score - a.score : compareIndexes(a.routesMeta.map((meta) => meta.childrenIndex), b.routesMeta.map((meta) => meta.childrenIndex)));
  }
  var paramRe = /^:[\w-]+$/;
  var dynamicSegmentValue = 3;
  var indexRouteValue = 2;
  var emptySegmentValue = 1;
  var staticSegmentValue = 10;
  var splatPenalty = -2;
  var isSplat = (s) => s === "*";
  function computeScore(path, index) {
    let segments = path.split("/");
    let initialScore = segments.length;
    if (segments.some(isSplat)) {
      initialScore += splatPenalty;
    }
    if (index) {
      initialScore += indexRouteValue;
    }
    return segments.filter((s) => !isSplat(s)).reduce((score, segment) => score + (paramRe.test(segment) ? dynamicSegmentValue : segment === "" ? emptySegmentValue : staticSegmentValue), initialScore);
  }
  function compareIndexes(a, b) {
    let siblings = a.length === b.length && a.slice(0, -1).every((n, i) => n === b[i]);
    return siblings ? (
      // If two routes are siblings, we should try to match the earlier sibling
      // first. This allows people to have fine-grained control over the matching
      // behavior by simply putting routes with identical paths in the order they
      // want them tried.
      a[a.length - 1] - b[b.length - 1]
    ) : (
      // Otherwise, it doesn't really make sense to rank non-siblings by index,
      // so they sort equally.
      0
    );
  }
  function matchRouteBranch(branch, pathname, allowPartial) {
    if (allowPartial === void 0) {
      allowPartial = false;
    }
    let {
      routesMeta
    } = branch;
    let matchedParams = {};
    let matchedPathname = "/";
    let matches = [];
    for (let i = 0; i < routesMeta.length; ++i) {
      let meta = routesMeta[i];
      let end = i === routesMeta.length - 1;
      let remainingPathname = matchedPathname === "/" ? pathname : pathname.slice(matchedPathname.length) || "/";
      let match = matchPath({
        path: meta.relativePath,
        caseSensitive: meta.caseSensitive,
        end
      }, remainingPathname);
      let route = meta.route;
      if (!match && end && allowPartial && !routesMeta[routesMeta.length - 1].route.index) {
        match = matchPath({
          path: meta.relativePath,
          caseSensitive: meta.caseSensitive,
          end: false
        }, remainingPathname);
      }
      if (!match) {
        return null;
      }
      Object.assign(matchedParams, match.params);
      matches.push({
        // TODO: Can this as be avoided?
        params: matchedParams,
        pathname: joinPaths([matchedPathname, match.pathname]),
        pathnameBase: normalizePathname(joinPaths([matchedPathname, match.pathnameBase])),
        route
      });
      if (match.pathnameBase !== "/") {
        matchedPathname = joinPaths([matchedPathname, match.pathnameBase]);
      }
    }
    return matches;
  }
  function matchPath(pattern, pathname) {
    if (typeof pattern === "string") {
      pattern = {
        path: pattern,
        caseSensitive: false,
        end: true
      };
    }
    let [matcher, compiledParams] = compilePath(pattern.path, pattern.caseSensitive, pattern.end);
    let match = pathname.match(matcher);
    if (!match) return null;
    let matchedPathname = match[0];
    let pathnameBase = matchedPathname.replace(/(.)\/+$/, "$1");
    let captureGroups = match.slice(1);
    let params = compiledParams.reduce((memo2, _ref, index) => {
      let {
        paramName,
        isOptional
      } = _ref;
      if (paramName === "*") {
        let splatValue = captureGroups[index] || "";
        pathnameBase = matchedPathname.slice(0, matchedPathname.length - splatValue.length).replace(/(.)\/+$/, "$1");
      }
      const value = captureGroups[index];
      if (isOptional && !value) {
        memo2[paramName] = void 0;
      } else {
        memo2[paramName] = (value || "").replace(/%2F/g, "/");
      }
      return memo2;
    }, {});
    return {
      params,
      pathname: matchedPathname,
      pathnameBase,
      pattern
    };
  }
  function compilePath(path, caseSensitive, end) {
    if (caseSensitive === void 0) {
      caseSensitive = false;
    }
    if (end === void 0) {
      end = true;
    }
    warning(path === "*" || !path.endsWith("*") || path.endsWith("/*"), 'Route path "' + path + '" will be treated as if it were ' + ('"' + path.replace(/\*$/, "/*") + '" because the `*` character must ') + "always follow a `/` in the pattern. To get rid of this warning, " + ('please change the route path to "' + path.replace(/\*$/, "/*") + '".'));
    let params = [];
    let regexpSource = "^" + path.replace(/\/*\*?$/, "").replace(/^\/*/, "/").replace(/[\\.*+^${}|()[\]]/g, "\\$&").replace(/\/:([\w-]+)(\?)?/g, (_, paramName, isOptional) => {
      params.push({
        paramName,
        isOptional: isOptional != null
      });
      return isOptional ? "/?([^\\/]+)?" : "/([^\\/]+)";
    });
    if (path.endsWith("*")) {
      params.push({
        paramName: "*"
      });
      regexpSource += path === "*" || path === "/*" ? "(.*)$" : "(?:\\/(.+)|\\/*)$";
    } else if (end) {
      regexpSource += "\\/*$";
    } else if (path !== "" && path !== "/") {
      regexpSource += "(?:(?=\\/|$))";
    } else ;
    let matcher = new RegExp(regexpSource, caseSensitive ? void 0 : "i");
    return [matcher, params];
  }
  function decodePath(value) {
    try {
      return value.split("/").map((v) => decodeURIComponent(v).replace(/\//g, "%2F")).join("/");
    } catch (error) {
      warning(false, 'The URL path "' + value + '" could not be decoded because it is is a malformed URL segment. This is probably due to a bad percent ' + ("encoding (" + error + ")."));
      return value;
    }
  }
  function stripBasename(pathname, basename) {
    if (basename === "/") return pathname;
    if (!pathname.toLowerCase().startsWith(basename.toLowerCase())) {
      return null;
    }
    let startIndex = basename.endsWith("/") ? basename.length - 1 : basename.length;
    let nextChar = pathname.charAt(startIndex);
    if (nextChar && nextChar !== "/") {
      return null;
    }
    return pathname.slice(startIndex) || "/";
  }
  var ABSOLUTE_URL_REGEX$1 = /^(?:[a-z][a-z0-9+.-]*:|\/\/)/i;
  var isAbsoluteUrl = (url) => ABSOLUTE_URL_REGEX$1.test(url);
  function resolvePath(to, fromPathname) {
    if (fromPathname === void 0) {
      fromPathname = "/";
    }
    let {
      pathname: toPathname,
      search = "",
      hash = ""
    } = typeof to === "string" ? parsePath(to) : to;
    let pathname;
    if (toPathname) {
      if (isAbsoluteUrl(toPathname)) {
        pathname = toPathname;
      } else {
        if (toPathname.includes("//")) {
          let oldPathname = toPathname;
          toPathname = toPathname.replace(/\/\/+/g, "/");
          warning(false, "Pathnames cannot have embedded double slashes - normalizing " + (oldPathname + " -> " + toPathname));
        }
        if (toPathname.startsWith("/")) {
          pathname = resolvePathname(toPathname.substring(1), "/");
        } else {
          pathname = resolvePathname(toPathname, fromPathname);
        }
      }
    } else {
      pathname = fromPathname;
    }
    return {
      pathname,
      search: normalizeSearch(search),
      hash: normalizeHash(hash)
    };
  }
  function resolvePathname(relativePath, fromPathname) {
    let segments = fromPathname.replace(/\/+$/, "").split("/");
    let relativeSegments = relativePath.split("/");
    relativeSegments.forEach((segment) => {
      if (segment === "..") {
        if (segments.length > 1) segments.pop();
      } else if (segment !== ".") {
        segments.push(segment);
      }
    });
    return segments.length > 1 ? segments.join("/") : "/";
  }
  function getInvalidPathError(char, field, dest, path) {
    return "Cannot include a '" + char + "' character in a manually specified " + ("`to." + field + "` field [" + JSON.stringify(path) + "].  Please separate it out to the ") + ("`to." + dest + "` field. Alternatively you may provide the full path as ") + 'a string in <Link to="..."> and the router will parse it for you.';
  }
  function getPathContributingMatches(matches) {
    return matches.filter((match, index) => index === 0 || match.route.path && match.route.path.length > 0);
  }
  function getResolveToMatches(matches, v7_relativeSplatPath) {
    let pathMatches = getPathContributingMatches(matches);
    if (v7_relativeSplatPath) {
      return pathMatches.map((match, idx) => idx === pathMatches.length - 1 ? match.pathname : match.pathnameBase);
    }
    return pathMatches.map((match) => match.pathnameBase);
  }
  function resolveTo(toArg, routePathnames, locationPathname, isPathRelative) {
    if (isPathRelative === void 0) {
      isPathRelative = false;
    }
    let to;
    if (typeof toArg === "string") {
      to = parsePath(toArg);
    } else {
      to = _extends({}, toArg);
      invariant(!to.pathname || !to.pathname.includes("?"), getInvalidPathError("?", "pathname", "search", to));
      invariant(!to.pathname || !to.pathname.includes("#"), getInvalidPathError("#", "pathname", "hash", to));
      invariant(!to.search || !to.search.includes("#"), getInvalidPathError("#", "search", "hash", to));
    }
    let isEmptyPath = toArg === "" || to.pathname === "";
    let toPathname = isEmptyPath ? "/" : to.pathname;
    let from;
    if (toPathname == null) {
      from = locationPathname;
    } else {
      let routePathnameIndex = routePathnames.length - 1;
      if (!isPathRelative && toPathname.startsWith("..")) {
        let toSegments = toPathname.split("/");
        while (toSegments[0] === "..") {
          toSegments.shift();
          routePathnameIndex -= 1;
        }
        to.pathname = toSegments.join("/");
      }
      from = routePathnameIndex >= 0 ? routePathnames[routePathnameIndex] : "/";
    }
    let path = resolvePath(to, from);
    let hasExplicitTrailingSlash = toPathname && toPathname !== "/" && toPathname.endsWith("/");
    let hasCurrentTrailingSlash = (isEmptyPath || toPathname === ".") && locationPathname.endsWith("/");
    if (!path.pathname.endsWith("/") && (hasExplicitTrailingSlash || hasCurrentTrailingSlash)) {
      path.pathname += "/";
    }
    return path;
  }
  var joinPaths = (paths) => paths.join("/").replace(/\/\/+/g, "/");
  var normalizePathname = (pathname) => pathname.replace(/\/+$/, "").replace(/^\/*/, "/");
  var normalizeSearch = (search) => !search || search === "?" ? "" : search.startsWith("?") ? search : "?" + search;
  var normalizeHash = (hash) => !hash || hash === "#" ? "" : hash.startsWith("#") ? hash : "#" + hash;
  function isRouteErrorResponse(error) {
    return error != null && typeof error.status === "number" && typeof error.statusText === "string" && typeof error.internal === "boolean" && "data" in error;
  }
  var validMutationMethodsArr = ["post", "put", "patch", "delete"];
  var validMutationMethods = new Set(validMutationMethodsArr);
  var validRequestMethodsArr = ["get", ...validMutationMethodsArr];
  var validRequestMethods = new Set(validRequestMethodsArr);
  var UNSAFE_DEFERRED_SYMBOL = Symbol("deferred");

  // node_modules/react-router/dist/index.js
  function _extends2() {
    _extends2 = Object.assign ? Object.assign.bind() : function(target) {
      for (var i = 1; i < arguments.length; i++) {
        var source = arguments[i];
        for (var key in source) {
          if (Object.prototype.hasOwnProperty.call(source, key)) {
            target[key] = source[key];
          }
        }
      }
      return target;
    };
    return _extends2.apply(this, arguments);
  }
  var DataRouterContext = /* @__PURE__ */ React.createContext(null);
  if (false) {
    DataRouterContext.displayName = "DataRouter";
  }
  var DataRouterStateContext = /* @__PURE__ */ React.createContext(null);
  if (false) {
    DataRouterStateContext.displayName = "DataRouterState";
  }
  if (false) {
    AwaitContext.displayName = "Await";
  }
  var NavigationContext = /* @__PURE__ */ React.createContext(null);
  if (false) {
    NavigationContext.displayName = "Navigation";
  }
  var LocationContext = /* @__PURE__ */ React.createContext(null);
  if (false) {
    LocationContext.displayName = "Location";
  }
  var RouteContext = /* @__PURE__ */ React.createContext({
    outlet: null,
    matches: [],
    isDataRoute: false
  });
  if (false) {
    RouteContext.displayName = "Route";
  }
  var RouteErrorContext = /* @__PURE__ */ React.createContext(null);
  if (false) {
    RouteErrorContext.displayName = "RouteError";
  }
  function useHref(to, _temp) {
    let {
      relative
    } = _temp === void 0 ? {} : _temp;
    !useInRouterContext() ? false ? invariant(
      false,
      // TODO: This error is probably because they somehow have 2 versions of the
      // router loaded. We can help them understand how to avoid that.
      "useHref() may be used only in the context of a <Router> component."
    ) : invariant(false) : void 0;
    let {
      basename,
      navigator: navigator2
    } = React.useContext(NavigationContext);
    let {
      hash,
      pathname,
      search
    } = useResolvedPath(to, {
      relative
    });
    let joinedPathname = pathname;
    if (basename !== "/") {
      joinedPathname = pathname === "/" ? basename : joinPaths([basename, pathname]);
    }
    return navigator2.createHref({
      pathname: joinedPathname,
      search,
      hash
    });
  }
  function useInRouterContext() {
    return React.useContext(LocationContext) != null;
  }
  function useLocation() {
    !useInRouterContext() ? false ? invariant(
      false,
      // TODO: This error is probably because they somehow have 2 versions of the
      // router loaded. We can help them understand how to avoid that.
      "useLocation() may be used only in the context of a <Router> component."
    ) : invariant(false) : void 0;
    return React.useContext(LocationContext).location;
  }
  function useIsomorphicLayoutEffect(cb) {
    let isStatic = React.useContext(NavigationContext).static;
    if (!isStatic) {
      React.useLayoutEffect(cb);
    }
  }
  function useNavigate() {
    let {
      isDataRoute
    } = React.useContext(RouteContext);
    return isDataRoute ? useNavigateStable() : useNavigateUnstable();
  }
  function useNavigateUnstable() {
    !useInRouterContext() ? false ? invariant(
      false,
      // TODO: This error is probably because they somehow have 2 versions of the
      // router loaded. We can help them understand how to avoid that.
      "useNavigate() may be used only in the context of a <Router> component."
    ) : invariant(false) : void 0;
    let dataRouterContext = React.useContext(DataRouterContext);
    let {
      basename,
      future,
      navigator: navigator2
    } = React.useContext(NavigationContext);
    let {
      matches
    } = React.useContext(RouteContext);
    let {
      pathname: locationPathname
    } = useLocation();
    let routePathnamesJson = JSON.stringify(getResolveToMatches(matches, future.v7_relativeSplatPath));
    let activeRef = React.useRef(false);
    useIsomorphicLayoutEffect(() => {
      activeRef.current = true;
    });
    let navigate = React.useCallback(function(to, options) {
      if (options === void 0) {
        options = {};
      }
      false ? warning(activeRef.current, navigateEffectWarning) : void 0;
      if (!activeRef.current) return;
      if (typeof to === "number") {
        navigator2.go(to);
        return;
      }
      let path = resolveTo(to, JSON.parse(routePathnamesJson), locationPathname, options.relative === "path");
      if (dataRouterContext == null && basename !== "/") {
        path.pathname = path.pathname === "/" ? basename : joinPaths([basename, path.pathname]);
      }
      (!!options.replace ? navigator2.replace : navigator2.push)(path, options.state, options);
    }, [basename, navigator2, routePathnamesJson, locationPathname, dataRouterContext]);
    return navigate;
  }
  function useResolvedPath(to, _temp2) {
    let {
      relative
    } = _temp2 === void 0 ? {} : _temp2;
    let {
      future
    } = React.useContext(NavigationContext);
    let {
      matches
    } = React.useContext(RouteContext);
    let {
      pathname: locationPathname
    } = useLocation();
    let routePathnamesJson = JSON.stringify(getResolveToMatches(matches, future.v7_relativeSplatPath));
    return React.useMemo(() => resolveTo(to, JSON.parse(routePathnamesJson), locationPathname, relative === "path"), [to, routePathnamesJson, locationPathname, relative]);
  }
  function useRoutes(routes, locationArg) {
    return useRoutesImpl(routes, locationArg);
  }
  function useRoutesImpl(routes, locationArg, dataRouterState, future) {
    !useInRouterContext() ? false ? invariant(
      false,
      // TODO: This error is probably because they somehow have 2 versions of the
      // router loaded. We can help them understand how to avoid that.
      "useRoutes() may be used only in the context of a <Router> component."
    ) : invariant(false) : void 0;
    let {
      navigator: navigator2
    } = React.useContext(NavigationContext);
    let {
      matches: parentMatches
    } = React.useContext(RouteContext);
    let routeMatch = parentMatches[parentMatches.length - 1];
    let parentParams = routeMatch ? routeMatch.params : {};
    let parentPathname = routeMatch ? routeMatch.pathname : "/";
    let parentPathnameBase = routeMatch ? routeMatch.pathnameBase : "/";
    let parentRoute = routeMatch && routeMatch.route;
    if (false) {
      let parentPath = parentRoute && parentRoute.path || "";
      warningOnce(parentPathname, !parentRoute || parentPath.endsWith("*"), "You rendered descendant <Routes> (or called `useRoutes()`) at " + ('"' + parentPathname + '" (under <Route path="' + parentPath + '">) but the ') + `parent route path has no trailing "*". This means if you navigate deeper, the parent won't match anymore and therefore the child routes will never render.

` + ('Please change the parent <Route path="' + parentPath + '"> to <Route ') + ('path="' + (parentPath === "/" ? "*" : parentPath + "/*") + '">.'));
    }
    let locationFromContext = useLocation();
    let location;
    if (locationArg) {
      var _parsedLocationArg$pa;
      let parsedLocationArg = typeof locationArg === "string" ? parsePath(locationArg) : locationArg;
      !(parentPathnameBase === "/" || ((_parsedLocationArg$pa = parsedLocationArg.pathname) == null ? void 0 : _parsedLocationArg$pa.startsWith(parentPathnameBase))) ? false ? invariant(false, "When overriding the location using `<Routes location>` or `useRoutes(routes, location)`, the location pathname must begin with the portion of the URL pathname that was " + ('matched by all parent routes. The current pathname base is "' + parentPathnameBase + '" ') + ('but pathname "' + parsedLocationArg.pathname + '" was given in the `location` prop.')) : invariant(false) : void 0;
      location = parsedLocationArg;
    } else {
      location = locationFromContext;
    }
    let pathname = location.pathname || "/";
    let remainingPathname = pathname;
    if (parentPathnameBase !== "/") {
      let parentSegments = parentPathnameBase.replace(/^\//, "").split("/");
      let segments = pathname.replace(/^\//, "").split("/");
      remainingPathname = "/" + segments.slice(parentSegments.length).join("/");
    }
    let matches = matchRoutes(routes, {
      pathname: remainingPathname
    });
    if (false) {
      false ? warning(parentRoute || matches != null, 'No routes matched location "' + location.pathname + location.search + location.hash + '" ') : void 0;
      false ? warning(matches == null || matches[matches.length - 1].route.element !== void 0 || matches[matches.length - 1].route.Component !== void 0 || matches[matches.length - 1].route.lazy !== void 0, 'Matched leaf route at location "' + location.pathname + location.search + location.hash + '" does not have an element or Component. This means it will render an <Outlet /> with a null value by default resulting in an "empty" page.') : void 0;
    }
    let renderedMatches = _renderMatches(matches && matches.map((match) => Object.assign({}, match, {
      params: Object.assign({}, parentParams, match.params),
      pathname: joinPaths([
        parentPathnameBase,
        // Re-encode pathnames that were decoded inside matchRoutes
        navigator2.encodeLocation ? navigator2.encodeLocation(match.pathname).pathname : match.pathname
      ]),
      pathnameBase: match.pathnameBase === "/" ? parentPathnameBase : joinPaths([
        parentPathnameBase,
        // Re-encode pathnames that were decoded inside matchRoutes
        navigator2.encodeLocation ? navigator2.encodeLocation(match.pathnameBase).pathname : match.pathnameBase
      ])
    })), parentMatches, dataRouterState, future);
    if (locationArg && renderedMatches) {
      return /* @__PURE__ */ React.createElement(LocationContext.Provider, {
        value: {
          location: _extends2({
            pathname: "/",
            search: "",
            hash: "",
            state: null,
            key: "default"
          }, location),
          navigationType: Action.Pop
        }
      }, renderedMatches);
    }
    return renderedMatches;
  }
  function DefaultErrorComponent() {
    let error = useRouteError();
    let message = isRouteErrorResponse(error) ? error.status + " " + error.statusText : error instanceof Error ? error.message : JSON.stringify(error);
    let stack = error instanceof Error ? error.stack : null;
    let lightgrey = "rgba(200,200,200, 0.5)";
    let preStyles = {
      padding: "0.5rem",
      backgroundColor: lightgrey
    };
    let codeStyles = {
      padding: "2px 4px",
      backgroundColor: lightgrey
    };
    let devInfo = null;
    if (false) {
      console.error("Error handled by React Router default ErrorBoundary:", error);
      devInfo = /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("p", null, "\u{1F4BF} Hey developer \u{1F44B}"), /* @__PURE__ */ React.createElement("p", null, "You can provide a way better UX than this when your app throws errors by providing your own ", /* @__PURE__ */ React.createElement("code", {
        style: codeStyles
      }, "ErrorBoundary"), " or", " ", /* @__PURE__ */ React.createElement("code", {
        style: codeStyles
      }, "errorElement"), " prop on your route."));
    }
    return /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("h2", null, "Unexpected Application Error!"), /* @__PURE__ */ React.createElement("h3", {
      style: {
        fontStyle: "italic"
      }
    }, message), stack ? /* @__PURE__ */ React.createElement("pre", {
      style: preStyles
    }, stack) : null, devInfo);
  }
  var defaultErrorElement = /* @__PURE__ */ React.createElement(DefaultErrorComponent, null);
  var RenderErrorBoundary = class extends React.Component {
    constructor(props) {
      super(props);
      this.state = {
        location: props.location,
        revalidation: props.revalidation,
        error: props.error
      };
    }
    static getDerivedStateFromError(error) {
      return {
        error
      };
    }
    static getDerivedStateFromProps(props, state) {
      if (state.location !== props.location || state.revalidation !== "idle" && props.revalidation === "idle") {
        return {
          error: props.error,
          location: props.location,
          revalidation: props.revalidation
        };
      }
      return {
        error: props.error !== void 0 ? props.error : state.error,
        location: state.location,
        revalidation: props.revalidation || state.revalidation
      };
    }
    componentDidCatch(error, errorInfo) {
      console.error("React Router caught the following error during render", error, errorInfo);
    }
    render() {
      return this.state.error !== void 0 ? /* @__PURE__ */ React.createElement(RouteContext.Provider, {
        value: this.props.routeContext
      }, /* @__PURE__ */ React.createElement(RouteErrorContext.Provider, {
        value: this.state.error,
        children: this.props.component
      })) : this.props.children;
    }
  };
  function RenderedRoute(_ref) {
    let {
      routeContext,
      match,
      children
    } = _ref;
    let dataRouterContext = React.useContext(DataRouterContext);
    if (dataRouterContext && dataRouterContext.static && dataRouterContext.staticContext && (match.route.errorElement || match.route.ErrorBoundary)) {
      dataRouterContext.staticContext._deepestRenderedBoundaryId = match.route.id;
    }
    return /* @__PURE__ */ React.createElement(RouteContext.Provider, {
      value: routeContext
    }, children);
  }
  function _renderMatches(matches, parentMatches, dataRouterState, future) {
    var _dataRouterState;
    if (parentMatches === void 0) {
      parentMatches = [];
    }
    if (dataRouterState === void 0) {
      dataRouterState = null;
    }
    if (future === void 0) {
      future = null;
    }
    if (matches == null) {
      var _future;
      if (!dataRouterState) {
        return null;
      }
      if (dataRouterState.errors) {
        matches = dataRouterState.matches;
      } else if ((_future = future) != null && _future.v7_partialHydration && parentMatches.length === 0 && !dataRouterState.initialized && dataRouterState.matches.length > 0) {
        matches = dataRouterState.matches;
      } else {
        return null;
      }
    }
    let renderedMatches = matches;
    let errors = (_dataRouterState = dataRouterState) == null ? void 0 : _dataRouterState.errors;
    if (errors != null) {
      let errorIndex = renderedMatches.findIndex((m) => m.route.id && (errors == null ? void 0 : errors[m.route.id]) !== void 0);
      !(errorIndex >= 0) ? false ? invariant(false, "Could not find a matching route for errors on route IDs: " + Object.keys(errors).join(",")) : invariant(false) : void 0;
      renderedMatches = renderedMatches.slice(0, Math.min(renderedMatches.length, errorIndex + 1));
    }
    let renderFallback = false;
    let fallbackIndex = -1;
    if (dataRouterState && future && future.v7_partialHydration) {
      for (let i = 0; i < renderedMatches.length; i++) {
        let match = renderedMatches[i];
        if (match.route.HydrateFallback || match.route.hydrateFallbackElement) {
          fallbackIndex = i;
        }
        if (match.route.id) {
          let {
            loaderData,
            errors: errors2
          } = dataRouterState;
          let needsToRunLoader = match.route.loader && loaderData[match.route.id] === void 0 && (!errors2 || errors2[match.route.id] === void 0);
          if (match.route.lazy || needsToRunLoader) {
            renderFallback = true;
            if (fallbackIndex >= 0) {
              renderedMatches = renderedMatches.slice(0, fallbackIndex + 1);
            } else {
              renderedMatches = [renderedMatches[0]];
            }
            break;
          }
        }
      }
    }
    return renderedMatches.reduceRight((outlet, match, index) => {
      let error;
      let shouldRenderHydrateFallback = false;
      let errorElement = null;
      let hydrateFallbackElement = null;
      if (dataRouterState) {
        error = errors && match.route.id ? errors[match.route.id] : void 0;
        errorElement = match.route.errorElement || defaultErrorElement;
        if (renderFallback) {
          if (fallbackIndex < 0 && index === 0) {
            warningOnce("route-fallback", false, "No `HydrateFallback` element provided to render during initial hydration");
            shouldRenderHydrateFallback = true;
            hydrateFallbackElement = null;
          } else if (fallbackIndex === index) {
            shouldRenderHydrateFallback = true;
            hydrateFallbackElement = match.route.hydrateFallbackElement || null;
          }
        }
      }
      let matches2 = parentMatches.concat(renderedMatches.slice(0, index + 1));
      let getChildren = () => {
        let children;
        if (error) {
          children = errorElement;
        } else if (shouldRenderHydrateFallback) {
          children = hydrateFallbackElement;
        } else if (match.route.Component) {
          children = /* @__PURE__ */ React.createElement(match.route.Component, null);
        } else if (match.route.element) {
          children = match.route.element;
        } else {
          children = outlet;
        }
        return /* @__PURE__ */ React.createElement(RenderedRoute, {
          match,
          routeContext: {
            outlet,
            matches: matches2,
            isDataRoute: dataRouterState != null
          },
          children
        });
      };
      return dataRouterState && (match.route.ErrorBoundary || match.route.errorElement || index === 0) ? /* @__PURE__ */ React.createElement(RenderErrorBoundary, {
        location: dataRouterState.location,
        revalidation: dataRouterState.revalidation,
        component: errorElement,
        error,
        children: getChildren(),
        routeContext: {
          outlet: null,
          matches: matches2,
          isDataRoute: true
        }
      }) : getChildren();
    }, null);
  }
  var DataRouterHook = /* @__PURE__ */ (function(DataRouterHook3) {
    DataRouterHook3["UseBlocker"] = "useBlocker";
    DataRouterHook3["UseRevalidator"] = "useRevalidator";
    DataRouterHook3["UseNavigateStable"] = "useNavigate";
    return DataRouterHook3;
  })(DataRouterHook || {});
  var DataRouterStateHook = /* @__PURE__ */ (function(DataRouterStateHook3) {
    DataRouterStateHook3["UseBlocker"] = "useBlocker";
    DataRouterStateHook3["UseLoaderData"] = "useLoaderData";
    DataRouterStateHook3["UseActionData"] = "useActionData";
    DataRouterStateHook3["UseRouteError"] = "useRouteError";
    DataRouterStateHook3["UseNavigation"] = "useNavigation";
    DataRouterStateHook3["UseRouteLoaderData"] = "useRouteLoaderData";
    DataRouterStateHook3["UseMatches"] = "useMatches";
    DataRouterStateHook3["UseRevalidator"] = "useRevalidator";
    DataRouterStateHook3["UseNavigateStable"] = "useNavigate";
    DataRouterStateHook3["UseRouteId"] = "useRouteId";
    return DataRouterStateHook3;
  })(DataRouterStateHook || {});
  function useDataRouterContext(hookName) {
    let ctx = React.useContext(DataRouterContext);
    !ctx ? false ? invariant(false, getDataRouterConsoleError(hookName)) : invariant(false) : void 0;
    return ctx;
  }
  function useDataRouterState(hookName) {
    let state = React.useContext(DataRouterStateContext);
    !state ? false ? invariant(false, getDataRouterConsoleError(hookName)) : invariant(false) : void 0;
    return state;
  }
  function useRouteContext(hookName) {
    let route = React.useContext(RouteContext);
    !route ? false ? invariant(false, getDataRouterConsoleError(hookName)) : invariant(false) : void 0;
    return route;
  }
  function useCurrentRouteId(hookName) {
    let route = useRouteContext(hookName);
    let thisRoute = route.matches[route.matches.length - 1];
    !thisRoute.route.id ? false ? invariant(false, hookName + ' can only be used on routes that contain a unique "id"') : invariant(false) : void 0;
    return thisRoute.route.id;
  }
  function useRouteError() {
    var _state$errors;
    let error = React.useContext(RouteErrorContext);
    let state = useDataRouterState(DataRouterStateHook.UseRouteError);
    let routeId = useCurrentRouteId(DataRouterStateHook.UseRouteError);
    if (error !== void 0) {
      return error;
    }
    return (_state$errors = state.errors) == null ? void 0 : _state$errors[routeId];
  }
  function useNavigateStable() {
    let {
      router
    } = useDataRouterContext(DataRouterHook.UseNavigateStable);
    let id = useCurrentRouteId(DataRouterStateHook.UseNavigateStable);
    let activeRef = React.useRef(false);
    useIsomorphicLayoutEffect(() => {
      activeRef.current = true;
    });
    let navigate = React.useCallback(function(to, options) {
      if (options === void 0) {
        options = {};
      }
      false ? warning(activeRef.current, navigateEffectWarning) : void 0;
      if (!activeRef.current) return;
      if (typeof to === "number") {
        router.navigate(to);
      } else {
        router.navigate(to, _extends2({
          fromRouteId: id
        }, options));
      }
    }, [router, id]);
    return navigate;
  }
  var alreadyWarned$1 = {};
  function warningOnce(key, cond, message) {
    if (!cond && !alreadyWarned$1[key]) {
      alreadyWarned$1[key] = true;
      false ? warning(false, message) : void 0;
    }
  }
  function warnOnce(key, message) {
    if (false) {
      alreadyWarned[message] = true;
      console.warn(message);
    }
  }
  var logDeprecation = (flag, msg, link) => warnOnce(flag, "\u26A0\uFE0F React Router Future Flag Warning: " + msg + ". " + ("You can use the `" + flag + "` future flag to opt-in early. ") + ("For more information, see " + link + "."));
  function logV6DeprecationWarnings(renderFuture, routerFuture) {
    if ((renderFuture == null ? void 0 : renderFuture.v7_startTransition) === void 0) {
      logDeprecation("v7_startTransition", "React Router will begin wrapping state updates in `React.startTransition` in v7", "https://reactrouter.com/v6/upgrading/future#v7_starttransition");
    }
    if ((renderFuture == null ? void 0 : renderFuture.v7_relativeSplatPath) === void 0 && (!routerFuture || routerFuture.v7_relativeSplatPath === void 0)) {
      logDeprecation("v7_relativeSplatPath", "Relative route resolution within Splat routes is changing in v7", "https://reactrouter.com/v6/upgrading/future#v7_relativesplatpath");
    }
    if (routerFuture) {
      if (routerFuture.v7_fetcherPersist === void 0) {
        logDeprecation("v7_fetcherPersist", "The persistence behavior of fetchers is changing in v7", "https://reactrouter.com/v6/upgrading/future#v7_fetcherpersist");
      }
      if (routerFuture.v7_normalizeFormMethod === void 0) {
        logDeprecation("v7_normalizeFormMethod", "Casing of `formMethod` fields is being normalized to uppercase in v7", "https://reactrouter.com/v6/upgrading/future#v7_normalizeformmethod");
      }
      if (routerFuture.v7_partialHydration === void 0) {
        logDeprecation("v7_partialHydration", "`RouterProvider` hydration behavior is changing in v7", "https://reactrouter.com/v6/upgrading/future#v7_partialhydration");
      }
      if (routerFuture.v7_skipActionErrorRevalidation === void 0) {
        logDeprecation("v7_skipActionErrorRevalidation", "The revalidation behavior after 4xx/5xx `action` responses is changing in v7", "https://reactrouter.com/v6/upgrading/future#v7_skipactionerrorrevalidation");
      }
    }
  }
  var START_TRANSITION = "startTransition";
  var startTransitionImpl = React[START_TRANSITION];
  function Route(_props) {
    false ? invariant(false, "A <Route> is only ever to be used as the child of <Routes> element, never rendered directly. Please wrap your <Route> in a <Routes>.") : invariant(false);
  }
  function Router(_ref5) {
    let {
      basename: basenameProp = "/",
      children = null,
      location: locationProp,
      navigationType = Action.Pop,
      navigator: navigator2,
      static: staticProp = false,
      future
    } = _ref5;
    !!useInRouterContext() ? false ? invariant(false, "You cannot render a <Router> inside another <Router>. You should never have more than one in your app.") : invariant(false) : void 0;
    let basename = basenameProp.replace(/^\/*/, "/");
    let navigationContext = React.useMemo(() => ({
      basename,
      navigator: navigator2,
      static: staticProp,
      future: _extends2({
        v7_relativeSplatPath: false
      }, future)
    }), [basename, future, navigator2, staticProp]);
    if (typeof locationProp === "string") {
      locationProp = parsePath(locationProp);
    }
    let {
      pathname = "/",
      search = "",
      hash = "",
      state = null,
      key = "default"
    } = locationProp;
    let locationContext = React.useMemo(() => {
      let trailingPathname = stripBasename(pathname, basename);
      if (trailingPathname == null) {
        return null;
      }
      return {
        location: {
          pathname: trailingPathname,
          search,
          hash,
          state,
          key
        },
        navigationType
      };
    }, [basename, pathname, search, hash, state, key, navigationType]);
    false ? warning(locationContext != null, '<Router basename="' + basename + '"> is not able to match the URL ' + ('"' + pathname + search + hash + '" because it does not start with the ') + "basename, so the <Router> won't render anything.") : void 0;
    if (locationContext == null) {
      return null;
    }
    return /* @__PURE__ */ React.createElement(NavigationContext.Provider, {
      value: navigationContext
    }, /* @__PURE__ */ React.createElement(LocationContext.Provider, {
      children,
      value: locationContext
    }));
  }
  function Routes(_ref6) {
    let {
      children,
      location
    } = _ref6;
    return useRoutes(createRoutesFromChildren(children), location);
  }
  var neverSettledPromise = new Promise(() => {
  });
  function createRoutesFromChildren(children, parentPath) {
    if (parentPath === void 0) {
      parentPath = [];
    }
    let routes = [];
    React.Children.forEach(children, (element, index) => {
      if (!/* @__PURE__ */ React.isValidElement(element)) {
        return;
      }
      let treePath = [...parentPath, index];
      if (element.type === React.Fragment) {
        routes.push.apply(routes, createRoutesFromChildren(element.props.children, treePath));
        return;
      }
      !(element.type === Route) ? false ? invariant(false, "[" + (typeof element.type === "string" ? element.type : element.type.name) + "] is not a <Route> component. All component children of <Routes> must be a <Route> or <React.Fragment>") : invariant(false) : void 0;
      !(!element.props.index || !element.props.children) ? false ? invariant(false, "An index route cannot have child routes.") : invariant(false) : void 0;
      let route = {
        id: element.props.id || treePath.join("-"),
        caseSensitive: element.props.caseSensitive,
        element: element.props.element,
        Component: element.props.Component,
        index: element.props.index,
        path: element.props.path,
        loader: element.props.loader,
        action: element.props.action,
        errorElement: element.props.errorElement,
        ErrorBoundary: element.props.ErrorBoundary,
        hasErrorBoundary: element.props.ErrorBoundary != null || element.props.errorElement != null,
        shouldRevalidate: element.props.shouldRevalidate,
        handle: element.props.handle,
        lazy: element.props.lazy
      };
      if (element.props.children) {
        route.children = createRoutesFromChildren(element.props.children, treePath);
      }
      routes.push(route);
    });
    return routes;
  }

  // node_modules/react-router-dom/dist/index.js
  function _extends3() {
    _extends3 = Object.assign ? Object.assign.bind() : function(target) {
      for (var i = 1; i < arguments.length; i++) {
        var source = arguments[i];
        for (var key in source) {
          if (Object.prototype.hasOwnProperty.call(source, key)) {
            target[key] = source[key];
          }
        }
      }
      return target;
    };
    return _extends3.apply(this, arguments);
  }
  function _objectWithoutPropertiesLoose(source, excluded) {
    if (source == null) return {};
    var target = {};
    var sourceKeys = Object.keys(source);
    var key, i;
    for (i = 0; i < sourceKeys.length; i++) {
      key = sourceKeys[i];
      if (excluded.indexOf(key) >= 0) continue;
      target[key] = source[key];
    }
    return target;
  }
  function isModifiedEvent(event) {
    return !!(event.metaKey || event.altKey || event.ctrlKey || event.shiftKey);
  }
  function shouldProcessLinkClick(event, target) {
    return event.button === 0 && // Ignore everything but left clicks
    (!target || target === "_self") && // Let browser handle "target=_blank" etc.
    !isModifiedEvent(event);
  }
  var _excluded = ["onClick", "relative", "reloadDocument", "replace", "state", "target", "to", "preventScrollReset", "viewTransition"];
  var REACT_ROUTER_VERSION = "6";
  try {
    window.__reactRouterVersion = REACT_ROUTER_VERSION;
  } catch (e) {
  }
  if (false) {
    ViewTransitionContext.displayName = "ViewTransition";
  }
  if (false) {
    FetchersContext.displayName = "Fetchers";
  }
  var START_TRANSITION2 = "startTransition";
  var startTransitionImpl2 = React2[START_TRANSITION2];
  var FLUSH_SYNC = "flushSync";
  var flushSyncImpl = ReactDOM[FLUSH_SYNC];
  var USE_ID = "useId";
  var useIdImpl = React2[USE_ID];
  function BrowserRouter(_ref4) {
    let {
      basename,
      children,
      future,
      window: window2
    } = _ref4;
    let historyRef = React2.useRef();
    if (historyRef.current == null) {
      historyRef.current = createBrowserHistory({
        window: window2,
        v5Compat: true
      });
    }
    let history = historyRef.current;
    let [state, setStateImpl] = React2.useState({
      action: history.action,
      location: history.location
    });
    let {
      v7_startTransition
    } = future || {};
    let setState = React2.useCallback((newState) => {
      v7_startTransition && startTransitionImpl2 ? startTransitionImpl2(() => setStateImpl(newState)) : setStateImpl(newState);
    }, [setStateImpl, v7_startTransition]);
    React2.useLayoutEffect(() => history.listen(setState), [history, setState]);
    React2.useEffect(() => logV6DeprecationWarnings(future), [future]);
    return /* @__PURE__ */ React2.createElement(Router, {
      basename,
      children,
      location: state.location,
      navigationType: state.action,
      navigator: history,
      future
    });
  }
  if (false) {
    HistoryRouter.displayName = "unstable_HistoryRouter";
  }
  var isBrowser = typeof window !== "undefined" && typeof window.document !== "undefined" && typeof window.document.createElement !== "undefined";
  var ABSOLUTE_URL_REGEX = /^(?:[a-z][a-z0-9+.-]*:|\/\/)/i;
  var Link = /* @__PURE__ */ React2.forwardRef(function LinkWithRef(_ref7, ref) {
    let {
      onClick,
      relative,
      reloadDocument,
      replace: replace2,
      state,
      target,
      to,
      preventScrollReset,
      viewTransition
    } = _ref7, rest = _objectWithoutPropertiesLoose(_ref7, _excluded);
    let {
      basename
    } = React2.useContext(NavigationContext);
    let absoluteHref;
    let isExternal = false;
    if (typeof to === "string" && ABSOLUTE_URL_REGEX.test(to)) {
      absoluteHref = to;
      if (isBrowser) {
        try {
          let currentUrl = new URL(window.location.href);
          let targetUrl = to.startsWith("//") ? new URL(currentUrl.protocol + to) : new URL(to);
          let path = stripBasename(targetUrl.pathname, basename);
          if (targetUrl.origin === currentUrl.origin && path != null) {
            to = path + targetUrl.search + targetUrl.hash;
          } else {
            isExternal = true;
          }
        } catch (e) {
          false ? warning(false, '<Link to="' + to + '"> contains an invalid URL which will probably break when clicked - please update to a valid URL path.') : void 0;
        }
      }
    }
    let href = useHref(to, {
      relative
    });
    let internalOnClick = useLinkClickHandler(to, {
      replace: replace2,
      state,
      target,
      preventScrollReset,
      relative,
      viewTransition
    });
    function handleClick(event) {
      if (onClick) onClick(event);
      if (!event.defaultPrevented) {
        internalOnClick(event);
      }
    }
    return (
      // eslint-disable-next-line jsx-a11y/anchor-has-content
      /* @__PURE__ */ React2.createElement("a", _extends3({}, rest, {
        href: absoluteHref || href,
        onClick: isExternal || reloadDocument ? onClick : handleClick,
        ref,
        target
      }))
    );
  });
  if (false) {
    Link.displayName = "Link";
  }
  if (false) {
    NavLink.displayName = "NavLink";
  }
  if (false) {
    Form.displayName = "Form";
  }
  if (false) {
    ScrollRestoration.displayName = "ScrollRestoration";
  }
  var DataRouterHook2;
  (function(DataRouterHook3) {
    DataRouterHook3["UseScrollRestoration"] = "useScrollRestoration";
    DataRouterHook3["UseSubmit"] = "useSubmit";
    DataRouterHook3["UseSubmitFetcher"] = "useSubmitFetcher";
    DataRouterHook3["UseFetcher"] = "useFetcher";
    DataRouterHook3["useViewTransitionState"] = "useViewTransitionState";
  })(DataRouterHook2 || (DataRouterHook2 = {}));
  var DataRouterStateHook2;
  (function(DataRouterStateHook3) {
    DataRouterStateHook3["UseFetcher"] = "useFetcher";
    DataRouterStateHook3["UseFetchers"] = "useFetchers";
    DataRouterStateHook3["UseScrollRestoration"] = "useScrollRestoration";
  })(DataRouterStateHook2 || (DataRouterStateHook2 = {}));
  function useLinkClickHandler(to, _temp) {
    let {
      target,
      replace: replaceProp,
      state,
      preventScrollReset,
      relative,
      viewTransition
    } = _temp === void 0 ? {} : _temp;
    let navigate = useNavigate();
    let location = useLocation();
    let path = useResolvedPath(to, {
      relative
    });
    return React2.useCallback((event) => {
      if (shouldProcessLinkClick(event, target)) {
        event.preventDefault();
        let replace2 = replaceProp !== void 0 ? replaceProp : createPath(location) === createPath(path);
        navigate(to, {
          replace: replace2,
          state,
          preventScrollReset,
          relative,
          viewTransition
        });
      }
    }, [location, navigate, path, replaceProp, state, target, to, preventScrollReset, relative, viewTransition]);
  }

  // views/react/ReactRoutes.js
  var ReactRoutes = {
    dashboard: "/",
    serverConsolePattern: "/server/:containerId",
    serverFilesPattern: "/server/:containerId/files",
    serverBackupsPattern: "/server/:containerId/backups",
    serverNetworkPattern: "/server/:containerId/network",
    serverApiPattern: "/server/:containerId/api",
    serverDatabasesPattern: "/server/:containerId/databases",
    serverUsersPattern: "/server/:containerId/users",
    serverSchedulesPattern: "/server/:containerId/schedules",
    serverStartupPattern: "/server/:containerId/startup",
    serverFilesEditPattern: "/server/:containerId/files/edit",
    serverMinecraftCenterPattern: "/server/:containerId/minecraft-center",
    serverMinecraftWorldCenterPattern: "/server/:containerId/minecraft/world-center",
    serverMinecraftAddonsPattern: "/server/:containerId/minecraft/addons",
    serverMinecraftInstallerPattern: "/server/:containerId/minecraft/installer",
    serverMinecraftAdminPattern: "/server/:containerId/minecraft/admin",
    serverMinecraftConfigsPattern: "/server/:containerId/minecraft/configs",
    serverOverviewPattern: "/server/:containerId/overview",
    serverActivityPattern: "/server/:containerId/activity",
    serverTimelinePattern: "/server/:containerId/timeline",
    serverNotFoundPattern: "/server/:containerId/notfound",
    serverNoPermissionsPattern: "/server/:containerId/no-permissions",
    serverSuspendedPattern: "/server/:containerId/suspended",
    account: "/account",
    deviceLogin: "/account/device-login",
    themes: "/themes",
    rewards: "/rewards",
    afk: "/afk",
    experimentalFeatures: "/instable/outdated",
    changeView: "/experimental/change-view",
    connectorsCheck: "/connectors-check",
    notifications: "/notifications",
    admin: "/admin"
  };
  var RESERVED_SERVER_SEGMENTS = /* @__PURE__ */ new Set(["notfound", "no-permissions", "suspended"]);
  function resolveBrandImage(pageData = {}) {
    return pageData.faviconUrl || "/assets/rocky.png";
  }
  function resolveUserAvatar(user = {}, fallback = "/assets/rocky.png") {
    if (user && user.avatarProvider === "url" && user.avatarUrl) {
      return user.avatarUrl;
    }
    if (user && user.gravatarHash) {
      return `https://www.gravatar.com/avatar/${user.gravatarHash}?d=retro&s=120`;
    }
    return fallback;
  }
  function parseServerRoute(pathname = "") {
    const normalized = String(pathname || "").trim().replace(/\/+$/, "") || "/";
    const match = normalized.match(/^\/server\/([^/]+)(?:\/(minecraft-center|minecraft\/world-center|minecraft\/addons|minecraft\/installer|minecraft\/admin|minecraft\/configs|files\/edit|files|backups|network|api|databases|users|schedules|startup|overview|activity|timeline|notfound|no-permissions|suspended))?$/);
    if (!match) return null;
    let containerId = "";
    try {
      containerId = decodeURIComponent(match[1]).trim();
    } catch {
      containerId = String(match[1] || "").trim();
    }
    if (!containerId || RESERVED_SERVER_SEGMENTS.has(containerId.toLowerCase())) {
      return null;
    }
    return {
      containerId,
      page: match[2] || "console"
    };
  }
  function resolveServerReactPage(pathname = "") {
    return parseServerRoute(pathname);
  }

  // views/react/dashboard.jsx
  var import_react13 = __toESM(require_react());
  var import_client = __toESM(require_client());

  // views/react/components/ThemeContext.jsx
  var import_react = __toESM(require_react());
  var import_jsx_runtime = __toESM(require_jsx_runtime());
  var ThemeContext = (0, import_react.createContext)();
  function ThemeProvider2({ children, pageData = {} }) {
    const [activeTheme, setActiveTheme] = (0, import_react.useState)(pageData.activeTheme || "default");
    const [previewTheme, setPreviewTheme] = (0, import_react.useState)(null);
    const [customTheme, setCustomTheme] = (0, import_react.useState)(pageData.customTheme || { enabled: false });
    const applyTheme = (themeId, isPreview = false) => {
      if (isPreview) {
        setPreviewTheme(themeId);
      } else {
        setActiveTheme(themeId || activeTheme);
        setPreviewTheme(null);
      }
    };
    const toggleCustomTheme = (enabled) => {
      setCustomTheme((prev) => ({ ...prev, enabled }));
    };
    const restoreTheme = () => {
      setPreviewTheme(null);
    };
    (0, import_react.useEffect)(() => {
      if (pageData.activeTheme) {
        setActiveTheme(pageData.activeTheme);
      }
      if (pageData.customTheme) {
        setCustomTheme(pageData.customTheme);
      }
    }, [pageData]);
    (0, import_react.useEffect)(() => {
      const themeToApply = previewTheme || activeTheme;
      let themeLink = document.getElementById("cpanel-theme-css");
      if (!themeLink) {
        themeLink = document.createElement("link");
        themeLink.id = "cpanel-theme-css";
        themeLink.rel = "stylesheet";
        document.head.appendChild(themeLink);
      }
      const href = `/themes-react/${themeToApply}.css`;
      if (themeLink.getAttribute("href") !== href) {
        themeLink.setAttribute("href", href);
      }
      document.documentElement.setAttribute("data-theme", themeToApply);
      document.body.style.background = "var(--cp-body-background)";
      document.body.style.backgroundSize = "cover";
      document.body.style.backgroundPosition = "center";
      document.body.style.backgroundAttachment = "fixed";
      const customEnabled = previewTheme ? false : customTheme.enabled;
      document.documentElement.setAttribute("data-user-custom-theme", customEnabled ? "on" : "off");
      let customStyle = document.getElementById("cpanel-custom-theme-overrides");
      if (customEnabled) {
        if (!customStyle) {
          customStyle = document.createElement("style");
          customStyle.id = "cpanel-custom-theme-overrides";
          document.head.appendChild(customStyle);
        }
        customStyle.textContent = `
                :root {
                    --neutral-900: ${customTheme.panelSurface || "#141419"};
                    --neutral-800: ${customTheme.cardBackground || "#1f2023"};
                    --neutral-700: ${customTheme.cardBorder || "#2e3036"};
                    --primary-500: ${customTheme.accentColor || "#3b82f6"};
                    --neutral-100: ${customTheme.textColor || "#ffffff"};
                    --neutral-400: ${customTheme.mutedTextColor || "#a1a1aa"};
                    --cp-body-background: ${customTheme.backgroundImageUrl ? `linear-gradient(rgba(0,0,0,0.4), rgba(0,0,0,0.4)), url('${customTheme.backgroundImageUrl}'), ${customTheme.backgroundColor || "#0d0d0f"}` : customTheme.backgroundColor || "#0d0d0f"};
                }
            `;
      } else if (customStyle) {
        customStyle.textContent = "";
      }
    }, [activeTheme, previewTheme, customTheme]);
    const value = {
      activeTheme,
      previewTheme,
      customTheme,
      applyTheme,
      toggleCustomTheme,
      restoreTheme
    };
    return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ThemeContext.Provider, { value, children });
  }
  var useTheme = () => {
    const context = (0, import_react.useContext)(ThemeContext);
    if (!context) {
      throw new Error("useTheme must be used within a ThemeProvider");
    }
    return context;
  };
  var ThemeContext_default = ThemeProvider2;

  // views/react/components/ReactAppShell.jsx
  var import_react9 = __toESM(require_react());

  // views/react/components/ProvisioningBarrier.jsx
  var import_react2 = __toESM(require_react());
  var import_jsx_runtime2 = __toESM(require_jsx_runtime());
  function ProvisioningBarrier({ status = "installing", containerId }) {
    const isReinstall = status === "reinstalling";
    return /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: "flex flex-col items-center justify-center min-h-[500px] py-20 px-6 text-center", children: [
      /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: "relative mb-8", children: [
        /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("div", { className: "absolute -inset-10 bg-primary-600/10 rounded-full blur-3xl animate-pulse" }),
        /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: "relative w-32 h-32 flex items-center justify-center", children: [
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("svg", { className: "w-full h-full text-primary-500 animate-[spin_3s_linear_infinite]", viewBox: "0 0 100 100", children: /* @__PURE__ */ (0, import_jsx_runtime2.jsx)(
            "circle",
            {
              cx: "50",
              cy: "50",
              r: "45",
              fill: "none",
              stroke: "currentColor",
              strokeWidth: "2",
              strokeDasharray: "200 100",
              strokeLinecap: "round"
            }
          ) }),
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("div", { className: "absolute inset-0 flex items-center justify-center text-primary-400", children: /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("i", { className: `bi ${isReinstall ? "bi-arrow-clockwise" : "bi-tools"} text-4xl` }) })
        ] })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("h2", { className: "text-3xl font-black text-white uppercase tracking-[0.2em] mb-4", children: isReinstall ? "System Reinstall" : "Server Provisioning" }),
      /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("p", { className: "text-neutral-500 font-bold uppercase tracking-widest text-xs max-w-md mx-auto leading-relaxed mb-8", children: [
        "Your server instance is currently being ",
        isReinstall ? "reinstalled" : "set up",
        " on the node. Administrative tools are temporarily disabled to ensure data integrity during file restoration."
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: "flex flex-col items-center gap-4", children: [
        /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: "flex items-center gap-2 bg-neutral-800/50 px-4 py-2 rounded-full border border-neutral-700/50", children: [
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("div", { className: "w-2 h-2 bg-primary-500 rounded-full animate-ping" }),
          /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("span", { className: "text-[10px] font-black text-neutral-300 uppercase tracking-widest", children: [
            "Working on ",
            containerId?.substring(0, 12) || "unknown"
          ] })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("div", { className: "mt-4 flex gap-4", children: /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)(
          "a",
          {
            href: `/server/${containerId}`,
            className: "bg-neutral-800 hover:bg-neutral-700 text-neutral-100 px-6 py-3 rounded-xl text-[10px] font-black uppercase tracking-[0.2em] transition-all flex items-center gap-3 border border-neutral-700",
            children: [
              /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("i", { className: "bi bi-terminal text-lg opacity-50" }),
              "Open Console"
            ]
          }
        ) })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: "mt-16 grid grid-cols-1 sm:grid-cols-3 gap-8 w-full max-w-2xl opacity-40 grayscale group-hover:grayscale-0 transition-all", children: [
        /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: "text-center", children: [
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("div", { className: "text-xl text-neutral-400 mb-1 font-black", children: "1" }),
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("div", { className: "text-[10px] text-neutral-600 uppercase font-black tracking-widest", children: "Allocating Resources" })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: "text-center", children: [
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("div", { className: "text-xl text-white mb-1 font-black", children: "2" }),
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("div", { className: "text-[10px] text-primary-400 uppercase font-black tracking-widest ring-1 ring-primary-500/20 rounded-full px-2 py-1", children: "Running Install Script" })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime2.jsxs)("div", { className: "text-center", children: [
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("div", { className: "text-xl text-neutral-400 mb-1 font-black", children: "3" }),
          /* @__PURE__ */ (0, import_jsx_runtime2.jsx)("div", { className: "text-[10px] text-neutral-600 uppercase font-black tracking-widest", children: "Starting Instance" })
        ] })
      ] })
    ] });
  }

  // views/react/components/GlobalStatusModal.jsx
  var import_react3 = __toESM(require_react());
  var import_jsx_runtime3 = __toESM(require_jsx_runtime());
  function GlobalStatusModal() {
    const [payload, setPayload] = (0, import_react3.useState)(null);
    const [isOpen, setIsOpen] = (0, import_react3.useState)(false);
    (0, import_react3.useEffect)(() => {
      const params = new URLSearchParams(window.location.search);
      const error = params.get("error");
      const warning2 = params.get("warning");
      const success = params.get("success");
      if (error || warning2 || success) {
        setPayload({
          type: error ? "error" : warning2 ? "warning" : "success",
          message: error || warning2 || success
        });
        setIsOpen(true);
        const url = new URL(window.location.href);
        url.searchParams.delete("error");
        url.searchParams.delete("warning");
        url.searchParams.delete("success");
        window.history.replaceState({}, document.title, url.pathname + url.search + url.hash);
      }
      const triggerHandler = (e) => {
        if (e.detail && e.detail.message) {
          setPayload({
            type: e.detail.type || "success",
            message: e.detail.message
          });
          setIsOpen(true);
        }
      };
      window.addEventListener("cpanel:show-status", triggerHandler);
      return () => window.removeEventListener("cpanel:show-status", triggerHandler);
    }, []);
    if (!isOpen || !payload) return null;
    const config = {
      error: {
        title: "Whoops! Something went wrong.",
        img: "/assets/sad-rocky.png",
        color: "text-red-400",
        bar: "bg-gradient-to-r from-red-600 to-red-900",
        bg: "bg-red-500/10",
        border: "border-red-500/30",
        btn: "bg-red-600 hover:bg-red-500 shadow-red-900/40",
        btnLabel: "I Understand"
      },
      warning: {
        title: "Wait! One second.",
        img: "/assets/what-rocky.png",
        color: "text-amber-400",
        bar: "bg-gradient-to-r from-amber-500 to-amber-700",
        bg: "bg-amber-500/10",
        border: "border-amber-500/30",
        btn: "bg-amber-600 hover:bg-amber-500 shadow-amber-900/40",
        btnLabel: "Got It"
      },
      success: {
        title: "Great! Success.",
        img: "/assets/happy-rocky.png",
        color: "text-emerald-400",
        bar: "bg-gradient-to-r from-emerald-500 to-emerald-700",
        bg: "bg-emerald-500/10",
        border: "border-emerald-500/30",
        btn: "bg-emerald-600 hover:bg-emerald-500 shadow-emerald-900/40",
        btnLabel: "Perfect, thanks!"
      }
    }[payload.type];
    return /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "fixed inset-0 z-[9999] flex items-center justify-center p-4", children: [
      /* @__PURE__ */ (0, import_jsx_runtime3.jsx)(
        "div",
        {
          className: "absolute inset-0 bg-black/80 backdrop-blur-md transition-opacity",
          onClick: () => setIsOpen(false)
        }
      ),
      /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "relative w-full max-w-md bg-neutral-900 border border-neutral-800 rounded-[2.5rem] overflow-hidden shadow-2xl animate-in zoom-in duration-300", children: [
        /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("div", { className: `h-1.5 w-full ${config.bar}` }),
        /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "p-8 pt-10 text-center", children: [
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)(
            "button",
            {
              onClick: () => setIsOpen(false),
              className: "absolute top-6 right-6 text-neutral-500 hover:text-white transition-colors",
              children: /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("i", { className: "bi bi-x-lg" })
            }
          ),
          /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: `relative w-32 h-32 mx-auto mb-6 rounded-full flex items-center justify-center border-2 border-dashed ${config.bg} ${config.border}`, children: [
            /* @__PURE__ */ (0, import_jsx_runtime3.jsx)(
              "img",
              {
                src: config.img,
                alt: "Rocky Mascot",
                className: "w-24 h-24 object-contain relative z-10"
              }
            ),
            /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("div", { className: `absolute inset-0 rounded-full blur-2xl opacity-20 ${config.bg}` })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("h3", { className: `text-xl font-black uppercase tracking-[0.15em] mb-2 ${config.color}`, children: config.title }),
          /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("p", { className: "text-neutral-400 font-medium leading-relaxed mb-8 px-4", children: payload.message }),
          /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("div", { className: "space-y-4", children: [
            payload.type === "error" && /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("div", { className: "bg-red-500/5 border border-red-500/20 rounded-xl py-2 mb-4", children: /* @__PURE__ */ (0, import_jsx_runtime3.jsxs)("span", { className: "text-[10px] font-black uppercase tracking-widest text-red-400/80", children: [
              /* @__PURE__ */ (0, import_jsx_runtime3.jsx)("i", { className: "bi bi-info-circle me-2" }),
              "If this persists, contact support"
            ] }) }),
            /* @__PURE__ */ (0, import_jsx_runtime3.jsx)(
              "button",
              {
                onClick: () => setIsOpen(false),
                className: `w-full py-4 rounded-2xl text-[11px] font-black uppercase tracking-[0.25em] text-white transition-all transform hover:-translate-y-1 shadow-xl ${config.btn}`,
                children: config.btnLabel
              }
            )
          ] })
        ] })
      ] })
    ] });
  }

  // views/react/components/NotificationBell.jsx
  var import_react4 = __toESM(require_react());
  var import_jsx_runtime4 = __toESM(require_jsx_runtime());
  function NotificationBell() {
    const [unreadCount, setUnreadCount] = (0, import_react4.useState)(0);
    const [notifications, setNotifications] = (0, import_react4.useState)([]);
    const [isOpen, setIsOpen] = (0, import_react4.useState)(false);
    const [loading, setLoading] = (0, import_react4.useState)(false);
    const dropdownRef = (0, import_react4.useRef)(null);
    const fetchNotifications = async () => {
      setLoading(true);
      try {
        const res = await fetch("/api/account/notifications?limit=8", {
          headers: { "Accept": "application/json" }
        });
        const payload = await res.json();
        if (res.ok) {
          setNotifications(payload.notifications || []);
          setUnreadCount(payload.unreadCount || 0);
        }
      } catch (err) {
        console.error("Failed to fetch notifications:", err);
      } finally {
        setLoading(false);
      }
    };
    (0, import_react4.useEffect)(() => {
      fetchNotifications();
      let ws;
      const connectWs = () => {
        const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        ws = new WebSocket(`${protocol}//${window.location.host}/ws/ui`);
        ws.onmessage = (event) => {
          try {
            const data32 = JSON.parse(event.data);
            if (data32.type === "notification:unread_count") {
              setUnreadCount(data32.unreadCount || 0);
            }
            if (data32.type === "notification:new" || data32.type === "notification:read") {
              fetchNotifications();
            }
          } catch (e) {
          }
        };
        ws.onclose = () => setTimeout(connectWs, 5e3);
      };
      connectWs();
      const handleClickOutside = (event) => {
        if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
          setIsOpen(false);
        }
      };
      document.addEventListener("mousedown", handleClickOutside);
      return () => {
        if (ws) ws.close();
        document.removeEventListener("mousedown", handleClickOutside);
      };
    }, []);
    const markRead = async (id) => {
      try {
        const res = await fetch(`/api/account/notifications/${id}/read`, { method: "POST" });
        if (res.ok) {
          const payload = await res.json();
          setUnreadCount(payload.unreadCount || 0);
          fetchNotifications();
        }
      } catch (err) {
      }
    };
    const markAllRead = async () => {
      try {
        const res = await fetch("/api/account/notifications/read-all", { method: "POST" });
        if (res.ok) {
          setUnreadCount(0);
          fetchNotifications();
        }
      } catch (err) {
      }
    };
    return /* @__PURE__ */ (0, import_jsx_runtime4.jsxs)("div", { className: "relative", ref: dropdownRef, children: [
      /* @__PURE__ */ (0, import_jsx_runtime4.jsxs)(
        "button",
        {
          onClick: () => setIsOpen(!isOpen),
          className: `relative p-2 rounded-full transition-all duration-300 ${isOpen ? "bg-primary-500/10 text-primary-400" : "text-neutral-400 hover:text-neutral-100 hover:bg-neutral-800"}`,
          children: [
            /* @__PURE__ */ (0, import_jsx_runtime4.jsx)("i", { className: "bi bi-bell text-lg" }),
            unreadCount > 0 && /* @__PURE__ */ (0, import_jsx_runtime4.jsxs)("span", { className: "absolute top-1.5 right-1.5 flex h-4 w-4", children: [
              /* @__PURE__ */ (0, import_jsx_runtime4.jsx)("span", { className: "animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" }),
              /* @__PURE__ */ (0, import_jsx_runtime4.jsx)("span", { className: "relative inline-flex rounded-full h-4 w-4 bg-red-500 text-[9px] font-black text-white items-center justify-center border-2 border-neutral-800", children: unreadCount > 9 ? "9+" : unreadCount })
            ] })
          ]
        }
      ),
      isOpen && /* @__PURE__ */ (0, import_jsx_runtime4.jsxs)("div", { className: "absolute right-0 mt-3 w-80 lg:w-96 bg-neutral-900/95 backdrop-blur-xl border border-neutral-800 rounded-2xl shadow-2xl overflow-hidden z-[100] animate-in slide-in-from-top-2 duration-200", children: [
        /* @__PURE__ */ (0, import_jsx_runtime4.jsxs)("div", { className: "px-5 py-4 border-b border-neutral-800 flex items-center justify-between bg-neutral-900/50", children: [
          /* @__PURE__ */ (0, import_jsx_runtime4.jsx)("span", { className: "text-xs font-black uppercase tracking-widest text-neutral-100", children: "Notifications" }),
          /* @__PURE__ */ (0, import_jsx_runtime4.jsx)(
            "button",
            {
              onClick: markAllRead,
              className: "text-[10px] font-bold text-primary-400 hover:text-primary-300 uppercase tracking-widest transition-colors",
              children: "Mark all read"
            }
          )
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime4.jsx)("div", { className: "max-h-[400px] overflow-y-auto no-scrollbar", children: loading && notifications.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime4.jsxs)("div", { className: "p-8 text-center", children: [
          /* @__PURE__ */ (0, import_jsx_runtime4.jsx)("div", { className: "w-6 h-6 border-2 border-neutral-700 border-t-primary-500 rounded-full animate-spin mx-auto mb-2" }),
          /* @__PURE__ */ (0, import_jsx_runtime4.jsx)("span", { className: "text-[10px] text-neutral-500 uppercase font-black", children: "Syncing..." })
        ] }) : notifications.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime4.jsxs)("div", { className: "p-10 text-center flex flex-col items-center gap-3", children: [
          /* @__PURE__ */ (0, import_jsx_runtime4.jsx)("div", { className: "w-12 h-12 bg-neutral-800/50 rounded-full flex items-center justify-center", children: /* @__PURE__ */ (0, import_jsx_runtime4.jsx)("i", { className: "bi bi-bell-slash text-2xl text-neutral-600" }) }),
          /* @__PURE__ */ (0, import_jsx_runtime4.jsx)("span", { className: "text-xs font-bold text-neutral-600 uppercase tracking-widest", children: "No notifications" })
        ] }) : /* @__PURE__ */ (0, import_jsx_runtime4.jsx)("div", { className: "divide-y divide-neutral-800/50", children: notifications.map((n) => /* @__PURE__ */ (0, import_jsx_runtime4.jsx)(
          "div",
          {
            className: `p-4 transition-colors hover:bg-neutral-800/30 ${!n.isRead ? "bg-primary-500/5 border-l-2 border-primary-500" : ""}`,
            children: /* @__PURE__ */ (0, import_jsx_runtime4.jsxs)("div", { className: "flex justify-between items-start gap-4", children: [
              /* @__PURE__ */ (0, import_jsx_runtime4.jsxs)("div", { className: "flex-1 min-w-0", children: [
                /* @__PURE__ */ (0, import_jsx_runtime4.jsx)("h4", { className: "text-xs font-bold text-neutral-200 mb-1 truncate", children: n.title }),
                /* @__PURE__ */ (0, import_jsx_runtime4.jsx)("p", { className: "text-[11px] text-neutral-500 leading-relaxed mb-2 whitespace-pre-wrap", children: n.message }),
                /* @__PURE__ */ (0, import_jsx_runtime4.jsxs)("div", { className: "flex items-center gap-3", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime4.jsx)("span", { className: "text-[9px] font-bold text-neutral-600 uppercase tracking-widest", children: new Date(n.createdAt).toLocaleDateString() }),
                  n.linkUrl && /* @__PURE__ */ (0, import_jsx_runtime4.jsx)(
                    "a",
                    {
                      href: n.linkUrl,
                      className: "text-[9px] font-black text-primary-400 hover:text-primary-300 uppercase tracking-widest",
                      children: "Open Link"
                    }
                  )
                ] })
              ] }),
              !n.isRead && /* @__PURE__ */ (0, import_jsx_runtime4.jsx)(
                "button",
                {
                  onClick: () => markRead(n.id),
                  className: "w-2 h-2 rounded-full bg-primary-500 mt-1",
                  title: "Mark as read"
                }
              )
            ] })
          },
          n.id
        )) }) }),
        /* @__PURE__ */ (0, import_jsx_runtime4.jsx)(
          "a",
          {
            href: "/notifications",
            className: "block w-full py-3 bg-neutral-900/80 border-t border-neutral-800 text-center text-[10px] font-black uppercase tracking-[0.2em] text-neutral-500 hover:text-neutral-100 hover:bg-neutral-800 transition-all",
            children: "View All Activity"
          }
        )
      ] })
    ] });
  }

  // views/react/components/GlobalSearch.jsx
  var import_react5 = __toESM(require_react());
  var import_jsx_runtime5 = __toESM(require_jsx_runtime());
  function GlobalSearch() {
    const [isOpen, setIsOpen] = (0, import_react5.useState)(false);
    const [query, setQuery] = (0, import_react5.useState)("");
    const inputRef = (0, import_react5.useRef)(null);
    const containerRef = (0, import_react5.useRef)(null);
    (0, import_react5.useEffect)(() => {
      if (window.location.pathname === "/") {
        const params = new URLSearchParams(window.location.search);
        const sq = params.get("search");
        if (sq) {
          setQuery(sq);
          setIsOpen(true);
        }
      }
    }, []);
    (0, import_react5.useEffect)(() => {
      if (window.location.pathname === "/") {
        window.dispatchEvent(new CustomEvent("dashboard-search", { detail: query }));
      }
    }, [query]);
    (0, import_react5.useEffect)(() => {
      function handleClickOutside(event) {
        if (containerRef.current && !containerRef.current.contains(event.target)) {
          if (!query) setIsOpen(false);
        }
      }
      document.addEventListener("mousedown", handleClickOutside);
      return () => document.removeEventListener("mousedown", handleClickOutside);
    }, [query]);
    const handleToggle = () => {
      if (isOpen && !query) {
        setIsOpen(false);
      } else {
        setIsOpen(true);
        setTimeout(() => inputRef.current?.focus(), 50);
      }
    };
    const handleKeyDown = (e) => {
      if (e.key === "Enter") {
        if (window.location.pathname !== "/") {
          window.location.href = `/?search=${encodeURIComponent(query)}`;
        } else {
          inputRef.current?.blur();
        }
      } else if (e.key === "Escape") {
        setQuery("");
        setIsOpen(false);
      }
    };
    return /* @__PURE__ */ (0, import_jsx_runtime5.jsxs)("div", { ref: containerRef, className: `relative flex items-center transition-all duration-300 ease-in-out ${isOpen ? "w-48 sm:w-64" : "w-10"}`, children: [
      /* @__PURE__ */ (0, import_jsx_runtime5.jsx)(
        "button",
        {
          type: "button",
          onClick: handleToggle,
          className: `absolute left-0 z-10 w-10 h-10 flex items-center justify-center transition-colors ${isOpen ? "text-primary-400" : "text-neutral-400 hover:text-neutral-100 hover:bg-neutral-700/50 rounded-full"}`,
          children: /* @__PURE__ */ (0, import_jsx_runtime5.jsx)("i", { className: "bi bi-search" })
        }
      ),
      /* @__PURE__ */ (0, import_jsx_runtime5.jsx)(
        "input",
        {
          ref: inputRef,
          type: "text",
          placeholder: "Search servers...",
          value: query,
          onChange: (e) => setQuery(e.target.value),
          onKeyDown: handleKeyDown,
          className: `w-full bg-neutral-800 border transition-all duration-300 h-10 py-2 pl-10 pr-4 text-sm text-neutral-200 placeholder-neutral-500 focus:outline-none focus:border-primary-500/50 focus:ring-1 focus:ring-primary-500/50 ${isOpen ? "border-neutral-700 rounded-xl opacity-100" : "border-transparent rounded-full opacity-0 pointer-events-none bg-transparent"}`
        }
      ),
      isOpen && query && /* @__PURE__ */ (0, import_jsx_runtime5.jsx)(
        "button",
        {
          type: "button",
          onClick: () => {
            setQuery("");
            inputRef.current?.focus();
          },
          className: "absolute right-3 text-neutral-500 hover:text-neutral-300",
          children: /* @__PURE__ */ (0, import_jsx_runtime5.jsx)("i", { className: "bi bi-x-circle-fill text-[11px]" })
        }
      )
    ] });
  }

  // views/react/components/ServerNavbar.jsx
  var import_react6 = __toESM(require_react());
  var import_jsx_runtime6 = __toESM(require_jsx_runtime());
  var NAV_ICONS = {
    console: "bi-terminal-fill",
    overview: "bi-speedometer2",
    performance: "bi-cpu-fill",
    smartalerts: "bi-bell-fill",
    activity: "bi-clock-history",
    timeline: "bi-list-ul",
    files: "bi-folder2-open",
    backups: "bi-cloud-arrow-down",
    dbs: "bi-database",
    network: "bi-diagram-3",
    users: "bi-people-fill",
    api: "bi-key-fill",
    schedules: "bi-calendar-event",
    startup: "bi-play-circle",
    mccenter: "bi-controller",
    mcinstaller: "bi-download",
    mounts: "bi-hdd-stack-fill",
    scaling: "bi-graph-up-arrow",
    policy: "bi-shield-lock-fill",
    metrics: "bi-bar-chart-fill",
    debuglogs: "bi-bug-fill",
    auditconsole: "bi-shield-shaded",
    recovery: "bi-life-preserver",
    ai: "bi-robot",
    "proxy-network": "bi-hdd-network-fill",
    macros: "bi-command"
  };
  var NAV_GROUPS = [
    { label: "Server", keys: ["console", "overview", "activity"] },
    { label: "Storage", keys: ["files", "backups", "dbs"] },
    { label: "Access", keys: ["network", "users", "api", "schedules"] },
    { label: "Config", keys: ["startup", "timeline", "mounts", "scaling", "policy", "macros"] },
    { label: "Diagnostics", keys: ["metrics", "debuglogs", "auditconsole", "performance", "smartalerts", "recovery", "ai", "proxy-network"] },
    { label: "Minecraft", keys: ["mccenter", "mcinstaller"] }
  ];
  function NavItem({ item, isProvisioning, blockedKeys }) {
    const isDisabled = isProvisioning && blockedKeys.includes(item.key);
    const icon = NAV_ICONS[item.key];
    return /* @__PURE__ */ (0, import_jsx_runtime6.jsxs)(
      "a",
      {
        href: isDisabled ? "#" : item.href,
        onClick: isDisabled ? (e) => e.preventDefault() : void 0,
        title: isDisabled ? `${item.label} \u2014 unavailable while server is provisioning` : item.label,
        className: [
          "relative flex items-center gap-2.5 px-4 h-full text-[12.5px] font-black uppercase tracking-widest",
          "whitespace-nowrap border-b-2 transition-all duration-150 select-none",
          isDisabled ? "text-neutral-700 border-transparent cursor-not-allowed opacity-60" : item.active ? "text-primary-400 border-primary-500 bg-primary-500/5" : "text-neutral-500 border-transparent hover:text-neutral-200 hover:border-neutral-500"
        ].join(" "),
        children: [
          icon && /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("i", { className: `bi ${icon} text-[16px] shrink-0` }),
          /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("span", { children: item.label }),
          isDisabled && /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("i", { className: "bi bi-lock-fill text-[8px] opacity-50 ml-0.5" })
        ]
      }
    );
  }
  function ServerNavbar({ pageData = {} }) {
    const items = Array.isArray(pageData.serverNavItems) ? pageData.serverNavItems : [];
    if (items.length === 0) return null;
    const status = pageData.server?.status || "";
    const isProvisioning = ["installing", "reinstalling"].includes(status);
    const blockedKeys = ["files", "backups", "dbs", "network", "users", "api", "schedules", "startup", "timeline"];
    const [mobileOpen, setMobileOpen] = (0, import_react6.useState)(false);
    const activeGroups = NAV_GROUPS.map((group) => ({
      ...group,
      items: group.keys.map((k) => items.find((i) => i.key === k)).filter(Boolean)
    })).filter((g) => g.items.length > 0);
    const activeItem = items.find((i) => i.active);
    return /* @__PURE__ */ (0, import_jsx_runtime6.jsxs)(import_jsx_runtime6.Fragment, { children: [
      /* @__PURE__ */ (0, import_jsx_runtime6.jsxs)("nav", { className: "hidden md:flex bg-neutral-900 border-b border-neutral-800 w-full h-14 items-center px-6 lg:px-10 overflow-x-auto no-scrollbar gap-1.5", children: [
        activeGroups.map((group, gIdx) => /* @__PURE__ */ (0, import_jsx_runtime6.jsxs)(import_react6.default.Fragment, { children: [
          gIdx > 0 && /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("div", { className: "h-6 w-px bg-neutral-700/60 mx-1 shrink-0" }),
          /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("div", { className: "flex items-center h-full", children: group.items.map((item) => /* @__PURE__ */ (0, import_jsx_runtime6.jsx)(
            NavItem,
            {
              item,
              isProvisioning,
              blockedKeys
            },
            item.key
          )) })
        ] }, group.label)),
        pageData.server?.name && /* @__PURE__ */ (0, import_jsx_runtime6.jsxs)("div", { className: "ml-auto pl-4 shrink-0 flex items-center gap-2", children: [
          /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("span", { className: `w-2 h-2 rounded-full shrink-0 ${status === "running" ? "bg-green-500" : status === "starting" ? "bg-yellow-500 animate-pulse" : status === "stopping" ? "bg-orange-500 animate-pulse" : isProvisioning ? "bg-blue-500 animate-pulse" : "bg-neutral-600"}` }),
          /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("span", { className: "text-[11px] font-black text-neutral-500 uppercase tracking-widest max-w-[180px] truncate", children: pageData.server.name })
        ] })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("div", { className: "md:hidden bg-neutral-900 border-b border-neutral-800 w-full h-12 flex items-center px-4 overflow-x-auto no-scrollbar gap-1 relative", children: activeGroups.map((group, gIdx) => /* @__PURE__ */ (0, import_jsx_runtime6.jsxs)(import_react6.default.Fragment, { children: [
        gIdx > 0 && /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("div", { className: "h-4 w-px bg-neutral-800 mx-1 shrink-0" }),
        /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("div", { className: "flex items-center h-full", children: group.items.map((item) => {
          const isDisabled = isProvisioning && blockedKeys.includes(item.key);
          const icon = NAV_ICONS[item.key];
          return /* @__PURE__ */ (0, import_jsx_runtime6.jsxs)(
            "a",
            {
              href: isDisabled ? "#" : item.href,
              onClick: isDisabled ? (e) => e.preventDefault() : void 0,
              className: [
                "relative flex items-center gap-2 px-3 h-full text-[10px] font-black uppercase tracking-widest",
                "whitespace-nowrap transition-all duration-150 select-none border-b-2",
                isDisabled ? "text-neutral-700 border-transparent cursor-not-allowed opacity-60" : item.active ? "text-primary-400 border-primary-500 bg-primary-500/5" : "text-neutral-500 border-transparent hover:text-neutral-300"
              ].join(" "),
              children: [
                icon && /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("i", { className: `bi ${icon} text-[14px] shrink-0` }),
                /* @__PURE__ */ (0, import_jsx_runtime6.jsx)("span", { children: item.label })
              ]
            },
            item.key
          );
        }) })
      ] }, group.label)) })
    ] });
  }

  // views/react/components/SponsorModal.jsx
  var import_react7 = __toESM(require_react());
  var import_jsx_runtime7 = __toESM(require_jsx_runtime());
  function SponsorModal({ isOpen, onClose }) {
    if (!isOpen) return null;
    const sponsorLinks = [
      {
        name: "BuyMeACoffee",
        handle: "mihai14launcher",
        url: "https://www.buymeacoffee.com/mihai14launcher",
        icon: "bi-cup-hot-fill",
        color: "bg-[#FFDD00] text-black"
      },
      {
        name: "Ko-fi",
        handle: "mihai14launcher",
        url: "https://ko-fi.com/mihai14launcher",
        icon: "bi-patch-check-fill",
        color: "bg-[#13C3FF] text-white"
      },
      {
        name: "GitHub Sponsors",
        handle: "mihai209",
        url: "https://github.com/sponsors/mihai209",
        icon: "bi-heart-fill",
        color: "bg-[#ea4aaa] text-white"
      }
    ];
    return /* @__PURE__ */ (0, import_jsx_runtime7.jsxs)("div", { className: "fixed inset-0 z-[10000] flex items-center justify-center p-4", children: [
      /* @__PURE__ */ (0, import_jsx_runtime7.jsx)("div", { className: "absolute inset-0 bg-black/80 backdrop-blur-xl transition-opacity", onClick: onClose }),
      /* @__PURE__ */ (0, import_jsx_runtime7.jsxs)("div", { className: "relative w-full max-w-lg bg-neutral-900 border border-neutral-800 rounded-[2.5rem] overflow-hidden shadow-2xl animate-in zoom-in duration-300", children: [
        /* @__PURE__ */ (0, import_jsx_runtime7.jsx)("div", { className: "h-1.5 w-full bg-gradient-to-r from-primary-600 via-purple-500 to-pink-500" }),
        /* @__PURE__ */ (0, import_jsx_runtime7.jsxs)("div", { className: "p-8 pt-10 text-center", children: [
          /* @__PURE__ */ (0, import_jsx_runtime7.jsx)(
            "button",
            {
              onClick: onClose,
              className: "absolute top-6 right-6 text-neutral-500 hover:text-white transition-colors",
              children: /* @__PURE__ */ (0, import_jsx_runtime7.jsx)("i", { className: "bi bi-x-lg" })
            }
          ),
          /* @__PURE__ */ (0, import_jsx_runtime7.jsxs)("div", { className: "relative w-32 h-32 mx-auto mb-6 rounded-full flex items-center justify-center border-2 border-dashed border-primary-500/30 bg-primary-500/5", children: [
            /* @__PURE__ */ (0, import_jsx_runtime7.jsx)(
              "img",
              {
                src: "/assets/happy-rocky.png",
                alt: "Happy Rocky",
                className: "w-24 h-24 object-contain relative z-10 animate-bounce group-hover:animate-none"
              }
            ),
            /* @__PURE__ */ (0, import_jsx_runtime7.jsx)("div", { className: "absolute inset-0 rounded-full blur-2xl opacity-20 bg-primary-500" })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime7.jsx)("h3", { className: "text-2xl font-black uppercase tracking-[0.1em] mb-3 text-white", children: "Support the Creator" }),
          /* @__PURE__ */ (0, import_jsx_runtime7.jsxs)("p", { className: "text-neutral-400 font-medium leading-relaxed mb-8 px-4 text-sm", children: [
            "CPanel Rocky and the Connector are developed for ",
            /* @__PURE__ */ (0, import_jsx_runtime7.jsx)("strong", { children: "free" }),
            ' during my spare time. If you find this project useful, a small "thank you" gift would mean a lot!'
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime7.jsx)("div", { className: "grid grid-cols-1 gap-4 mb-4", children: sponsorLinks.map((link) => /* @__PURE__ */ (0, import_jsx_runtime7.jsxs)(
            "a",
            {
              href: link.url,
              target: "_blank",
              rel: "noopener noreferrer",
              className: `flex items-center justify-between p-4 rounded-2xl transition-all hover:-translate-y-1 shadow-lg group ${link.color}`,
              children: [
                /* @__PURE__ */ (0, import_jsx_runtime7.jsxs)("div", { className: "flex items-center gap-4", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime7.jsx)("div", { className: "w-10 h-10 rounded-xl bg-black/10 flex items-center justify-center", children: /* @__PURE__ */ (0, import_jsx_runtime7.jsx)("i", { className: `bi ${link.icon} text-xl` }) }),
                  /* @__PURE__ */ (0, import_jsx_runtime7.jsxs)("div", { className: "text-left", children: [
                    /* @__PURE__ */ (0, import_jsx_runtime7.jsx)("div", { className: "text-[10px] font-black uppercase tracking-widest opacity-80", children: link.name }),
                    /* @__PURE__ */ (0, import_jsx_runtime7.jsxs)("div", { className: "font-bold", children: [
                      "@",
                      link.handle
                    ] })
                  ] })
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime7.jsx)("i", { className: "bi bi-arrow-right text-lg opacity-0 group-hover:opacity-100 transition-opacity" })
              ]
            },
            link.name
          )) })
        ] })
      ] })
    ] });
  }

  // views/react/components/FooterLegalModal.jsx
  var import_react8 = __toESM(require_react());
  var import_jsx_runtime8 = __toESM(require_jsx_runtime());
  function FooterLegalModal({ isOpen, onClose }) {
    if (!isOpen) return null;
    return /* @__PURE__ */ (0, import_jsx_runtime8.jsxs)("div", { className: "fixed inset-0 z-[10000] flex items-center justify-center p-4", children: [
      /* @__PURE__ */ (0, import_jsx_runtime8.jsx)("div", { className: "absolute inset-0 bg-black/80 backdrop-blur-xl transition-opacity", onClick: onClose }),
      /* @__PURE__ */ (0, import_jsx_runtime8.jsxs)("div", { className: "relative w-full max-w-2xl bg-neutral-900 border border-neutral-800 rounded-[2.5rem] overflow-hidden shadow-2xl animate-in zoom-in duration-300 flex flex-col max-h-[90vh]", children: [
        /* @__PURE__ */ (0, import_jsx_runtime8.jsx)("div", { className: "h-1.5 w-full bg-primary-600" }),
        /* @__PURE__ */ (0, import_jsx_runtime8.jsxs)("div", { className: "p-8 border-b border-neutral-800 flex justify-between items-center bg-neutral-900/50", children: [
          /* @__PURE__ */ (0, import_jsx_runtime8.jsxs)("div", { className: "flex items-center gap-4", children: [
            /* @__PURE__ */ (0, import_jsx_runtime8.jsx)("div", { className: "w-12 h-12 rounded-2xl bg-primary-500/10 flex items-center justify-center border border-primary-500/20 shadow-inner", children: /* @__PURE__ */ (0, import_jsx_runtime8.jsx)("img", { src: "/assets/rocky-security.png", alt: "Security Rocky", className: "w-10 h-10 object-contain" }) }),
            /* @__PURE__ */ (0, import_jsx_runtime8.jsxs)("div", { children: [
              /* @__PURE__ */ (0, import_jsx_runtime8.jsx)("h3", { className: "text-xl font-black uppercase tracking-[0.15em] text-white", children: "Licensing & Support" }),
              /* @__PURE__ */ (0, import_jsx_runtime8.jsx)("p", { className: "text-[10px] font-bold text-neutral-500 uppercase tracking-widest mt-1", children: "Official Project Documentation" })
            ] })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime8.jsx)(
            "button",
            {
              onClick: onClose,
              className: "w-10 h-10 flex items-center justify-center rounded-xl bg-neutral-800 text-neutral-400 hover:text-white transition-colors",
              children: /* @__PURE__ */ (0, import_jsx_runtime8.jsx)("i", { className: "bi bi-x-lg" })
            }
          )
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime8.jsxs)("div", { className: "p-8 overflow-y-auto custom-scrollbar space-y-8", children: [
          /* @__PURE__ */ (0, import_jsx_runtime8.jsxs)("section", { children: [
            /* @__PURE__ */ (0, import_jsx_runtime8.jsxs)("div", { className: "flex items-center gap-3 mb-3", children: [
              /* @__PURE__ */ (0, import_jsx_runtime8.jsx)("div", { className: "w-1.5 h-6 bg-primary-500 rounded-full" }),
              /* @__PURE__ */ (0, import_jsx_runtime8.jsx)("h4", { className: "text-sm font-black uppercase tracking-[0.2em] text-primary-400", children: "MIT License" })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime8.jsx)("p", { className: "text-sm text-neutral-300 leading-relaxed font-medium", children: "CPanel is distributed under the MIT License. You are free to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the software, subject to the conditions of the license." })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime8.jsxs)("section", { children: [
            /* @__PURE__ */ (0, import_jsx_runtime8.jsxs)("div", { className: "flex items-center gap-3 mb-3", children: [
              /* @__PURE__ */ (0, import_jsx_runtime8.jsx)("div", { className: "w-1.5 h-6 bg-yellow-500 rounded-full" }),
              /* @__PURE__ */ (0, import_jsx_runtime8.jsx)("h4", { className: "text-sm font-black uppercase tracking-[0.2em] text-yellow-500", children: "Disclaimer" })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime8.jsxs)("p", { className: "text-sm text-neutral-300 leading-relaxed font-medium", children: [
              "CPanel is not associated with ",
              /* @__PURE__ */ (0, import_jsx_runtime8.jsx)("strong", { children: "pterodactyl.io" }),
              " or the Pterodactyl Panel. This software is merely inspired by its design and concepts, but remains an independent project."
            ] })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime8.jsxs)("section", { className: "p-6 bg-neutral-800/50 border border-neutral-700/50 rounded-3xl relative overflow-hidden group", children: [
            /* @__PURE__ */ (0, import_jsx_runtime8.jsx)("div", { className: "absolute top-0 right-0 p-4 opacity-5 group-hover:opacity-10 transition-opacity", children: /* @__PURE__ */ (0, import_jsx_runtime8.jsx)("i", { className: "bi bi-shield-lock-fill text-6xl" }) }),
            /* @__PURE__ */ (0, import_jsx_runtime8.jsxs)("div", { className: "flex items-center gap-3 mb-4", children: [
              /* @__PURE__ */ (0, import_jsx_runtime8.jsx)("div", { className: "w-1.5 h-6 bg-red-500 rounded-full" }),
              /* @__PURE__ */ (0, import_jsx_runtime8.jsx)("h4", { className: "text-sm font-black uppercase tracking-[0.2em] text-red-500", children: "Support & Modification Policy" })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime8.jsxs)("div", { className: "space-y-4 relative z-10", children: [
              /* @__PURE__ */ (0, import_jsx_runtime8.jsx)("p", { className: "text-sm text-neutral-200 leading-relaxed font-semibold", children: "You are free to modify any assets, styles, and logic within the panel and connector to suit your needs." }),
              /* @__PURE__ */ (0, import_jsx_runtime8.jsx)("div", { className: "p-4 bg-red-500/10 border border-red-500/20 rounded-2xl", children: /* @__PURE__ */ (0, import_jsx_runtime8.jsx)("p", { className: "text-sm text-red-400 leading-relaxed font-bold", children: "IMPORTANT: Removing or modifying the copyright notices in the footer will result in the immediate and automatic termination of support from the developer." }) }),
              /* @__PURE__ */ (0, import_jsx_runtime8.jsxs)("p", { className: "text-sm text-neutral-400 leading-relaxed font-medium italic", children: [
                "Support is provided solely by ",
                /* @__PURE__ */ (0, import_jsx_runtime8.jsx)("strong", { children: "Mihai209" }),
                " to users who maintain the original branding in the footer. By using this software, you agree to keep the copyright links visible."
              ] })
            ] })
          ] })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime8.jsx)("div", { className: "p-8 bg-neutral-800/50 flex justify-end", children: /* @__PURE__ */ (0, import_jsx_runtime8.jsx)(
          "button",
          {
            onClick: onClose,
            className: "px-8 py-3 bg-neutral-800 hover:bg-neutral-700 text-neutral-300 rounded-xl text-[10px] font-black uppercase tracking-[0.2em] border border-neutral-700 transition-all font-bold",
            children: "Close Document"
          }
        ) })
      ] })
    ] });
  }

  // views/react/components/ReactAppShell.jsx
  var import_jsx_runtime9 = __toESM(require_jsx_runtime());
  function InternalTopAction({ to, icon, title }) {
    const location = useLocation();
    const isActive = location.pathname === to;
    return /* @__PURE__ */ (0, import_jsx_runtime9.jsx)(
      "a",
      {
        href: to,
        title,
        className: `text-neutral-400 hover:text-neutral-100 transition-colors p-2 rounded-full hover:bg-neutral-700 ${isActive ? "text-neutral-100 bg-neutral-700" : ""}`,
        children: /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("i", { className: `bi ${icon}` })
      }
    );
  }
  function PrimaryNavLink({ to, label }) {
    const location = useLocation();
    const isActive = to === "/" ? location.pathname === "/" : location.pathname.startsWith(to);
    return /* @__PURE__ */ (0, import_jsx_runtime9.jsx)(
      "a",
      {
        href: to,
        className: `px-4 py-3 text-sm font-semibold transition-colors ${isActive ? "text-white border-b-2 border-primary-500" : "text-neutral-400 hover:text-white"}`,
        children: label
      }
    );
  }
  function ReactAppShell({
    pageData = {},
    subtitle = "React view beta",
    pageClassName = "",
    shellClassName = "",
    children
  }) {
    const brandImage = resolveBrandImage(pageData);
    const userAvatar = resolveUserAvatar(pageData.user || {}, brandImage);
    const [mobileNavOpen, setMobileNavOpen] = import_react9.default.useState(false);
    const [sponsorModalOpen, setSponsorModalOpen] = import_react9.default.useState(false);
    const [legalModalOpen, setLegalModalOpen] = import_react9.default.useState(false);
    const serverNavItems = Array.isArray(pageData.serverNavItems) ? pageData.serverNavItems : [];
    const shellNavItems = [
      { to: ReactRoutes.dashboard, label: "Dashboard" },
      { to: ReactRoutes.account, label: "Account" }
    ];
    const isProvisioning = ["installing", "reinstalling"].includes(pageData.server?.status);
    const blockedPageKeys = ["files", "backups", "dbs", "network", "users", "api", "schedules", "startup", "timeline"];
    const activeNavItem = serverNavItems.find((item) => item.active);
    const shouldBlock = isProvisioning && activeNavItem && blockedPageKeys.includes(activeNavItem.key);
    return /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)(
      "div",
      {
        className: `min-h-screen text-neutral-200 flex flex-col transition-all duration-700 ${pageClassName || ""}`,
        style: {
          background: "transparent"
        },
        children: [
          /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)("div", { className: "bg-neutral-800 border-b border-neutral-700 w-full flex items-center justify-between px-4 lg:px-8 h-16 shrink-0 sticky top-0 z-40 shadow-md", children: [
            /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)("div", { className: "flex items-center gap-4", children: [
              /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("img", { src: brandImage, alt: pageData.brandName || "CPanel", className: "w-8 h-8 rounded shrink-0" }),
              /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)("div", { children: [
                /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("div", { className: "text-lg font-bold text-neutral-100 leading-tight", children: pageData.brandName || "CPanel" }),
                /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("div", { className: "text-xs text-neutral-400 font-semibold", children: subtitle })
              ] })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)("nav", { className: "hidden md:flex items-center h-full ml-10 flex-1", children: [
              shellNavItems.map((item) => /* @__PURE__ */ (0, import_jsx_runtime9.jsx)(PrimaryNavLink, { to: item.to, label: item.label }, item.to)),
              /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("div", { className: "flex-1" })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)("div", { className: "flex items-center gap-3 md:gap-4 shrink-0", children: [
              /* @__PURE__ */ (0, import_jsx_runtime9.jsx)(
                "button",
                {
                  type: "button",
                  className: "md:hidden text-neutral-400 hover:text-neutral-100 p-2",
                  title: "Toggle navigation",
                  onClick: () => setMobileNavOpen(!mobileNavOpen),
                  children: /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("i", { className: "bi bi-list text-2xl" })
                }
              ),
              /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)("div", { className: "hidden md:flex items-center gap-2", children: [
                pageData.user?.isAdmin && /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)(import_jsx_runtime9.Fragment, { children: [
                  /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("a", { className: "text-neutral-400 hover:text-neutral-100 transition-colors p-2 rounded-full hover:bg-neutral-700", href: ReactRoutes.admin, title: "Admin Area", children: /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("i", { className: "bi bi-gear-fill" }) }),
                  /* @__PURE__ */ (0, import_jsx_runtime9.jsx)(InternalTopAction, { to: ReactRoutes.connectorsCheck, icon: "bi-cpu", title: "Connectors Check" })
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("div", { className: "h-6 w-px bg-neutral-700 mx-1" }),
                /* @__PURE__ */ (0, import_jsx_runtime9.jsx)(GlobalSearch, {}),
                /* @__PURE__ */ (0, import_jsx_runtime9.jsx)(InternalTopAction, { to: ReactRoutes.themes, icon: "bi-palette-fill", title: "Themes" }),
                /* @__PURE__ */ (0, import_jsx_runtime9.jsx)(InternalTopAction, { to: ReactRoutes.rewards, icon: "bi-coin", title: "Rewards" }),
                /* @__PURE__ */ (0, import_jsx_runtime9.jsx)(InternalTopAction, { to: ReactRoutes.afk, icon: "bi-hourglass-split", title: "AFK Timer" }),
                /* @__PURE__ */ (0, import_jsx_runtime9.jsx)(NotificationBell, {}),
                /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("div", { className: "h-6 w-px bg-neutral-700 mx-2" }),
                /* @__PURE__ */ (0, import_jsx_runtime9.jsx)(InternalTopAction, { to: ReactRoutes.outdatedFeatures, icon: "bi-sliders", title: "Outdated Features" }),
                /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("a", { className: "text-neutral-400 hover:text-neutral-100 transition-colors p-2 rounded-full hover:bg-neutral-700", href: ReactRoutes.changeView, title: "Exit Beta", children: /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("i", { className: "bi bi-door-open" }) })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)("div", { className: "flex items-center gap-3 pl-4 border-l border-neutral-700", children: [
                /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("span", { className: "text-sm font-semibold hidden md:block", children: pageData.user?.username || "Guest" }),
                /* @__PURE__ */ (0, import_jsx_runtime9.jsx)(
                  "img",
                  {
                    src: userAvatar,
                    alt: "User Avatar",
                    className: "w-8 h-8 rounded-full border border-neutral-600"
                  }
                )
              ] })
            ] })
          ] }),
          mobileNavOpen && /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)("div", { className: "md:hidden bg-neutral-800 border-b border-neutral-700 flex flex-col py-2", children: [
            shellNavItems.map((item) => {
              const isActive = item.to === "/" ? window.location.pathname === "/" : window.location.pathname.startsWith(item.to);
              return /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)(
                "a",
                {
                  href: item.to,
                  className: `px-5 py-3 text-sm font-bold flex items-center gap-3 transition-colors ${isActive ? "text-primary-400 bg-primary-500/5" : "text-neutral-400 hover:text-white"}`,
                  children: [
                    /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("i", { className: `bi ${item.to === ReactRoutes.dashboard ? "bi-grid-fill" : "bi-person-fill"} text-lg` }),
                    item.label
                  ]
                },
                item.to
              );
            }),
            /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("div", { className: "h-px bg-neutral-700/50 mx-5 my-1" }),
            /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)("a", { href: ReactRoutes.themes, className: `px-5 py-3 text-sm font-bold flex items-center gap-3 transition-colors ${window.location.pathname === ReactRoutes.themes ? "text-primary-400 bg-primary-500/5" : "text-neutral-400 hover:text-white"}`, children: [
              /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("i", { className: "bi bi-palette-fill text-lg" }),
              "Themes"
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)("a", { href: ReactRoutes.rewards, className: `px-5 py-3 text-sm font-bold flex items-center gap-3 transition-colors ${window.location.pathname === ReactRoutes.rewards ? "text-primary-400 bg-primary-500/5" : "text-neutral-400 hover:text-white"}`, children: [
              /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("i", { className: "bi bi-coin text-lg" }),
              "Rewards"
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)("a", { href: ReactRoutes.afk, className: `px-5 py-3 text-sm font-bold flex items-center gap-3 transition-colors ${window.location.pathname === ReactRoutes.afk ? "text-primary-400 bg-primary-500/5" : "text-neutral-400 hover:text-white"}`, children: [
              /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("i", { className: "bi bi-hourglass-split text-lg" }),
              "AFK Timer"
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("div", { className: "h-px bg-neutral-700/50 mx-5 my-1" }),
            /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)("a", { href: ReactRoutes.outdatedFeatures, className: `px-5 py-3 text-sm font-bold flex items-center gap-3 transition-colors ${window.location.pathname === ReactRoutes.outdatedFeatures ? "text-primary-400 bg-primary-500/5" : "text-neutral-400 hover:text-white"}`, children: [
              /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("i", { className: "bi bi-sliders text-lg" }),
              "Outdated Features"
            ] }),
            pageData.user?.isAdmin && /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)(import_jsx_runtime9.Fragment, { children: [
              /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)("a", { href: ReactRoutes.admin, className: "px-5 py-3 text-sm font-bold flex items-center gap-3 text-neutral-400 hover:text-white transition-colors", children: [
                /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("i", { className: "bi bi-gear-fill text-lg" }),
                "Admin Panel"
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)("a", { href: ReactRoutes.connectorsCheck, className: `px-5 py-3 text-sm font-bold flex items-center gap-3 transition-colors ${window.location.pathname === ReactRoutes.connectorsCheck ? "text-primary-400 bg-primary-500/5" : "text-neutral-400 hover:text-white"}`, children: [
                /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("i", { className: "bi bi-cpu text-lg" }),
                "Connectors Check"
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("div", { className: "h-px bg-neutral-700/50 mx-5 my-1" })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)("a", { href: ReactRoutes.changeView, className: "px-5 py-3 text-sm font-bold flex items-center gap-3 text-neutral-400 hover:text-white transition-colors", children: [
              /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("i", { className: "bi bi-door-open text-lg" }),
              "Exit Beta Mode"
            ] })
          ] }),
          serverNavItems.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime9.jsx)(ServerNavbar, { pageData }),
          /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("main", { className: "flex-1 w-full bg-neutral-900", children: shouldBlock ? /* @__PURE__ */ (0, import_jsx_runtime9.jsx)(ProvisioningBarrier, { status: pageData.server.status, containerId: pageData.server.containerId }) : children }),
          /* @__PURE__ */ (0, import_jsx_runtime9.jsx)(GlobalStatusModal, {}),
          /* @__PURE__ */ (0, import_jsx_runtime9.jsx)(SponsorModal, { isOpen: sponsorModalOpen, onClose: () => setSponsorModalOpen(false) }),
          /* @__PURE__ */ (0, import_jsx_runtime9.jsx)(FooterLegalModal, { isOpen: legalModalOpen, onClose: () => setLegalModalOpen(false) }),
          /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)("footer", { className: "w-full py-12 border-t border-neutral-800 bg-neutral-900 mt-auto overflow-hidden relative", children: [
            /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("div", { className: "absolute top-0 left-1/2 -translate-x-1/2 w-full max-w-4xl h-px bg-gradient-to-r from-transparent via-neutral-700/50 to-transparent" }),
            /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)("div", { className: "px-4 lg:px-8 max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-center gap-10", children: [
              /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)("div", { className: "flex flex-col items-center md:items-start gap-4", children: [
                /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)("div", { className: "flex items-center gap-4", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("img", { src: brandImage, alt: "Brand", className: "w-6 h-6 grayscale opacity-30" }),
                  /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("span", { className: "text-[10px] font-black text-neutral-500 uppercase tracking-[0.3em]", children: "CPanel Rocky \xA9 2026" })
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)("div", { className: "flex items-center gap-2", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)(
                    "a",
                    {
                      href: "https://github.com/mihai209",
                      target: "_blank",
                      rel: "noopener noreferrer",
                      className: "px-4 py-2 rounded-xl bg-neutral-800/50 hover:bg-neutral-800 text-[10px] font-bold text-neutral-500 hover:text-white transition-all border border-neutral-700/30 flex items-center gap-2",
                      children: [
                        /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("i", { className: "bi bi-github" }),
                        "Mihai209"
                      ]
                    }
                  ),
                  /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)(
                    "a",
                    {
                      href: "https://cpanel-rocky.netlify.app/",
                      target: "_blank",
                      rel: "noopener noreferrer",
                      className: "px-4 py-2 rounded-xl bg-neutral-800/50 hover:bg-neutral-800 text-[10px] font-bold text-neutral-500 hover:text-white transition-all border border-neutral-700/30 flex items-center gap-2",
                      children: [
                        /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("i", { className: "bi bi-globe" }),
                        "Project Website"
                      ]
                    }
                  )
                ] })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)("div", { className: "flex items-center gap-3", children: [
                /* @__PURE__ */ (0, import_jsx_runtime9.jsxs)(
                  "button",
                  {
                    onClick: () => setSponsorModalOpen(true),
                    className: "group flex items-center gap-3 px-6 py-3 rounded-2xl bg-primary-600/10 hover:bg-primary-600 text-primary-400 hover:text-white transition-all duration-300 border border-primary-500/20 active:scale-95",
                    children: [
                      /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("i", { className: "bi bi-heart-fill animate-pulse group-hover:animate-none" }),
                      /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("span", { className: "text-[10px] font-black uppercase tracking-[0.2em]", children: "Sponsor Project" })
                    ]
                  }
                ),
                /* @__PURE__ */ (0, import_jsx_runtime9.jsx)(
                  "button",
                  {
                    onClick: () => setLegalModalOpen(true),
                    className: "p-3 rounded-2xl bg-neutral-800/50 hover:bg-neutral-800 text-neutral-500 hover:text-white transition-all border border-neutral-700/30 active:scale-95",
                    title: "Licensing & Support Policy",
                    children: /* @__PURE__ */ (0, import_jsx_runtime9.jsx)("i", { className: "bi bi-info-circle-fill text-lg" })
                  }
                )
              ] })
            ] })
          ] })
        ]
      }
    );
  }

  // views/react/components/PageContentBlock.jsx
  var import_react10 = __toESM(require_react());
  var import_jsx_runtime10 = __toESM(require_jsx_runtime());
  function PageContentBlock({ title, children, className = "" }) {
    import_react10.default.useEffect(() => {
      if (title) {
        document.title = `${title} - CPanel`;
      }
    }, [title]);
    return /* @__PURE__ */ (0, import_jsx_runtime10.jsxs)("div", { className: `w-full max-w-7xl mx-auto px-4 md:px-6 lg:px-8 py-6 ${className}`, children: [
      title && /* @__PURE__ */ (0, import_jsx_runtime10.jsx)("div", { className: "mb-6 flex justify-between items-center", children: /* @__PURE__ */ (0, import_jsx_runtime10.jsx)("h1", { className: "text-2xl font-bold text-neutral-100", children: title }) }),
      /* @__PURE__ */ (0, import_jsx_runtime10.jsx)("div", { className: "w-full", children })
    ] });
  }

  // views/react/components/ServerRow.jsx
  var import_react11 = __toESM(require_react());
  var import_jsx_runtime11 = __toESM(require_jsx_runtime());
  function formatLimit(mb) {
    if (!mb || mb <= 0) return "N/A";
    if (mb >= 1024) return `${(mb / 1024).toFixed(mb % 1024 === 0 ? 0 : 1)} GB`;
    return `${mb} MB`;
  }
  function ServerRow({ server, isAdminDashboard, showResourcePills = true }) {
    const rawStatus = String(server.status || "unknown").toLowerCase();
    let statusColor = "bg-neutral-600 text-neutral-200";
    let statusLabel = rawStatus;
    if (server.isSuspended) {
      statusColor = "bg-red-600 text-white";
      statusLabel = "suspended";
    } else if (rawStatus === "running") {
      statusColor = "bg-green-600 text-white";
    } else if (rawStatus === "stopped") {
      statusColor = "bg-red-600 text-white";
    } else if (rawStatus === "installing") {
      statusColor = "bg-yellow-500 text-neutral-900";
    }
    return /* @__PURE__ */ (0, import_jsx_runtime11.jsxs)("div", { className: "bg-neutral-900/50 backdrop-blur-sm border border-neutral-800/80 rounded-[1.5rem] p-6 hover:border-primary-500/30 hover:bg-neutral-800/40 transition-all duration-300 flex flex-col lg:flex-row lg:items-center justify-between group shadow-lg hover:shadow-primary-900/5", children: [
      /* @__PURE__ */ (0, import_jsx_runtime11.jsxs)("div", { className: "flex-1 min-w-0", children: [
        /* @__PURE__ */ (0, import_jsx_runtime11.jsxs)("div", { className: "flex items-center gap-4 mb-2", children: [
          /* @__PURE__ */ (0, import_jsx_runtime11.jsx)("div", { className: `w-2.5 h-2.5 rounded-full ${server.isSuspended ? "bg-red-500" : rawStatus === "running" ? "bg-green-500" : "bg-neutral-700"} shadow-[0_0_10px_rgba(34,197,94,0.3)]` }),
          /* @__PURE__ */ (0, import_jsx_runtime11.jsx)("h3", { className: "text-lg font-black text-neutral-100 truncate group-hover:text-primary-400 transition-colors tracking-tight", children: server.name }),
          /* @__PURE__ */ (0, import_jsx_runtime11.jsx)("span", { className: `text-[10px] px-3 py-1 rounded-full font-black uppercase tracking-[0.1em] ${statusColor} bg-opacity-10 ring-1 ring-inset ring-current`, children: statusLabel })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime11.jsxs)("div", { className: "flex items-center gap-3 mt-2", children: [
          /* @__PURE__ */ (0, import_jsx_runtime11.jsx)("span", { className: "text-[10px] text-neutral-500 font-black uppercase tracking-widest bg-neutral-800/50 px-2 py-0.5 rounded", children: server.containerId?.substring(0, 12) }),
          isAdminDashboard && server.owner && /* @__PURE__ */ (0, import_jsx_runtime11.jsxs)("div", { className: "flex items-center gap-2 pl-3 border-l border-neutral-800", children: [
            /* @__PURE__ */ (0, import_jsx_runtime11.jsx)("i", { className: "bi bi-person-badge text-xs text-primary-500/70" }),
            /* @__PURE__ */ (0, import_jsx_runtime11.jsx)("span", { className: "text-[10px] font-black text-neutral-400 uppercase tracking-widest", children: server.owner.username })
          ] })
        ] })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime11.jsxs)("div", { className: "mt-6 lg:mt-0 flex flex-wrap sm:flex-nowrap items-center gap-6 lg:ml-8 shrink-0", children: [
        showResourcePills && /* @__PURE__ */ (0, import_jsx_runtime11.jsxs)(import_jsx_runtime11.Fragment, { children: [
          /* @__PURE__ */ (0, import_jsx_runtime11.jsxs)("div", { className: "flex-1 sm:flex-none", children: [
            /* @__PURE__ */ (0, import_jsx_runtime11.jsx)("div", { className: "text-[10px] text-neutral-500 uppercase font-black tracking-widest mb-1 opacity-60", children: "CPU Usage" }),
            /* @__PURE__ */ (0, import_jsx_runtime11.jsx)("div", { className: "text-sm font-black text-neutral-200 tabular-nums", children: server.cpu ? `${server.cpu}%` : "0%" })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime11.jsx)("div", { className: "w-px h-8 bg-neutral-800 hidden sm:block" }),
          /* @__PURE__ */ (0, import_jsx_runtime11.jsxs)("div", { className: "flex-1 sm:flex-none", children: [
            /* @__PURE__ */ (0, import_jsx_runtime11.jsx)("div", { className: "text-[10px] text-neutral-500 uppercase font-black tracking-widest mb-1 opacity-60", children: "Memory" }),
            /* @__PURE__ */ (0, import_jsx_runtime11.jsx)("div", { className: "text-sm font-black text-neutral-200 tabular-nums", children: formatLimit(server.memory) })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime11.jsx)("div", { className: "w-px h-8 bg-neutral-800 hidden sm:block" }),
          /* @__PURE__ */ (0, import_jsx_runtime11.jsxs)("div", { className: "flex-1 sm:flex-none", children: [
            /* @__PURE__ */ (0, import_jsx_runtime11.jsx)("div", { className: "text-[10px] text-neutral-500 uppercase font-black tracking-widest mb-1 opacity-60", children: "Storage" }),
            /* @__PURE__ */ (0, import_jsx_runtime11.jsx)("div", { className: "text-sm font-black text-neutral-200 tabular-nums", children: formatLimit(server.disk) })
          ] })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime11.jsx)("div", { className: "w-full sm:w-auto mt-4 sm:mt-0 sm:ml-4", children: /* @__PURE__ */ (0, import_jsx_runtime11.jsxs)("a", { href: `/server/${server.containerId}`, className: "flex items-center justify-center gap-2 bg-neutral-800 hover:bg-primary-600 text-neutral-100 hover:text-white px-6 py-3 rounded-xl font-black text-[10px] uppercase tracking-[0.2em] transition-all duration-300 shadow-xl shadow-black/20 hover:shadow-primary-900/20 active:scale-95", children: [
          "Manage ",
          /* @__PURE__ */ (0, import_jsx_runtime11.jsx)("i", { className: "bi bi-arrow-right-short text-lg" })
        ] }) })
      ] })
    ] });
  }

  // views/react/components/Spinner.jsx
  var import_react12 = __toESM(require_react());
  var import_jsx_runtime12 = __toESM(require_jsx_runtime());
  function Spinner({ centered, size = "default" }) {
    const sizeClasses = size === "large" ? "w-10 h-10 border-4" : "w-5 h-5 border-2";
    const spinner = /* @__PURE__ */ (0, import_jsx_runtime12.jsx)("div", { className: `animate-spin rounded-full border-t-primary-500 border-neutral-700 ${sizeClasses}` });
    if (centered) {
      return /* @__PURE__ */ (0, import_jsx_runtime12.jsx)("div", { className: "flex justify-center items-center w-full py-16", children: spinner });
    }
    return spinner;
  }

  // views/react/dashboard.jsx
  var import_jsx_runtime13 = __toESM(require_jsx_runtime());
  var data = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "dashboard";
  var root = standaloneEntry ? (0, import_client.createRoot)(document.getElementById("reactRoot")) : null;
  function formatMetricValue(val) {
    return Number(val || 0).toLocaleString();
  }
  function Announcer({ settings = {} }) {
    const enabled = String(settings.extensionAnnouncerEnabled || "false") === "true";
    const message = String(settings.extensionAnnouncerMessage || "").trim();
    if (!enabled || !message) return null;
    const severity = String(settings.extensionAnnouncerSeverity || "normal").toLowerCase();
    const configs = {
      normal: { badge: "NORMAL", bg: "bg-green-500/10", border: "border-green-500/20", text: "text-green-300" },
      warning: { badge: "WARNING", bg: "bg-yellow-500/10", border: "border-yellow-500/20", text: "text-yellow-300" },
      critical: { badge: "CRITICAL", bg: "bg-red-500/10", border: "border-red-500/20", text: "text-red-300" }
    };
    const conf = configs[severity] || configs.normal;
    return /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: `mb-6 p-4 rounded-2xl border ${conf.bg} ${conf.border} shadow-lg shadow-black/20 group relative overflow-hidden`, children: [
      /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("div", { className: "absolute -right-4 -top-4 opacity-5 group-hover:opacity-10 transition-opacity duration-700", children: /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("i", { className: "bi bi-megaphone-fill text-8xl -rotate-12" }) }),
      /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("div", { className: "flex items-center gap-3 mb-2", children: /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("span", { className: `text-[10px] font-black uppercase tracking-[0.2em] px-2.5 py-1 rounded-lg bg-neutral-900 shadow-inner ${conf.text}`, children: [
        /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("i", { className: "bi bi-megaphone me-1.5" }),
        "Broadcast \u2022 ",
        conf.badge
      ] }) }),
      /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("p", { className: "text-sm text-neutral-200 leading-relaxed font-medium", children: message })
    ] });
  }
  function MetricCard({ label, value, icon, tone = "neutral" }) {
    const colors = {
      success: "text-green-400 group-hover:text-green-300",
      warning: "text-yellow-400 group-hover:text-yellow-300",
      danger: "text-red-400 group-hover:text-red-300",
      neutral: "text-primary-400 group-hover:text-primary-300"
    };
    return /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "group relative", children: [
      /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("div", { className: "absolute -inset-0.5 bg-gradient-to-br from-neutral-800 to-neutral-800/20 rounded-2xl blur opacity-30 group-hover:opacity-60 transition duration-500" }),
      /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "relative bg-neutral-900/40 backdrop-blur-xl border border-neutral-800/50 p-5 rounded-2xl h-full transition-all duration-300 hover:border-neutral-700/50", children: [
        /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "flex justify-between items-start mb-3", children: [
          /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("span", { className: "text-[10px] font-black text-neutral-500 uppercase tracking-widest", children: label }),
          /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("i", { className: `bi ${icon} text-lg opacity-40 group-hover:opacity-100 transition-opacity ${colors[tone]}` })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("div", { className: "text-2xl font-black text-white tracking-tight tabular-nums", children: value })
      ] })
    ] });
  }
  function VersionStatusBanner({ status }) {
    if (!status || !status.message) return null;
    const configs = {
      success: {
        icon: "bi-check-circle-fill",
        bg: "bg-green-500/10",
        border: "border-green-500/20",
        text: "text-green-400",
        accent: "bg-green-500"
      },
      warning: {
        icon: "bi-exclamation-triangle-fill",
        bg: "bg-yellow-500/10",
        border: "border-yellow-500/20",
        text: "text-yellow-400",
        accent: "bg-yellow-500"
      },
      error: {
        icon: "bi-x-circle-fill",
        bg: "bg-red-500/10",
        border: "border-red-500/20",
        text: "text-red-400",
        accent: "bg-red-500"
      }
    };
    const conf = configs[status.type] || configs.success;
    return /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("div", { className: `mb-8 p-5 rounded-[2rem] border backdrop-blur-md shadow-2xl transition-all duration-500 hover:shadow-primary-900/10 ${conf.bg} ${conf.border}`, children: /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "flex items-center gap-4", children: [
      /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("div", { className: `w-10 h-10 rounded-xl flex items-center justify-center shadow-lg ${conf.accent} text-white`, children: /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("i", { className: `bi ${conf.icon} text-lg` }) }),
      /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "flex-1", children: [
        /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "flex items-center gap-2 mb-0.5", children: [
          /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("span", { className: `text-[10px] font-black uppercase tracking-[0.2em] ${conf.text}`, children: "System Update Status" }),
          /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("span", { className: "w-1 h-1 rounded-full bg-neutral-600" }),
          /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("span", { className: "text-[10px] font-bold text-neutral-500 uppercase tracking-widest", children: status.currentVersion })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("p", { className: "text-sm text-neutral-200 font-medium leading-relaxed", children: status.message })
      ] }),
      status.type === "warning" && /* @__PURE__ */ (0, import_jsx_runtime13.jsx)(
        "a",
        {
          href: "/admin/system",
          className: "px-6 py-2.5 bg-neutral-900/80 hover:bg-neutral-800 text-white rounded-xl text-[10px] font-black uppercase tracking-[0.2em] border border-neutral-700/50 transition-all active:scale-95 whitespace-nowrap",
          children: "View Updates"
        }
      )
    ] }) });
  }
  function OpsFeedItem({ entry, tone = "neutral", type = "incident" }) {
    const severityColors = {
      critical: "bg-red-500 text-white",
      warning: "bg-yellow-500 text-neutral-900",
      normal: "bg-green-600 text-white"
    };
    const toneColor = severityColors[String(entry.severity || "").toLowerCase()] || "bg-neutral-600";
    return /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "p-4 bg-neutral-900/50 border border-neutral-800/80 rounded-xl hover:border-neutral-700 transition-colors", children: [
      /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "flex justify-between items-start gap-3 mb-2", children: [
        /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("h4", { className: "text-sm font-bold text-neutral-100 leading-snug", children: entry.title }),
        /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("span", { className: `text-[9px] px-2 py-0.5 rounded-full font-black uppercase tracking-widest ${toneColor}`, children: entry.severity || (type === "maintenance" ? "PLANNED" : "INFO") })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("div", { className: "text-[10px] text-neutral-500 font-bold uppercase tracking-widest mb-2 opacity-70", children: type === "maintenance" ? `Window: ${new Date(entry.startsAtMs).toLocaleString()} -> ${new Date(entry.endsAtMs).toLocaleString()}` : `Reported: ${new Date(entry.createdAtMs).toLocaleString()}` }),
      entry.message && /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("p", { className: "text-xs text-neutral-300 leading-relaxed opacity-90 border-t border-neutral-800 pt-2 mt-2 italic", children: entry.message })
    ] });
  }
  function DashboardPage({ pageData = data }) {
    const [servers, setServers] = import_react13.default.useState(Array.isArray(pageData.servers) ? pageData.servers : null);
    const [searchQuery, setSearchQuery] = import_react13.default.useState(() => {
      if (typeof window !== "undefined") {
        return new URLSearchParams(window.location.search).get("search") || "";
      }
      return "";
    });
    const [selectedUser, setSelectedUser] = import_react13.default.useState("");
    const [selectedFolder, setSelectedFolder] = import_react13.default.useState("");
    const [selectedTag, setSelectedTag] = import_react13.default.useState("");
    const [sortMode, setSortMode] = import_react13.default.useState("latest");
    const [layout, setLayout] = import_react13.default.useState(() => {
      if (typeof window !== "undefined") {
        try {
          const saved = localStorage.getItem("cpanel_dashboard_layout");
          if (saved) return JSON.parse(saved);
        } catch (e) {
        }
      }
      const raw = pageData.dashboardLayout || {};
      return {
        metrics: raw.metrics !== false,
        announcements: raw.announcements !== false,
        opsFeed: raw.opsFeed !== false,
        filters: raw.filters !== false,
        resourcePills: raw.resourcePills !== false
      };
    });
    const [showCustomize, setShowCustomize] = import_react13.default.useState(false);
    import_react13.default.useEffect(() => {
      if (typeof window !== "undefined") {
        localStorage.setItem("cpanel_dashboard_layout", JSON.stringify(layout));
      }
    }, [layout]);
    import_react13.default.useEffect(() => {
      const handleSearch = (e) => {
        setSearchQuery(e.detail || "");
      };
      window.addEventListener("dashboard-search", handleSearch);
      return () => window.removeEventListener("dashboard-search", handleSearch);
    }, []);
    import_react13.default.useEffect(() => {
      if (!pageData.servers) {
        setServers([]);
      } else {
        setServers(pageData.servers);
      }
    }, [pageData]);
    const isViewingAllServers = Boolean(pageData.showOthersServers);
    const userIsAdmin = Boolean(pageData.isAdminDashboard);
    const uniqueUsers = import_react13.default.useMemo(() => {
      if (!servers || !isViewingAllServers) return [];
      const users = /* @__PURE__ */ new Set();
      servers.forEach((s) => {
        if (s.owner && s.owner.username) {
          users.add(s.owner.username);
        }
      });
      return Array.from(users).sort();
    }, [servers, isViewingAllServers]);
    const filteredServers = import_react13.default.useMemo(() => {
      if (!servers) return null;
      let filtered = [...servers];
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        filtered = filtered.filter(
          (s) => s.name && s.name.toLowerCase().includes(query) || s.containerId && s.containerId.toLowerCase().includes(query) || s.owner && s.owner.username && s.owner.username.toLowerCase().includes(query)
        );
      }
      if (isViewingAllServers && selectedUser) {
        filtered = filtered.filter((s) => s.owner && s.owner.username === selectedUser);
      }
      if (selectedFolder) {
        filtered = filtered.filter((s) => String(s.folder || "").trim() === selectedFolder);
      }
      if (selectedTag) {
        filtered = filtered.filter((s) => Array.isArray(s.tags) && s.tags.includes(selectedTag));
      }
      if (sortMode === "alphabetical") {
        filtered.sort((a, b) => (a.name || "").localeCompare(b.name || ""));
      } else if (sortMode === "latest") {
      }
      return filtered;
    }, [servers, searchQuery, selectedUser, selectedFolder, selectedTag, sortMode, isViewingAllServers]);
    return /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)(ReactAppShell, { pageData, subtitle: "React view beta", children: [
      /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)(
        PageContentBlock,
        {
          title: isViewingAllServers ? "System Overview" : "Dashboard",
          description: isViewingAllServers ? "Viewing all active servers across the system." : "Individual overview of your servers and instances.",
          children: [
            layout.announcements && /* @__PURE__ */ (0, import_jsx_runtime13.jsx)(Announcer, { settings: pageData.settings }),
            pageData.versionStatus && pageData.isAdminDashboard && /* @__PURE__ */ (0, import_jsx_runtime13.jsx)(VersionStatusBanner, { status: pageData.versionStatus }),
            layout.metrics && /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "grid grid-cols-2 lg:grid-cols-5 gap-4 mb-8", children: [
              /* @__PURE__ */ (0, import_jsx_runtime13.jsx)(MetricCard, { label: "Total Nodes", value: formatMetricValue(pageData.totalServers), icon: "bi-server" }),
              /* @__PURE__ */ (0, import_jsx_runtime13.jsx)(MetricCard, { label: "Operational", value: formatMetricValue(pageData.runningServers), icon: "bi-activity", tone: "success" }),
              /* @__PURE__ */ (0, import_jsx_runtime13.jsx)(MetricCard, { label: "Awaiting", value: formatMetricValue(pageData.installingServers), icon: "bi-hourglass-split", tone: "warning" }),
              /* @__PURE__ */ (0, import_jsx_runtime13.jsx)(MetricCard, { label: "Suspended", value: formatMetricValue(pageData.suspendedServers), icon: "bi-shield-exclamation", tone: "danger" }),
              /* @__PURE__ */ (0, import_jsx_runtime13.jsx)(MetricCard, { label: "Wallet Buffer", value: `${formatMetricValue(pageData.user?.coins)} \u{1FA99}`, icon: "bi-wallet2" })
            ] }),
            layout.opsFeed && (Array.isArray(pageData.openIncidents) && pageData.openIncidents.length > 0 || Array.isArray(pageData.pendingMaintenance) && pageData.pendingMaintenance.length > 0 || Array.isArray(pageData.openSecurityAlerts) && pageData.openSecurityAlerts.length > 0) && /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "grid grid-cols-1 xl:grid-cols-3 gap-6 mb-10", children: [
              Array.isArray(pageData.openIncidents) && pageData.openIncidents.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "flex flex-col gap-4", children: [
                /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("h3", { className: "text-[10px] font-black text-neutral-500 uppercase tracking-[0.2em] flex items-center gap-2", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("span", { className: "w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" }),
                  " Open Incidents"
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("div", { className: "flex flex-col gap-3", children: pageData.openIncidents.map((e) => /* @__PURE__ */ (0, import_jsx_runtime13.jsx)(OpsFeedItem, { entry: e, type: "incident" }, e.id || e.title)) })
              ] }),
              Array.isArray(pageData.pendingMaintenance) && pageData.pendingMaintenance.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "flex flex-col gap-4", children: [
                /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("h3", { className: "text-[10px] font-black text-neutral-500 uppercase tracking-[0.2em] flex items-center gap-2", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("span", { className: "w-1.5 h-1.5 rounded-full bg-primary-500" }),
                  " Maintenance"
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("div", { className: "flex flex-col gap-3", children: pageData.pendingMaintenance.map((e) => /* @__PURE__ */ (0, import_jsx_runtime13.jsx)(OpsFeedItem, { entry: e, type: "maintenance" }, e.id || e.title)) })
              ] }),
              Array.isArray(pageData.openSecurityAlerts) && pageData.openSecurityAlerts.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "flex flex-col gap-4", children: [
                /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("h3", { className: "text-[10px] font-black text-neutral-500 uppercase tracking-[0.2em] flex items-center gap-2", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("span", { className: "w-1.5 h-1.5 rounded-full bg-yellow-500" }),
                  " Security Alerts"
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("div", { className: "flex flex-col gap-3", children: pageData.openSecurityAlerts.map((e) => /* @__PURE__ */ (0, import_jsx_runtime13.jsx)(OpsFeedItem, { entry: e, type: "security" }, e.id || e.title)) })
              ] })
            ] }),
            userIsAdmin && /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "mb-10 group relative", children: [
              /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("div", { className: "absolute -inset-1 bg-gradient-to-r from-primary-600/20 to-purple-600/20 rounded-[2.5rem] blur-xl opacity-50 group-hover:opacity-100 transition duration-1000 group-hover:duration-200" }),
              /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "relative flex flex-col sm:flex-row justify-between items-center bg-neutral-900/80 backdrop-blur-xl border border-neutral-800/50 p-6 sm:p-8 rounded-[2rem] shadow-2xl overflow-hidden ring-1 ring-white/5", children: [
                /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "flex items-center gap-6 mb-6 sm:mb-0", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("div", { className: `w-14 h-14 rounded-2xl flex items-center justify-center transition-all duration-500 shadow-inner ${isViewingAllServers ? "bg-primary-500/10 text-primary-400 ring-2 ring-primary-500/20" : "bg-neutral-800 text-neutral-500"}`, children: /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("i", { className: `bi ${isViewingAllServers ? "bi-shield-check" : "bi-shield-lock"} text-2xl` }) }),
                  /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { children: [
                    /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("h4", { className: "text-[11px] font-black text-white uppercase tracking-[0.2em] leading-none mb-2 opacity-90", children: isViewingAllServers ? "System-Wide Administration" : "Personal Instance Dashboard" }),
                    /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("p", { className: "text-[10px] text-neutral-500 font-bold uppercase tracking-widest opacity-70", children: isViewingAllServers ? "Global visibility enabled: Viewing all network servers" : "Filtered view: Only showing your private instances" })
                  ] })
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "flex items-center gap-3", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime13.jsx)(
                    "button",
                    {
                      onClick: () => setShowCustomize(true),
                      className: "p-4 rounded-xl bg-neutral-800 hover:bg-neutral-700 text-neutral-400 hover:text-white transition-all border border-neutral-700/50",
                      title: "Customize Layout",
                      children: /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("i", { className: "bi bi-layout-text-window-reverse text-lg" })
                    }
                  ),
                  /* @__PURE__ */ (0, import_jsx_runtime13.jsx)(
                    "a",
                    {
                      href: isViewingAllServers ? "/" : "/?others=true",
                      className: `group relative px-8 py-4 rounded-xl text-xs font-black uppercase tracking-[0.25em] transition-all duration-300 flex items-center gap-3 overflow-hidden ${isViewingAllServers ? "bg-neutral-800 hover:bg-neutral-700 text-primary-400 border border-neutral-700" : "bg-primary-600 hover:bg-primary-500 text-white shadow-2xl shadow-primary-900/40"}`,
                      children: /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("span", { className: "relative z-10 flex items-center gap-3", children: [
                        /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("i", { className: `bi ${isViewingAllServers ? "bi-toggle-on text-lg" : "bi-toggle-off text-lg opacity-50"}` }),
                        isViewingAllServers ? "Leave Admin View" : "Enter Admin View"
                      ] })
                    }
                  )
                ] })
              ] })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "mb-8 flex flex-col xl:flex-row justify-between items-start xl:items-center gap-6", children: [
              /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "flex flex-wrap items-center gap-3 w-full xl:w-auto", children: [
                String(pageData.settings?.featureUserCreateEnabled) === "true" && /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)(import_jsx_runtime13.Fragment, { children: [
                  /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("a", { href: "/user/create", className: "px-6 py-3 bg-primary-600 hover:bg-primary-500 text-white rounded-xl text-[10px] font-black uppercase tracking-[0.2em] shadow-lg shadow-primary-900/20 transition-all active:scale-95 flex items-center gap-2", children: [
                    /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("i", { className: "bi bi-plus-lg text-sm" }),
                    " Create Server"
                  ] }),
                  /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("a", { href: "/store", className: "px-6 py-3 bg-neutral-800 hover:bg-neutral-700 text-neutral-200 rounded-xl text-[10px] font-black uppercase tracking-[0.2em] border border-neutral-700 transition-all flex items-center gap-2", children: [
                    /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("i", { className: "bi bi-shop" }),
                    " Store"
                  ] }),
                  /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("div", { className: "hidden xl:block w-px h-8 bg-neutral-800 mx-2" })
                ] }),
                layout.filters && servers && servers.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "flex flex-wrap items-center gap-3 flex-1 xl:flex-none", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "relative group", children: [
                    /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("i", { className: "bi bi-sort-down absolute left-4 top-1/2 -translate-y-1/2 text-neutral-500 text-xs pointer-events-none transition-colors group-focus-within:text-primary-400" }),
                    /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)(
                      "select",
                      {
                        value: sortMode,
                        onChange: (e) => setSortMode(e.target.value),
                        className: "bg-neutral-900/50 border border-neutral-800 rounded-xl py-2.5 pl-10 pr-10 text-[10px] font-black uppercase tracking-widest text-neutral-400 focus:outline-none focus:border-primary-500/50 focus:ring-1 focus:ring-primary-500/50 transition-all appearance-none cursor-pointer",
                        children: [
                          /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("option", { value: "latest", children: "Latest First" }),
                          /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("option", { value: "alphabetical", children: "Alphabetical" }),
                          /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("option", { value: "custom", children: "Custom Order" })
                        ]
                      }
                    ),
                    /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("i", { className: "bi bi-chevron-down absolute right-4 top-1/2 -translate-y-1/2 text-neutral-600 text-[8px] pointer-events-none" })
                  ] }),
                  Array.isArray(pageData.dashboardFolders) && pageData.dashboardFolders.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "relative group", children: [
                    /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("i", { className: "bi bi-folder2 absolute left-4 top-1/2 -translate-y-1/2 text-neutral-500 text-xs pointer-events-none transition-colors group-focus-within:text-primary-400" }),
                    /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)(
                      "select",
                      {
                        value: selectedFolder,
                        onChange: (e) => setSelectedFolder(e.target.value),
                        className: "bg-neutral-900/50 border border-neutral-800 rounded-xl py-2.5 pl-10 pr-10 text-[10px] font-black uppercase tracking-widest text-neutral-400 focus:outline-none focus:border-primary-500/50 focus:ring-1 focus:ring-primary-500/50 transition-all appearance-none cursor-pointer",
                        children: [
                          /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("option", { value: "", children: "All Folders" }),
                          pageData.dashboardFolders.map((f) => /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("option", { value: f, children: f }, f))
                        ]
                      }
                    ),
                    /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("i", { className: "bi bi-chevron-down absolute right-4 top-1/2 -translate-y-1/2 text-neutral-600 text-[8px] pointer-events-none" })
                  ] }),
                  Array.isArray(pageData.dashboardTags) && pageData.dashboardTags.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "relative group", children: [
                    /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("i", { className: "bi bi-tag absolute left-4 top-1/2 -translate-y-1/2 text-neutral-500 text-xs pointer-events-none transition-colors group-focus-within:text-primary-400" }),
                    /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)(
                      "select",
                      {
                        value: selectedTag,
                        onChange: (e) => setSelectedTag(e.target.value),
                        className: "bg-neutral-900/50 border border-neutral-800 rounded-xl py-2.5 pl-10 pr-10 text-[10px] font-black uppercase tracking-widest text-neutral-400 focus:outline-none focus:border-primary-500/50 focus:ring-1 focus:ring-primary-500/50 transition-all appearance-none cursor-pointer",
                        children: [
                          /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("option", { value: "", children: "All Tags" }),
                          pageData.dashboardTags.map((t) => /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("option", { value: t, children: t }, t))
                        ]
                      }
                    ),
                    /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("i", { className: "bi bi-chevron-down absolute right-4 top-1/2 -translate-y-1/2 text-neutral-600 text-[8px] pointer-events-none" })
                  ] })
                ] })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("div", { className: "flex items-center gap-4 w-full xl:w-auto", children: isViewingAllServers && uniqueUsers.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "relative group flex-1 xl:flex-none", children: [
                /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("i", { className: "bi bi-person absolute left-4 top-1/2 -translate-y-1/2 text-neutral-500 text-xs pointer-events-none transition-colors group-focus-within:text-primary-400" }),
                /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)(
                  "select",
                  {
                    value: selectedUser,
                    onChange: (e) => setSelectedUser(e.target.value),
                    className: "w-full bg-neutral-900/50 border border-neutral-800 rounded-xl py-2.5 pl-10 pr-10 text-[10px] font-black uppercase tracking-widest text-neutral-400 focus:outline-none focus:border-primary-500/50 focus:ring-1 focus:ring-primary-500/50 transition-all appearance-none cursor-pointer",
                    children: [
                      /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("option", { value: "", children: "All Users" }),
                      uniqueUsers.map((u) => /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("option", { value: u, children: u }, u))
                    ]
                  }
                ),
                /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("i", { className: "bi bi-chevron-down absolute right-4 top-1/2 -translate-y-1/2 text-neutral-600 text-[8px] pointer-events-none" })
              ] }) })
            ] }),
            !servers ? /* @__PURE__ */ (0, import_jsx_runtime13.jsx)(Spinner, { centered: true, size: "large" }) : filteredServers.length > 0 ? /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("div", { className: "flex flex-col gap-2", children: filteredServers.map((server) => /* @__PURE__ */ (0, import_jsx_runtime13.jsx)(
              ServerRow,
              {
                server,
                isAdminDashboard: isViewingAllServers,
                showResourcePills: layout.resourcePills
              },
              server.id || server.containerId
            )) }) : /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "flex flex-col items-center justify-center py-24 bg-neutral-900/30 border border-neutral-800/50 border-dashed rounded-[3rem]", children: [
              /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("i", { className: "bi bi-search text-5xl text-neutral-800 mb-6" }),
              /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("p", { className: "text-center text-sm font-black text-neutral-500 uppercase tracking-[0.2em]", children: "No results match your criteria." }),
              (searchQuery || selectedUser || selectedFolder || selectedTag) && /* @__PURE__ */ (0, import_jsx_runtime13.jsx)(
                "button",
                {
                  onClick: () => {
                    setSearchQuery("");
                    setSelectedUser("");
                    setSelectedFolder("");
                    setSelectedTag("");
                  },
                  className: "mt-8 px-8 py-3 bg-neutral-800 hover:bg-neutral-700 text-neutral-300 rounded-2xl text-[10px] font-black uppercase tracking-[0.2em] transition-all border border-neutral-700/50",
                  children: "Reset All Filters"
                }
              )
            ] })
          ]
        }
      ),
      showCustomize && /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "fixed inset-0 z-[100] flex items-center justify-center p-6 sm:p-0", children: [
        /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("div", { className: "absolute inset-0 bg-black/60 backdrop-blur-md", onClick: () => setShowCustomize(false) }),
        /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "relative w-full max-w-xl bg-neutral-900 border border-neutral-800 rounded-[2.5rem] shadow-2xl overflow-hidden ring-1 ring-white/10", children: [
          /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "p-8 border-b border-neutral-800 flex justify-between items-center", children: [
            /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { children: [
              /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("h2", { className: "text-xl font-bold text-white tracking-tight", children: "Customize Dashboard" }),
              /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("p", { className: "text-xs text-neutral-500 font-bold uppercase tracking-widest mt-1", children: "Configure your personal view prefs" })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("button", { onClick: () => setShowCustomize(false), className: "w-10 h-10 flex items-center justify-center rounded-xl bg-neutral-800 text-neutral-400 hover:text-white transition-colors", children: /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("i", { className: "bi bi-x-lg" }) })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("div", { className: "p-8 space-y-6", children: [
            { id: "metrics", label: "Summary Metrics Bar", desc: "Display total count, running status, and wallet balance." },
            { id: "announcements", label: "Broadcast Announcements", desc: "Show important messages from system administrators." },
            { id: "opsFeed", label: "Operations Feed", desc: "Monitor active incidents and scheduled maintenance." },
            { id: "filters", label: "Advanced Filter Controls", desc: "Enable folder, tag, and custom sorting dropdowns." },
            { id: "resourcePills", label: "Internal Resource Data", desc: "Show CPU/RAM usage directly on the server cards." }
          ].map((item) => /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("label", { className: "flex items-center justify-between gap-6 group cursor-pointer", children: [
            /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "flex-1", children: [
              /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("div", { className: "block text-sm font-bold text-neutral-200 group-hover:text-primary-400 transition-colors", children: item.label }),
              /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("p", { className: "text-xs text-neutral-500 mt-1", children: item.desc })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "relative inline-flex items-center", children: [
              /* @__PURE__ */ (0, import_jsx_runtime13.jsx)(
                "input",
                {
                  type: "checkbox",
                  id: item.id,
                  className: "sr-only peer",
                  checked: layout[item.id],
                  onChange: () => setLayout((prev) => ({ ...prev, [item.id]: !prev[item.id] }))
                }
              ),
              /* @__PURE__ */ (0, import_jsx_runtime13.jsx)("div", { className: "w-12 h-6 bg-neutral-800 rounded-full peer peer-checked:bg-primary-600 after:content-[''] after:absolute after:top-[4px] after:left-[4px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:after:translate-x-6 border border-neutral-700 peer-checked:border-primary-500 transition-colors" })
            ] })
          ] }, item.id)) }),
          /* @__PURE__ */ (0, import_jsx_runtime13.jsxs)("div", { className: "p-8 bg-neutral-800/50 flex justify-between items-center", children: [
            /* @__PURE__ */ (0, import_jsx_runtime13.jsx)(
              "button",
              {
                onClick: () => setLayout({ metrics: true, announcements: true, opsFeed: true, filters: true, resourcePills: true }),
                className: "text-[10px] font-black text-neutral-500 hover:text-white uppercase tracking-widest transition-colors",
                children: "Reset to Defaults"
              }
            ),
            /* @__PURE__ */ (0, import_jsx_runtime13.jsx)(
              "button",
              {
                onClick: () => setShowCustomize(false),
                className: "px-8 py-3 bg-primary-600 hover:bg-primary-500 text-white rounded-xl text-[10px] font-black uppercase tracking-[0.2em] shadow-lg shadow-primary-900/20 transition-all active:scale-95",
                children: "Save Changes"
              }
            )
          ] })
        ] })
      ] })
    ] });
  }
  if (root) {
    root.render(
      /* @__PURE__ */ (0, import_jsx_runtime13.jsx)(ThemeContext_default, { pageData: data, children: /* @__PURE__ */ (0, import_jsx_runtime13.jsx)(BrowserRouter, { children: /* @__PURE__ */ (0, import_jsx_runtime13.jsx)(DashboardPage, { pageData: data }) }) })
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === "function") {
      window.__CPANEL_REACT_BOOTED__();
    }
  }

  // views/react/server-console.jsx
  var import_react14 = __toESM(require_react());
  var import_client2 = __toESM(require_client());
  var import_jsx_runtime14 = __toESM(require_jsx_runtime());
  var data2 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry2 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "server-console";
  var root2 = standaloneEntry2 ? (0, import_client2.createRoot)(document.getElementById("reactRoot")) : null;
  var XTERM_CSS_URL = "https://cdn.jsdelivr.net/npm/xterm@5.2.1/css/xterm.css";
  var XTERM_SCRIPT_URLS = [
    "https://cdn.jsdelivr.net/npm/xterm@5.2.1/lib/xterm.js",
    "https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.7.0/lib/xterm-addon-fit.js",
    "https://cdn.jsdelivr.net/npm/xterm-addon-web-links@0.8.0/lib/xterm-addon-web-links.js",
    "https://cdn.jsdelivr.net/npm/xterm-addon-unicode11@0.6.0/lib/xterm-addon-unicode11.js"
  ];
  var xtermAssetsPromise = null;
  function ensureStyle(href) {
    if (typeof document === "undefined") return;
    if (document.querySelector(`link[data-react-asset="${href}"]`)) return;
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = href;
    link.setAttribute("data-react-asset", href);
    document.head.appendChild(link);
  }
  function loadScript(src) {
    return new Promise((resolve, reject) => {
      const existing = document.querySelector(`script[data-react-asset="${src}"]`);
      if (existing) {
        if (existing.getAttribute("data-loaded") === "1") {
          resolve();
          return;
        }
        existing.addEventListener("load", () => resolve(), { once: true });
        existing.addEventListener("error", () => reject(new Error(`Failed to load ${src}`)), { once: true });
        return;
      }
      const script = document.createElement("script");
      script.src = src;
      script.async = true;
      script.setAttribute("data-react-asset", src);
      script.addEventListener("load", () => {
        script.setAttribute("data-loaded", "1");
        resolve();
      }, { once: true });
      script.addEventListener("error", () => reject(new Error(`Failed to load ${src}`)), { once: true });
      document.body.appendChild(script);
    });
  }
  function ensureXtermAssets() {
    if (typeof window !== "undefined" && window.Terminal && window.FitAddon && window.WebLinksAddon && window.Unicode11Addon) {
      return Promise.resolve();
    }
    if (xtermAssetsPromise) return xtermAssetsPromise;
    ensureStyle(XTERM_CSS_URL);
    xtermAssetsPromise = XTERM_SCRIPT_URLS.reduce(
      (chain, src) => chain.then(() => loadScript(src)),
      Promise.resolve()
    );
    return xtermAssetsPromise;
  }
  function normalizeStatus(status) {
    return String(status || "unknown").trim().toLowerCase() || "unknown";
  }
  function statusTone(status) {
    const value = normalizeStatus(status);
    if (value === "running") return "success";
    if (["installing", "reinstalling", "starting", "stopping"].includes(value)) return "warning";
    if (["stopped", "offline", "error"].includes(value)) return "danger";
    return "muted";
  }
  function getToneColorClass(tone) {
    switch (tone) {
      case "success":
        return "bg-green-500";
      case "warning":
        return "bg-yellow-500";
      case "danger":
        return "bg-red-500";
      default:
        return "bg-neutral-500";
    }
  }
  function parseMetric(value) {
    const numeric = Number.parseFloat(String(value || "0").replace(/[^0-9.-]/g, ""));
    if (!Number.isFinite(numeric)) return 0;
    return Math.max(0, numeric);
  }
  function formatDuration(value) {
    const seconds = Math.max(0, Number.parseInt(String(value || "0"), 10) || 0);
    if (!seconds) return "0s";
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor(seconds % 86400 / 3600);
    const minutes = Math.floor(seconds % 3600 / 60);
    const secs = seconds % 60;
    const parts = [];
    if (days) parts.push(`${days}d`);
    if (hours) parts.push(`${hours}h`);
    if (minutes) parts.push(`${minutes}m`);
    if (secs || parts.length === 0) parts.push(`${secs}s`);
    return parts.slice(0, 3).join(" ");
  }
  function formatRuntimeSource(source) {
    const value = String(source || "system").trim().toLowerCase().replace(/_/g, " ");
    return value ? value.charAt(0).toUpperCase() + value.slice(1) : "System";
  }
  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }
  function usagePercent(value, limit) {
    const safeValue = parseMetric(value);
    const safeLimit = parseMetric(limit);
    if (!safeLimit) return 0;
    return clamp(safeValue / safeLimit * 100, 0, 100);
  }
  function InlineMetric({ title, value, note, tone = "" }) {
    const toneTextClass = tone === "success" ? "text-green-400" : tone === "warning" ? "text-yellow-400" : tone === "danger" ? "text-red-400" : "text-primary-400";
    return /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "flex flex-col mb-1 pb-2 border-b border-neutral-700/50 last:border-0 last:pb-0", children: [
      /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "flex justify-between items-center", children: [
        /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("span", { className: "text-xs font-bold text-neutral-400 uppercase tracking-wide", children: title }),
        /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("strong", { className: `font-mono text-sm ${toneTextClass}`, children: value })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("small", { className: "text-xs text-neutral-500 mt-1", children: note })
    ] });
  }
  function scrubAnsi(text) {
    return String(text || "").replace(/\\x1b/g, "\x1B");
  }
  function buildWsUrl(wsToken, containerId) {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    return `${protocol}//${window.location.host}/ws/server/${encodeURIComponent(String(containerId || ""))}?token=${encodeURIComponent(String(wsToken || ""))}`;
  }
  function ServerConsolePage({ pageData = data2 }) {
    const [isPopout, setIsPopout] = import_react14.default.useState(false);
    import_react14.default.useEffect(() => {
      if (typeof window !== "undefined") {
        setIsPopout(new URLSearchParams(window.location.search).get("popout") === "true");
      }
    }, []);
    const server = pageData.server || {};
    const limits = server.limits || {};
    const historyStorageKey = import_react14.default.useMemo(
      () => `cpanel.react.console.history.${server.containerId || "server"}`,
      [server.containerId]
    );
    const isMinecraft = Boolean(pageData.isMinecraftServer);
    const macros = Array.isArray(pageData.commandMacros) ? pageData.commandMacros : [];
    const mcPerms = pageData.minecraftActionPermissions || {};
    const terminalHostRef = import_react14.default.useRef(null);
    const terminalInstanceRef = import_react14.default.useRef(null);
    const fitAddonRef = import_react14.default.useRef(null);
    const wsRef = import_react14.default.useRef(null);
    const reconnectTimerRef = import_react14.default.useRef(null);
    const heartbeatTimerRef = import_react14.default.useRef(null);
    const disposedRef = import_react14.default.useRef(false);
    const followOutputRef = import_react14.default.useRef(true);
    const historyIndexRef = import_react14.default.useRef(-1);
    const [status, setStatus] = import_react14.default.useState(normalizeStatus(server.status));
    const [connectorOnline, setConnectorOnline] = import_react14.default.useState(Boolean(pageData.connectorOnline));
    const [commandValue, setCommandValue] = import_react14.default.useState("");
    const [history, setHistory] = import_react14.default.useState(() => {
      try {
        const raw = localStorage.getItem(historyStorageKey) || "[]";
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed) ? parsed.filter((entry) => typeof entry === "string" && entry.trim()).slice(0, 32) : [];
      } catch {
        return [];
      }
    });
    const [stats, setStats] = import_react14.default.useState({
      cpu: parseMetric(pageData.initialStats && pageData.initialStats.cpu),
      memory: parseMetric(pageData.initialStats && pageData.initialStats.memory),
      disk: parseMetric(pageData.initialStats && pageData.initialStats.disk),
      networkRx: parseMetric(pageData.initialStats && pageData.initialStats.network_rx),
      networkTx: parseMetric(pageData.initialStats && pageData.initialStats.network_tx),
      uptimeSeconds: parseMetric(pageData.initialStats && pageData.initialStats.uptime_seconds)
    });
    const [exitInfo, setExitInfo] = import_react14.default.useState({
      exitCode: null,
      oomKilled: false
    });
    const [runtimeMeta, setRuntimeMeta] = import_react14.default.useState(() => {
      const incoming = pageData.runtimeMeta || {};
      return {
        lastSource: incoming.lastSource || "system",
        lastReason: incoming.lastReason || "",
        cooldownUntil: incoming.cooldownUntil || null,
        crashLoopCount: incoming.crashLoopCount || 0,
        history: Array.isArray(incoming.history) ? incoming.history.slice(0, 6) : []
      };
    });
    const [connectionState, setConnectionState] = import_react14.default.useState("Connecting...");
    const [followOutput, setFollowOutput] = import_react14.default.useState(true);
    const [terminalError, setTerminalError] = import_react14.default.useState("");
    const [terminalBooted, setTerminalBooted] = import_react14.default.useState(false);
    const [showShortcuts, setShowShortcuts] = import_react14.default.useState(false);
    const [players, setPlayers] = import_react14.default.useState([]);
    const [playersLoading, setPlayersLoading] = import_react14.default.useState(isMinecraft);
    const [playersError, setPlayersError] = import_react14.default.useState("");
    import_react14.default.useEffect(() => {
      if (!isMinecraft) return;
      let active = true;
      async function fetchPlayers() {
        if (!active) return;
        try {
          const bedrockMode = pageData.minecraftBedrockMode ? "1" : "0";
          const response = await fetch(`/server/${server.containerId}/minecraft/configs/status?bedrock=${bedrockMode}`);
          const payload = await response.json();
          if (!response.ok || !payload.success) throw new Error(payload.error || "Failed to sync players");
          if (active) {
            setPlayers(payload.status?.playersList || []);
            setPlayersError("");
            setPlayersLoading(false);
          }
        } catch (err) {
          if (active) setPlayersError(err.message || "Player sync failed");
        }
      }
      fetchPlayers();
      const interval = setInterval(fetchPlayers, 3e4);
      return () => {
        active = false;
        clearInterval(interval);
      };
    }, [isMinecraft, server.containerId]);
    const handleMcAction = async (action, player) => {
      const requiresReason = ["kick", "ban", "tempban"].includes(action);
      const requiresDuration = action === "tempban";
      const requiresDestination = action === "teleport";
      const extra = {};
      if (requiresDestination) {
        const destination = window.prompt(`Teleport destination for ${player}:`, "");
        if (!destination) return;
        extra.destination = String(destination).trim().slice(0, 64);
      }
      if (requiresDuration) {
        const duration = window.prompt(`Tempban duration for ${player} (e.g. 1h):`, "");
        if (!duration) return;
        extra.duration = String(duration).trim().slice(0, 16);
      }
      if (requiresReason) {
        const reason = window.prompt(`Reason for ${action.toUpperCase()} ${player}:`, "");
        if (!reason) return;
        extra.reason = String(reason).trim().slice(0, 96);
      }
      const formData = new URLSearchParams();
      formData.append("action", action);
      formData.append("player", player);
      formData.append("bedrock", pageData.minecraftBedrockMode ? "1" : "0");
      if (extra.reason) formData.append("reason", extra.reason);
      if (extra.duration) formData.append("duration", extra.duration);
      if (extra.destination) formData.append("destination", extra.destination);
      try {
        await fetch(`/server/${server.containerId}/minecraft/configs`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: formData.toString()
        });
      } catch (e) {
        console.error("Failed to dispatch action", e);
      }
    };
    import_react14.default.useEffect(() => {
      followOutputRef.current = followOutput;
    }, [followOutput]);
    import_react14.default.useEffect(() => {
      try {
        localStorage.setItem(historyStorageKey, JSON.stringify(history.slice(0, 32)));
      } catch {
      }
    }, [history, historyStorageKey]);
    import_react14.default.useEffect(() => {
      disposedRef.current = false;
      setTerminalError("");
      setTerminalBooted(false);
      const stopHeartbeat = () => {
        if (heartbeatTimerRef.current) {
          clearInterval(heartbeatTimerRef.current);
          heartbeatTimerRef.current = null;
        }
      };
      const clearReconnect = () => {
        if (reconnectTimerRef.current) {
          clearTimeout(reconnectTimerRef.current);
          reconnectTimerRef.current = null;
        }
      };
      const teardownSocket = () => {
        stopHeartbeat();
        clearReconnect();
        if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
          wsRef.current.close(1e3, "Leaving React console");
        }
        wsRef.current = null;
      };
      const handleResize = () => {
        try {
          fitAddonRef.current && fitAddonRef.current.fit();
        } catch {
        }
      };
      const boot = async () => {
        await ensureXtermAssets();
        if (disposedRef.current || !terminalHostRef.current) return;
        terminalHostRef.current.innerHTML = "";
        const term = new window.Terminal({
          theme: {
            background: "#18181b",
            // neutral-900 equivalent for console
            foreground: "#eef4fb",
            cursor: "#eef4fb",
            black: "#16161a",
            red: "#ef4444",
            green: "#10b981",
            yellow: "#f59e0b",
            blue: "#3b82f6",
            magenta: "#8b5cf6",
            cyan: "#06b6d4",
            white: "#eef4fb"
          },
          allowProposedApi: true,
          fontFamily: 'Menlo, Monaco, "Courier New", monospace',
          fontSize: 13,
          cursorBlink: true,
          scrollback: 5e3,
          convertEol: true,
          padding: "16px"
        });
        const fitAddon = new window.FitAddon.FitAddon();
        const webLinksAddon = new window.WebLinksAddon.WebLinksAddon();
        const unicode11Addon = new window.Unicode11Addon.Unicode11Addon();
        term.loadAddon(fitAddon);
        term.loadAddon(webLinksAddon);
        term.loadAddon(unicode11Addon);
        term.open(terminalHostRef.current);
        try {
          term.unicode.activeVersion = "11";
        } catch {
        }
        fitAddon.fit();
        terminalInstanceRef.current = term;
        fitAddonRef.current = fitAddon;
        setTerminalBooted(true);
        if (pageData.initialConsoleBuffer) {
          term.write(scrubAnsi(pageData.initialConsoleBuffer));
          if (followOutputRef.current) {
            term.scrollToBottom();
          }
        } else {
          term.writeln("\x1B[1;34m[*] React console ready.\x1B[0m");
        }
        let reconnectDelay = 1e3;
        const connect = () => {
          if (disposedRef.current) return;
          setConnectionState("Connecting...");
          const ws = new WebSocket(buildWsUrl(pageData.wsToken, server.containerId));
          wsRef.current = ws;
          ws.onopen = () => {
            reconnectDelay = 1e3;
            setConnectionState("Connected");
            setConnectorOnline(true);
            term.writeln("\x1B[1;32m[\u2713] Console stream connected.\x1B[0m");
            stopHeartbeat();
            heartbeatTimerRef.current = window.setInterval(() => {
              if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: "ping" }));
              }
            }, 3e4);
          };
          ws.onmessage = (event) => {
            try {
              const payload = JSON.parse(event.data);
              switch (payload.type) {
                case "console_output": {
                  const output = scrubAnsi(payload.output || "");
                  term.write(output);
                  if (followOutputRef.current) {
                    term.scrollToBottom();
                  }
                  break;
                }
                case "server_status_update":
                  setStatus(normalizeStatus(payload.status));
                  setExitInfo({
                    exitCode: payload.exitCode !== void 0 && payload.exitCode !== null && String(payload.exitCode).trim() !== "" ? String(payload.exitCode) : null,
                    oomKilled: payload.oomKilled === true || String(payload.oomKilled || "").toLowerCase() === "true"
                  });
                  break;
                case "connector_status":
                  setConnectorOnline(Boolean(payload.online));
                  break;
                case "server_stats": {
                  const nextCpu = parseMetric(payload.cpu);
                  const nextMemory = parseMetric(payload.memory);
                  const nextDisk = parseMetric(payload.disk);
                  const nextNetworkRx = parseMetric(payload.network_rx);
                  const nextNetworkTx = parseMetric(payload.network_tx);
                  const nextUptime = parseMetric(payload.uptime_seconds);
                  setStats({
                    cpu: nextCpu,
                    memory: nextMemory,
                    disk: nextDisk,
                    networkRx: nextNetworkRx,
                    networkTx: nextNetworkTx,
                    uptimeSeconds: nextUptime
                  });
                  break;
                }
                case "server_runtime_meta":
                  setRuntimeMeta({
                    lastSource: payload.lastSource || "system",
                    lastReason: payload.lastReason || "",
                    cooldownUntil: payload.cooldownUntil || null,
                    crashLoopCount: payload.crashLoopCount || 0,
                    history: Array.isArray(payload.history) ? payload.history.slice(0, 6) : []
                  });
                  break;
                case "server_action_ack": {
                  const phase = String(payload.phase || "").toLowerCase();
                  const actionType = String(payload.actionType || "action");
                  const text = String(payload.message || "").trim() || `${actionType} ${phase}`;
                  if (phase === "failed") {
                    term.writeln(`\x1B[1;31m[ACK] ${actionType}: ${text}\x1B[0m`);
                  } else if (phase === "executed") {
                    term.writeln(`\x1B[1;32m[ACK] ${actionType}: ${text}\x1B[0m`);
                  } else {
                    term.writeln(`\x1B[1;34m[ACK] ${actionType}: ${text}\x1B[0m`);
                  }
                  break;
                }
                case "error":
                  term.writeln(`\x1B[1;31m[!] ${String(payload.message || "Unknown error")}\x1B[0m`);
                  break;
                default:
                  break;
              }
            } catch (error) {
              console.error("React console failed to parse websocket payload.", error);
            }
          };
          ws.onclose = () => {
            stopHeartbeat();
            if (disposedRef.current) return;
            setConnectionState("Disconnected");
            setConnectorOnline(false);
            term.writeln(`\x1B[1;33m[!] Connection lost. Reconnecting in ${Math.round(reconnectDelay / 1e3)}s...\x1B[0m`);
            clearReconnect();
            reconnectTimerRef.current = window.setTimeout(() => {
              reconnectDelay = Math.min(Math.round(reconnectDelay * 1.5), 5e3);
              connect();
            }, reconnectDelay);
          };
          ws.onerror = (error) => {
            console.error("React console websocket error:", error);
            try {
              ws.close();
            } catch {
            }
          };
        };
        connect();
        window.addEventListener("resize", handleResize);
        return () => {
          window.removeEventListener("resize", handleResize);
          teardownSocket();
          try {
            term.dispose();
          } catch {
          }
          terminalInstanceRef.current = null;
          fitAddonRef.current = null;
        };
      };
      let cleanup = null;
      boot().then((nextCleanup) => {
        cleanup = nextCleanup;
      }).catch((error) => {
        console.error("React console bootstrap failed:", error);
        setTerminalError(error && error.message ? error.message : "Failed to initialize terminal.");
      });
      return () => {
        disposedRef.current = true;
        if (typeof cleanup === "function") cleanup();
        stopHeartbeat();
        clearReconnect();
        if (terminalInstanceRef.current) {
          try {
            terminalInstanceRef.current.dispose();
          } catch {
          }
          terminalInstanceRef.current = null;
        }
        fitAddonRef.current = null;
        wsRef.current = null;
      };
    }, [pageData.initialConsoleBuffer, pageData.wsToken, server.containerId]);
    const sendPayload = import_react14.default.useCallback((payload) => {
      const socket = wsRef.current;
      if (!socket || socket.readyState !== WebSocket.OPEN) return false;
      socket.send(JSON.stringify(payload));
      return true;
    }, []);
    const recordHistory = import_react14.default.useCallback((value) => {
      const trimmed = String(value || "").trim();
      if (!trimmed) return;
      setHistory((current) => [trimmed, ...current.filter((entry) => entry !== trimmed)].slice(0, 32));
      historyIndexRef.current = -1;
    }, []);
    const sendCommand = import_react14.default.useCallback(() => {
      const command = String(commandValue || "").trim();
      if (!command) return;
      if (!sendPayload({ type: "console_input", command })) return;
      recordHistory(command);
      setCommandValue("");
    }, [commandValue, recordHistory, sendPayload]);
    const runMacro = import_react14.default.useCallback((macroId) => {
      if (!sendPayload({ type: "run_macro", macroId })) return;
      const term = terminalInstanceRef.current;
      if (term) term.writeln(`\x1B[1;36m[*] Fired macro trigger...\x1B[0m`);
    }, [sendPayload]);
    const sendPowerAction = import_react14.default.useCallback((action) => {
      if (!sendPayload({ type: "power_action", action })) return;
      const term = terminalInstanceRef.current;
      if (term) {
        term.writeln(`\x1B[1;33m[*] Sending ${action} command...\x1B[0m`);
      }
    }, [sendPayload]);
    const isProvisioning = ["installing", "reinstalling", "starting"].includes(status);
    const isRestrictedProvisioningViewer = !pageData.user?.isAdmin && ["installing", "reinstalling", "starting"].includes(status);
    const startDisabled = !connectorOnline || isProvisioning || ["running", "error"].includes(status);
    const restartDisabled = !connectorOnline || status !== "running";
    const stopDisabled = !connectorOnline || status !== "running";
    const memoryPercent = usagePercent(stats.memory, limits.memory);
    const diskPercent = usagePercent(stats.disk, limits.disk);
    const lastExitValue = exitInfo.exitCode ? `Exit code ${exitInfo.exitCode}` : "No exit data";
    const lastExitNote = exitInfo.exitCode ? exitInfo.oomKilled ? "OOM kill detected for the last exit." : "Last stop did not carry an OOM kill flag." : "The runtime has not reported an exit event in this session.";
    const cooldownUntil = Number.parseInt(String(runtimeMeta.cooldownUntil || 0), 10) || 0;
    const cooldownActive = cooldownUntil > Date.now();
    const cooldownValue = cooldownActive ? "Active" : "Idle";
    const cooldownNote = cooldownActive ? `Cooldown until ${new Date(cooldownUntil).toLocaleString()}${runtimeMeta.crashLoopCount ? ` \xB7 loop count ${runtimeMeta.crashLoopCount}` : ""}` : runtimeMeta.crashLoopCount ? `Crash loop count tracked: ${runtimeMeta.crashLoopCount}` : "No crash cooldown is active.";
    const consoleShortcuts = [
      { action: "Focus command input", keys: "Ctrl + K" },
      { action: "Send command", keys: "Ctrl + Enter" },
      { action: "Clear console output", keys: "Ctrl + L" },
      { action: "Search console", keys: "Ctrl + F" },
      { action: "Toggle auto-copy selection", keys: "Ctrl + Shift + C" },
      { action: "Browse command history", keys: "Arrow Up / Arrow Down" },
      { action: "Restart server", keys: "Ctrl + Shift + R" },
      { action: "Start/Stop server", keys: "Ctrl + Shift + S" }
    ];
    const commandInputRef = import_react14.default.useRef(null);
    import_react14.default.useEffect(() => {
      const handleGlobalKeyDown = (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === "k") {
          e.preventDefault();
          if (commandInputRef.current) commandInputRef.current.focus();
        }
        if ((e.ctrlKey || e.metaKey) && e.key === "l") {
          e.preventDefault();
          if (terminalInstanceRef.current) terminalInstanceRef.current.clear();
        }
        if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === "R") {
          e.preventDefault();
          if (!restartDisabled) sendPowerAction("restart");
        }
        if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === "S") {
          e.preventDefault();
          if (!startDisabled) sendPowerAction("start");
          else if (!stopDisabled) sendPowerAction("stop");
        }
      };
      window.addEventListener("keydown", handleGlobalKeyDown);
      return () => window.removeEventListener("keydown", handleGlobalKeyDown);
    }, [restartDisabled, startDisabled, stopDisabled, sendPowerAction]);
    const content = /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)(import_jsx_runtime14.Fragment, { children: [
      pageData.success && /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("div", { className: "bg-green-600/20 border border-green-600/50 text-green-100 p-4 rounded-lg mb-6 shadow-sm mx-4 lg:mx-8 mt-6", children: pageData.success }),
      pageData.error && /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("div", { className: "bg-red-600/20 border border-red-600/50 text-red-100 p-4 rounded-lg mb-6 shadow-sm mx-4 lg:mx-8 mt-6", children: pageData.error }),
      terminalError && /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("div", { className: "bg-red-600/20 border border-red-600/50 text-red-100 p-4 rounded-lg mb-6 shadow-sm mx-4 lg:mx-8 mt-6", children: terminalError }),
      /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: `p-4 lg:p-8 grid grid-cols-1 ${isPopout ? "" : "xl:grid-cols-4"} gap-6`, children: [
        /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: isPopout ? "" : "xl:col-span-3 flex flex-col gap-6 relative", children: [
          /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6", children: [
            /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "flex items-center gap-4", children: [
              /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("div", { className: `w-3 h-3 rounded-full shrink-0 ${getToneColorClass(statusTone(status))}` }),
              /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { children: [
                /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("h1", { className: "text-xl font-bold text-white tracking-wide", children: server.name || "Server Console" }),
                /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("p", { className: "text-sm text-neutral-400 mt-1", children: server.description || "Live runtime output and power controls." })
              ] })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "flex bg-neutral-800 rounded-lg border border-neutral-700/50 overflow-hidden shadow-sm shrink-0", children: [
              /* @__PURE__ */ (0, import_jsx_runtime14.jsx)(
                "button",
                {
                  type: "button",
                  className: "px-6 py-2.5 text-sm font-semibold hover:bg-neutral-700 hover:text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed border-r border-neutral-700/50 text-green-500",
                  onClick: () => sendPowerAction("start"),
                  disabled: startDisabled,
                  children: "Start"
                }
              ),
              /* @__PURE__ */ (0, import_jsx_runtime14.jsx)(
                "button",
                {
                  type: "button",
                  className: "px-6 py-2.5 text-sm font-semibold hover:bg-neutral-700 text-blue-400 hover:text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed border-r border-neutral-700/50",
                  onClick: () => sendPowerAction("restart"),
                  disabled: restartDisabled,
                  children: "Restart"
                }
              ),
              /* @__PURE__ */ (0, import_jsx_runtime14.jsx)(
                "button",
                {
                  type: "button",
                  className: "px-6 py-2.5 text-sm font-semibold hover:bg-neutral-700 text-red-500 hover:text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed",
                  onClick: () => sendPowerAction("stop"),
                  disabled: stopDisabled,
                  children: "Stop"
                }
              ),
              /* @__PURE__ */ (0, import_jsx_runtime14.jsx)(
                "button",
                {
                  type: "button",
                  className: `px-6 py-2.5 text-sm font-semibold hover:bg-neutral-700 text-red-600 hover:text-red-400 transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${status === "stopping" ? "" : "hidden"}`,
                  onClick: () => sendPowerAction("kill"),
                  children: "Kill"
                }
              )
            ] })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "flex flex-wrap gap-2 items-center bg-neutral-900 border border-neutral-800 p-4 rounded-2xl shadow-inner shadow-black/40 mb-6", children: [
            /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("span", { className: "text-[10px] font-black text-neutral-600 uppercase tracking-widest mr-2 flex items-center gap-1", children: [
              /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("i", { className: "bi bi-lightning-fill text-yellow-500" }),
              " Actions"
            ] }),
            macros.map((m) => /* @__PURE__ */ (0, import_jsx_runtime14.jsx)(
              "button",
              {
                onClick: () => runMacro(m.id),
                className: "px-3 py-1.5 bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 hover:border-neutral-500 rounded-xl text-[10px] font-black text-neutral-300 uppercase tracking-widest transition-all hover:scale-105 active:scale-95",
                children: m.name
              },
              m.id
            )),
            /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("div", { className: "flex-1" }),
            /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)(
              "button",
              {
                onClick: () => setShowShortcuts(true),
                className: "px-3 py-1.5 bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 rounded-xl text-[10px] font-black text-neutral-400 hover:text-neutral-200 uppercase tracking-widest transition-all",
                children: [
                  /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("i", { className: "bi bi-keyboard me-2" }),
                  " Shortcuts"
                ]
              }
            )
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: `bg-neutral-900 border border-neutral-700 rounded-lg flex flex-col overflow-hidden shadow-lg relative ${isPopout ? "h-[calc(100vh-280px)]" : "h-[600px]"}`, children: [
            isProvisioning && /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("div", { className: "absolute inset-0 bg-neutral-900/90 backdrop-blur-sm z-50 flex items-center justify-center p-6 text-center", children: /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "max-w-md w-full", children: [
              /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("div", { className: "w-12 h-12 rounded-full border-4 border-neutral-700 border-t-primary-500 animate-spin mb-6 mx-auto" }),
              /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("h2", { className: "text-lg font-bold text-white mb-2 uppercase tracking-wide", children: "Server Busy" }),
              /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("p", { className: "text-xs text-neutral-500 mb-6 font-bold uppercase tracking-widest", children: [
                "Current State: ",
                status
              ] }),
              isRestrictedProvisioningViewer ? /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "bg-red-500/10 border border-red-500/20 p-4 rounded-xl text-red-400 text-xs font-black uppercase tracking-widest leading-relaxed", children: [
                /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("i", { className: "bi bi-shield-lock me-2 text-sm" }),
                "Interaction is restricted during provisioning for security."
              ] }) : /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("div", { className: "bg-neutral-800/50 p-4 rounded-xl text-neutral-400 text-xs font-bold uppercase tracking-widest italic", children: "Admin access: Interaction enabled despite provisioning state." })
            ] }) }),
            /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "bg-neutral-800 border-b border-neutral-700 px-4 py-3 flex justify-between items-center z-10 shrink-0", children: [
              /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "flex items-center gap-3", children: [
                /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("span", { className: "flex h-2 w-2 rounded-full bg-primary-500 shadow-[0_0_8px_rgba(59,130,246,0.6)]" }),
                /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { children: [
                  /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("strong", { className: "text-neutral-100 font-bold block text-sm", children: "Interactive Console" }),
                  /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("span", { className: "text-[10px] text-neutral-500 font-black uppercase tracking-widest", children: "Live Runtime Link" })
                ] })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "flex bg-neutral-900 rounded-xl overflow-hidden border border-neutral-700 p-1 gap-1", children: [
                /* @__PURE__ */ (0, import_jsx_runtime14.jsx)(
                  "button",
                  {
                    className: `px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-widest transition-all ${followOutput ? "bg-primary-600 text-white shadow-lg" : "text-neutral-500 hover:text-neutral-300 hover:bg-neutral-800"}`,
                    onClick: () => setFollowOutput((current) => !current),
                    children: "Follow"
                  }
                ),
                /* @__PURE__ */ (0, import_jsx_runtime14.jsx)(
                  "button",
                  {
                    className: "px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-widest text-neutral-500 hover:text-neutral-300 hover:bg-neutral-800 transition-all",
                    onClick: () => {
                      const term = terminalInstanceRef.current;
                      if (term) term.clear();
                    },
                    children: "Clear"
                  }
                )
              ] })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("div", { className: `flex-1 relative ${terminalBooted ? "" : "opacity-0"} p-2`, style: { minHeight: 0 }, children: /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("div", { className: "w-full h-full", ref: terminalHostRef }) }),
            !terminalBooted && !terminalError && !isProvisioning && /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "absolute inset-x-0 bottom-16 top-16 flex items-center justify-center flex-col gap-4 text-neutral-500 bg-neutral-900/50 backdrop-blur-sm z-30", children: [
              /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("div", { className: "w-8 h-8 border-4 border-neutral-700 border-t-primary-500 rounded-full animate-spin" }),
              /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("span", { className: "text-[10px] font-black uppercase tracking-widest", children: "Initializing Xterm..." })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "bg-neutral-800 border-t border-neutral-700 flex flex-col md:flex-row items-center shrink-0", children: [
              /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "flex-1 flex items-center w-full min-w-0", children: [
                /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("span", { className: "text-neutral-500 pl-4 font-mono font-bold", children: "$" }),
                /* @__PURE__ */ (0, import_jsx_runtime14.jsx)(
                  "input",
                  {
                    ref: commandInputRef,
                    type: "text",
                    className: "w-full bg-transparent border-none text-neutral-200 text-sm font-mono px-3 py-4 focus:ring-0 shadow-none outline-none disabled:opacity-50 disabled:cursor-not-allowed",
                    value: commandValue,
                    onChange: (event) => setCommandValue(event.target.value),
                    onKeyDown: (event) => {
                      if (event.key === "Enter") {
                        event.preventDefault();
                        sendCommand();
                        return;
                      }
                      if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
                        event.preventDefault();
                        sendCommand();
                        return;
                      }
                      if (event.key === "ArrowUp") {
                        event.preventDefault();
                        if (!history.length) return;
                        historyIndexRef.current = Math.min(historyIndexRef.current + 1, history.length - 1);
                        setCommandValue(history[historyIndexRef.current] || "");
                        return;
                      }
                      if (event.key === "ArrowDown") {
                        event.preventDefault();
                        if (!history.length) return;
                        historyIndexRef.current = Math.max(historyIndexRef.current - 1, -1);
                        setCommandValue(historyIndexRef.current >= 0 ? history[historyIndexRef.current] || "" : "");
                      }
                    },
                    placeholder: isRestrictedProvisioningViewer ? "Input locked during provisioning" : connectorOnline ? "Type a command and press Enter..." : "Connector offline",
                    disabled: !connectorOnline || isRestrictedProvisioningViewer
                  }
                )
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("div", { className: "flex items-center w-full md:w-auto border-t md:border-t-0 md:border-l border-neutral-700 h-full", children: /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)(
                "button",
                {
                  className: "px-10 py-4 bg-primary-600 hover:bg-primary-500 font-black text-white text-[10px] uppercase tracking-[0.2em] transition-all disabled:opacity-50 disabled:cursor-not-allowed active:scale-95 flex items-center justify-center gap-2 h-full",
                  onClick: sendCommand,
                  disabled: !connectorOnline || !String(commandValue || "").trim() || isRestrictedProvisioningViewer,
                  children: [
                    "Execute ",
                    /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("i", { className: "bi bi-terminal-fill" })
                  ]
                }
              ) })
            ] })
          ] }),
          showShortcuts && /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "fixed inset-0 z-[100] flex items-center justify-center p-6", children: [
            /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("div", { className: "absolute inset-0 bg-black/60 backdrop-blur-md", onClick: () => setShowShortcuts(false) }),
            /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "relative w-full max-w-lg bg-neutral-900 border border-neutral-800 rounded-[2.5rem] shadow-2xl overflow-hidden ring-1 ring-white/10", children: [
              /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "p-8 border-b border-neutral-800 flex justify-between items-center", children: [
                /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { children: [
                  /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("h2", { className: "text-xl font-bold text-white tracking-tight", children: "Console Shortcuts" }),
                  /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("p", { className: "text-xs text-neutral-500 font-bold uppercase tracking-widest mt-1", children: "Boost your terminal workflow" })
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("button", { onClick: () => setShowShortcuts(false), className: "w-10 h-10 flex items-center justify-center rounded-xl bg-neutral-800 text-neutral-400 hover:text-white transition-colors", children: /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("i", { className: "bi bi-x-lg" }) })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("div", { className: "p-8 space-y-4", children: consoleShortcuts.map((sc, i) => /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "flex justify-between items-center group", children: [
                /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("span", { className: "text-sm font-bold text-neutral-400 group-hover:text-neutral-200 transition-colors", children: sc.action }),
                /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("kbd", { className: "px-3 py-1 bg-neutral-800 border border-neutral-700 rounded-lg text-[10px] font-black text-primary-400 font-mono scale-110 shadow-lg shadow-black/20", children: sc.keys })
              ] }, i)) }),
              /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("div", { className: "p-8 bg-neutral-800/50 flex justify-center", children: /* @__PURE__ */ (0, import_jsx_runtime14.jsx)(
                "button",
                {
                  onClick: () => setShowShortcuts(false),
                  className: "px-8 py-3 bg-neutral-900 hover:bg-neutral-800 text-neutral-200 border border-neutral-700 rounded-xl text-[10px] font-black uppercase tracking-[0.2em] transition-all",
                  children: "Close Reference"
                }
              ) })
            ] })
          ] })
        ] }),
        !isPopout && /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("aside", { className: "xl:col-span-1 flex flex-col gap-4", children: [
          /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-2xl p-5 shadow-lg", children: [
            /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-4 flex items-center gap-2", children: [
              /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("i", { className: "bi bi-broadcast text-primary-400" }),
              " Connectivity"
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "space-y-4", children: [
              /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: `p-4 rounded-xl border flex flex-col gap-1 ${connectorOnline ? "bg-green-500/5 border-green-500/10" : "bg-red-500/5 border-red-500/10"}`, children: [
                /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "flex items-center justify-between", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("span", { className: "text-[10px] font-bold text-neutral-500 uppercase tracking-wider", children: "Daemon Status" }),
                  /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("div", { className: `w-2 h-2 rounded-full ${connectorOnline ? "bg-green-500 shadow-[0_0_10px_rgba(34,197,94,0.4)]" : "bg-red-500"}` })
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("span", { className: `text-sm font-black uppercase tracking-widest ${connectorOnline ? "text-green-400" : "text-red-400"}`, children: connectionState })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "grid grid-cols-2 gap-2", children: [
                /* @__PURE__ */ (0, import_jsx_runtime14.jsx)(Link, { to: ReactRoutes.changeView, className: "bg-neutral-900 border border-neutral-700 hover:border-neutral-500 text-neutral-300 text-[10px] font-black uppercase tracking-widest py-2.5 rounded-xl text-center transition-all", children: "View Mode" }),
                /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("a", { href: `/server/${server.containerId}?popout=true`, target: "_blank", rel: "noopener noreferrer", className: "bg-neutral-900 border border-neutral-700 hover:border-neutral-500 text-neutral-300 text-[10px] font-black uppercase tracking-widest py-2.5 rounded-xl text-center transition-all", children: "Popout" })
              ] })
            ] })
          ] }),
          isMinecraft && /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-2xl p-5 shadow-lg flex flex-col max-h-[400px]", children: [
            /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "flex justify-between items-center mb-4", children: [
              /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "text-[10px] font-black text-neutral-500 uppercase tracking-widest flex items-center gap-2", children: [
                /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("i", { className: "bi bi-people text-primary-400" }),
                " Players"
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("span", { className: "text-[10px] font-black bg-neutral-900 border border-neutral-700 px-2 py-0.5 rounded-lg text-neutral-400", children: [
                players.length,
                " Active"
              ] })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("div", { className: "flex-1 overflow-y-auto pr-1 custom-scrollbar", children: playersLoading ? /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("div", { className: "text-[10px] font-black text-neutral-600 uppercase tracking-widest text-center py-8", children: "Syncing..." }) : playersError ? /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("div", { className: "text-[10px] font-black text-red-500 uppercase tracking-widest text-center py-8", children: playersError }) : players.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("div", { className: "text-[10px] font-black text-neutral-600 uppercase tracking-widest text-center py-8", children: "Void Empty" }) : /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("div", { className: "flex flex-col gap-2", children: players.map((p) => /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "bg-neutral-900 border border-neutral-700/30 p-2 rounded-xl flex items-center justify-between group transition-colors hover:border-neutral-600", children: [
              /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "flex items-center gap-2 min-w-0", children: [
                /* @__PURE__ */ (0, import_jsx_runtime14.jsx)(
                  "img",
                  {
                    src: p.headUrl,
                    className: "w-6 h-6 rounded shadow-sm grayscale group-hover:grayscale-0 transition-all",
                    alt: p.name,
                    onError: (e) => {
                      e.target.src = "https://minotar.net/avatar/Steve/40";
                    }
                  }
                ),
                /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("span", { className: "text-xs font-bold text-neutral-300 truncate", children: p.name })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity", children: [
                /* @__PURE__ */ (0, import_jsx_runtime14.jsx)(
                  "button",
                  {
                    onClick: () => handleMcAction("kick", p.name),
                    disabled: !mcPerms.canKick,
                    className: "w-6 h-6 flex items-center justify-center bg-neutral-800 hover:bg-red-900/40 text-neutral-400 hover:text-red-400 rounded-lg transition-colors",
                    title: "Kick",
                    children: /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("i", { className: "bi bi-door-open-fill text-[10px]" })
                  }
                ),
                /* @__PURE__ */ (0, import_jsx_runtime14.jsx)(
                  "button",
                  {
                    onClick: () => handleMcAction("ban", p.name),
                    disabled: !mcPerms.canBan,
                    className: "w-6 h-6 flex items-center justify-center bg-neutral-800 hover:bg-red-900 text-neutral-400 hover:text-white rounded-lg transition-colors",
                    title: "Ban",
                    children: /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("i", { className: "bi bi-hammer text-[10px]" })
                  }
                )
              ] })
            ] }, p.name)) }) })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-2xl p-5 shadow-lg", children: [
            /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-4 flex items-center gap-2", children: [
              /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("i", { className: "bi bi-cpu text-primary-400" }),
              " Vital Metrics"
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "space-y-1", children: [
              /* @__PURE__ */ (0, import_jsx_runtime14.jsx)(InlineMetric, { title: "Core Load", value: `${stats.cpu.toFixed(1)}%`, note: limits.cpu ? `${limits.cpu}% cap` : "No cap", tone: "primary" }),
              /* @__PURE__ */ (0, import_jsx_runtime14.jsx)(InlineMetric, { title: "Memory Buffer", value: `${Math.round(stats.memory)} MB`, note: `${memoryPercent.toFixed(0)}% used`, tone: "success" }),
              /* @__PURE__ */ (0, import_jsx_runtime14.jsx)(InlineMetric, { title: "Disk Index", value: `${Math.round(stats.disk)} MB`, note: `${diskPercent.toFixed(0)}% used`, tone: "warning" }),
              /* @__PURE__ */ (0, import_jsx_runtime14.jsx)(InlineMetric, { title: "Session Time", value: formatDuration(stats.uptimeSeconds), note: "Current runtime session" }),
              /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("div", { className: "h-px bg-neutral-700/50 my-4" }),
              /* @__PURE__ */ (0, import_jsx_runtime14.jsxs)("div", { className: "text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-4 flex items-center gap-2", children: [
                /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("i", { className: "bi bi-shield-check text-primary-400" }),
                " Guard System"
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime14.jsx)(InlineMetric, { title: "Last Trigger", value: formatRuntimeSource(runtimeMeta.lastSource), note: runtimeMeta.lastReason || "Stable state." }),
              /* @__PURE__ */ (0, import_jsx_runtime14.jsx)(InlineMetric, { title: "Cooldown", value: cooldownValue, note: cooldownNote, tone: cooldownActive ? "warning" : "primary" }),
              /* @__PURE__ */ (0, import_jsx_runtime14.jsx)(InlineMetric, { title: "Exit Trace", value: lastExitValue, note: lastExitNote, tone: exitInfo.oomKilled ? "danger" : "primary" })
            ] })
          ] })
        ] })
      ] })
    ] });
    if (isPopout) {
      return /* @__PURE__ */ (0, import_jsx_runtime14.jsx)("div", { className: "min-h-screen bg-neutral-900 text-neutral-200", children: content });
    }
    return /* @__PURE__ */ (0, import_jsx_runtime14.jsx)(ReactAppShell, { pageData, subtitle: "React server console", children: content });
  }
  if (root2) {
    root2.render(
      /* @__PURE__ */ (0, import_jsx_runtime14.jsx)(ThemeContext_default, { pageData: data2, children: /* @__PURE__ */ (0, import_jsx_runtime14.jsx)(ServerConsolePage, { pageData: data2 }) })
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === "function") {
      window.__CPANEL_REACT_BOOTED__();
    }
  }

  // views/react/server-files.jsx
  var import_react15 = __toESM(require_react());
  var import_client3 = __toESM(require_client());
  var import_jsx_runtime15 = __toESM(require_jsx_runtime());
  var data3 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry3 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "server-files";
  var root3 = standaloneEntry3 ? (0, import_client3.createRoot)(document.getElementById("reactRoot")) : null;
  function normalizePath(v) {
    const r = String(v || "/").trim().replace(/\\/g, "/");
    if (!r || r === "/") return "/";
    const n = r.startsWith("/") ? r : `/${r}`;
    return n.replace(/\/+/g, "/").replace(/\/$/, "") || "/";
  }
  function formatBytes(v) {
    const b = Math.max(0, Number(v) || 0);
    if (!b) return "0 B";
    const u = ["B", "KB", "MB", "GB", "TB"];
    let c = b, i = 0;
    while (c >= 1024 && i < u.length - 1) {
      c /= 1024;
      i++;
    }
    return `${c >= 100 || i === 0 ? c.toFixed(0) : c.toFixed(2)} ${u[i]}`;
  }
  function formatDate(v) {
    if (!v) return "\u2014";
    const d = new Date(v);
    return isNaN(d) ? "\u2014" : d.toLocaleString();
  }
  function buildBreadcrumbs(path) {
    const n = normalizePath(path);
    if (n === "/") return [{ label: "", path: "/", icon: true }];
    const parts = n.split("/").filter(Boolean);
    const segs = [{ label: "", path: "/", icon: true }];
    let cur = "";
    parts.forEach((p) => {
      cur += `/${p}`;
      segs.push({ label: p, path: cur });
    });
    return segs;
  }
  function getFileIcon(entry) {
    if (entry.isDirectory) return "bi-folder-fill text-amber-400";
    const ext = (entry.name || "").split(".").pop().toLowerCase();
    const map = {
      js: "bi-filetype-js text-yellow-400",
      ts: "bi-filetype-ts text-blue-400",
      json: "bi-filetype-json text-green-400",
      yml: "bi-filetype-yml text-orange-400",
      yaml: "bi-filetype-yml text-orange-400",
      xml: "bi-filetype-xml text-orange-300",
      html: "bi-filetype-html text-orange-500",
      css: "bi-filetype-css text-blue-500",
      py: "bi-filetype-py text-green-500",
      php: "bi-filetype-php text-purple-400",
      sh: "bi-terminal text-green-300",
      md: "bi-filetype-md text-neutral-300",
      txt: "bi-file-earmark-text text-neutral-400",
      zip: "bi-file-zip text-yellow-500",
      tar: "bi-file-zip text-yellow-500",
      gz: "bi-file-zip text-yellow-500",
      jar: "bi-file-zip-fill text-red-400",
      png: "bi-file-earmark-image text-pink-400",
      jpg: "bi-file-earmark-image text-pink-400",
      jpeg: "bi-file-earmark-image text-pink-400",
      gif: "bi-file-earmark-image text-pink-400",
      mp4: "bi-file-earmark-play text-red-400",
      mp3: "bi-file-earmark-music text-purple-400",
      db: "bi-database text-blue-300",
      sqlite: "bi-database text-blue-300",
      sql: "bi-database-fill text-blue-300",
      log: "bi-file-earmark-text text-neutral-400",
      conf: "bi-gear text-neutral-400",
      cfg: "bi-gear text-neutral-400",
      ini: "bi-gear text-neutral-400",
      properties: "bi-gear text-neutral-400"
    };
    return map[ext] || "bi-file-earmark text-neutral-500";
  }
  var ARCHIVE_EXTS = [".zip", ".tar", ".tar.gz", ".tgz", ".gz", ".rar", ".7z"];
  function isArchive(name) {
    return ARCHIVE_EXTS.some((e) => name.toLowerCase().endsWith(e));
  }
  var MEDIA_IMAGE_EXTS = [".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".bmp"];
  var MEDIA_VIDEO_EXTS = [".mp4", ".webm", ".mov", ".ogg"];
  function mediaKind(name) {
    const n = name.toLowerCase();
    if (MEDIA_IMAGE_EXTS.some((e) => n.endsWith(e))) return "image";
    if (MEDIA_VIDEO_EXTS.some((e) => n.endsWith(e))) return "video";
    return null;
  }
  function Modal({ isOpen, onClose, title, children, maxW = "max-w-md" }) {
    (0, import_react15.useEffect)(() => {
      if (!isOpen) return;
      const handle = (e) => {
        if (e.key === "Escape") onClose();
      };
      window.addEventListener("keydown", handle);
      return () => window.removeEventListener("keydown", handle);
    }, [isOpen, onClose]);
    if (!isOpen) return null;
    return /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "fixed inset-0 z-[200] flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm", onClick: (e) => {
      if (e.target === e.currentTarget) onClose();
    }, children: /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: `bg-[#0f1115] border border-neutral-800 rounded-2xl w-full ${maxW} shadow-2xl overflow-hidden`, children: [
      /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "px-6 py-4 border-b border-neutral-800 flex justify-between items-center", children: [
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("h3", { className: "text-base font-bold text-white", children: title }),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("button", { onClick: onClose, className: "w-7 h-7 rounded flex items-center justify-center text-neutral-500 hover:text-white hover:bg-neutral-800 transition-colors", children: /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-x-lg text-sm" }) })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "p-6", children })
    ] }) });
  }
  function SearchModal({ isOpen, onClose, serverId, onNavigate }) {
    const [query, setQuery] = (0, import_react15.useState)("");
    const [filter, setFilter] = (0, import_react15.useState)("all");
    const [results, setResults] = (0, import_react15.useState)(null);
    const [loading, setLoading] = (0, import_react15.useState)(false);
    const [error, setError] = (0, import_react15.useState)("");
    const abortRef = (0, import_react15.useRef)(null);
    const doSearch = (0, import_react15.useCallback)(async () => {
      if (!query.trim()) return;
      if (abortRef.current) abortRef.current.abort();
      const ctrl = new AbortController();
      abortRef.current = ctrl;
      setLoading(true);
      setError("");
      setResults(null);
      try {
        const params = new URLSearchParams({ q: query.trim(), filter });
        const res = await fetch(`/server/${serverId}/files-search?${params}`, { signal: ctrl.signal });
        const payload = await res.json();
        if (!res.ok || payload.error) throw new Error(payload.error || "Search failed");
        setResults(payload.results || []);
      } catch (e) {
        if (e.name !== "AbortError") setError(e.message);
      } finally {
        setLoading(false);
      }
    }, [query, filter, serverId]);
    (0, import_react15.useEffect)(() => {
      if (!isOpen) {
        setQuery("");
        setResults(null);
        setError("");
      }
    }, [isOpen]);
    return /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)(Modal, { isOpen, onClose, title: "Search Files", maxW: "max-w-2xl", children: [
      /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "flex gap-2 mb-4", children: [
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(
          "input",
          {
            autoFocus: true,
            type: "text",
            value: query,
            onChange: (e) => setQuery(e.target.value),
            onKeyDown: (e) => e.key === "Enter" && doSearch(),
            className: "flex-1 bg-neutral-950 border border-neutral-700 rounded-lg px-4 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500",
            placeholder: "Search filename or path\u2026"
          }
        ),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)(
          "select",
          {
            value: filter,
            onChange: (e) => setFilter(e.target.value),
            className: "bg-neutral-950 border border-neutral-700 rounded-lg px-3 py-2 text-sm text-neutral-300 focus:outline-none",
            children: [
              /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("option", { value: "all", children: "All" }),
              /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("option", { value: "files", children: "Files only" }),
              /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("option", { value: "folders", children: "Folders only" })
            ]
          }
        ),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("button", { onClick: doSearch, disabled: loading || !query.trim(), className: "bg-primary-600 hover:bg-primary-500 disabled:bg-neutral-700 text-white rounded-lg px-4 py-2 text-sm font-bold transition-colors flex items-center gap-2", children: [
          loading ? /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" }) : /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-search" }),
          "Search"
        ] })
      ] }),
      error && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "text-sm text-red-400 mb-3", children: error }),
      results && /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "max-h-80 overflow-y-auto rounded-lg border border-neutral-800 divide-y divide-neutral-800/50", children: [
        results.length === 0 && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "p-8 text-center text-neutral-500 text-sm", children: "No results found." }),
        results.map((r, i) => {
          const parent = r.path.split("/").slice(0, -1).join("/") || "/";
          return /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "px-4 py-3 hover:bg-neutral-800/40 transition-colors", children: [
            /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "flex items-center gap-2 min-w-0", children: [
              /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: `bi ${r.isDirectory ? "bi-folder-fill text-amber-400" : "bi-file-earmark text-neutral-400"} shrink-0` }),
              /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("span", { className: "text-sm font-semibold text-neutral-200 truncate", children: r.name }),
              r.isDirectory ? /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("button", { onClick: () => {
                onNavigate(r.path);
                onClose();
              }, className: "ml-auto shrink-0 text-xs text-primary-400 hover:underline", children: "Open" }) : /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("a", { href: `/server/${serverId}/files/edit?path=${encodeURIComponent(r.path)}`, className: "ml-auto shrink-0 text-xs text-primary-400 hover:underline", children: "Edit" })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("button", { onClick: () => {
              onNavigate(parent);
              onClose();
            }, className: "text-xs text-neutral-500 hover:text-neutral-300 mt-0.5 truncate text-left", children: r.path })
          ] }, i);
        })
      ] })
    ] });
  }
  function SftpModal({ isOpen, onClose, sftpDetails }) {
    const d = sftpDetails || {};
    return /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)(Modal, { isOpen, onClose, title: "SFTP Details", children: [
      /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "space-y-3 mb-6", children: [
        [["Host", d.host || "\u2014"], ["Port", d.port || "\u2014"], ["Username", d.username || "\u2014"]].map(([label, val]) => /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "flex justify-between items-center border-b border-neutral-800 pb-3", children: [
          /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("span", { className: "text-xs font-bold text-neutral-500 uppercase tracking-widest", children: label }),
          /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("span", { className: "text-sm font-mono text-neutral-200", children: val })
        ] }, label)),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "flex justify-between items-start", children: [
          /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("span", { className: "text-xs font-bold text-neutral-500 uppercase tracking-widest", children: "Password" }),
          /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("span", { className: "text-xs text-neutral-400", children: d.passwordHint || "Use your panel password" })
        ] })
      ] }),
      d.host && d.port && /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "bg-neutral-950 rounded-lg p-3 font-mono text-xs text-neutral-400 break-all select-all", children: [
        "sftp://",
        d.username,
        "@",
        d.host,
        ":",
        d.port
      ] })
    ] });
  }
  function BulkBar({ selected, writeLocked, onBulkDelete, onBulkRename, onBulkChmod, onBulkArchive, onClear }) {
    if (selected.size === 0) return null;
    return /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "sticky top-0 z-30 bg-primary-950/90 backdrop-blur-md border border-primary-800/50 rounded-xl px-4 py-3 mb-4 flex items-center gap-3 flex-wrap shadow-xl shadow-primary-900/20", children: [
      /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("span", { className: "text-sm font-black text-primary-300", children: [
        selected.size,
        " selected"
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "flex-1 h-px bg-primary-800/30" }),
      !writeLocked && /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)(import_jsx_runtime15.Fragment, { children: [
        /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("button", { onClick: onBulkRename, className: "flex items-center gap-2 text-xs font-bold text-neutral-300 hover:text-white bg-neutral-800/80 hover:bg-neutral-700 px-3 py-1.5 rounded-lg transition-colors", children: [
          /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-input-cursor-text" }),
          " Rename"
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("button", { onClick: onBulkChmod, className: "flex items-center gap-2 text-xs font-bold text-neutral-300 hover:text-white bg-neutral-800/80 hover:bg-neutral-700 px-3 py-1.5 rounded-lg transition-colors", children: [
          /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-shield-check" }),
          " CHMOD"
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("button", { onClick: onBulkArchive, className: "flex items-center gap-2 text-xs font-bold text-neutral-300 hover:text-white bg-neutral-800/80 hover:bg-neutral-700 px-3 py-1.5 rounded-lg transition-colors", children: [
          /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-file-zip text-yellow-400" }),
          " Archive"
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("button", { onClick: onBulkDelete, className: "flex items-center gap-2 text-xs font-bold text-red-400 hover:text-white bg-red-900/20 hover:bg-red-900/40 px-3 py-1.5 rounded-lg transition-colors border border-red-900/30", children: [
          /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-trash3" }),
          " Delete ",
          selected.size
        ] })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("button", { onClick: onClear, className: "text-xs text-neutral-500 hover:text-white transition-colors ml-auto", children: /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-x-lg" }) })
    ] });
  }
  function BulkRenameModal({ isOpen, onClose, serverId, currentPath, selectedNames, onComplete }) {
    const [prefix, setPrefix] = (0, import_react15.useState)("");
    const [suffix, setSuffix] = (0, import_react15.useState)("");
    const [loading, setLoading] = (0, import_react15.useState)(false);
    const [error, setError] = (0, import_react15.useState)("");
    (0, import_react15.useEffect)(() => {
      if (isOpen) {
        setPrefix("");
        setSuffix("");
        setError("");
      }
    }, [isOpen]);
    const doRename = async () => {
      if (!prefix && !suffix) return;
      setLoading(true);
      setError("");
      const files = [...selectedNames].map((n) => ({ from: n, to: `${prefix}${n}${suffix}` }));
      try {
        const res = await fetch(`/api/client/servers/${serverId}/files/rename`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ directory: currentPath, files })
        });
        const p = await res.json();
        if (!res.ok || p.error) throw new Error(p.error || "Rename failed");
        onComplete();
        onClose();
      } catch (e) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    };
    return /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)(Modal, { isOpen, onClose, title: `Bulk Rename (${selectedNames.size} items)`, children: [
      error && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "text-sm text-red-400 mb-4", children: error }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "space-y-4 mb-6", children: [
        /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { children: [
          /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("label", { className: "block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-1.5", children: "Add Prefix" }),
          /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("input", { type: "text", value: prefix, onChange: (e) => setPrefix(e.target.value), placeholder: "e.g. backup_", className: "w-full bg-neutral-950 border border-neutral-700 rounded-lg px-4 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500" })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { children: [
          /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("label", { className: "block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-1.5", children: "Add Suffix" }),
          /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("input", { type: "text", value: suffix, onChange: (e) => setSuffix(e.target.value), placeholder: "e.g. .bak", className: "w-full bg-neutral-950 border border-neutral-700 rounded-lg px-4 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500" })
        ] }),
        [...selectedNames].slice(0, 3).map((n) => /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "text-xs font-mono text-neutral-500", children: [
          n,
          " ",
          /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("span", { className: "text-neutral-600", children: "\u2192" }),
          " ",
          /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("span", { className: "text-primary-400", children: [
            prefix,
            n,
            suffix
          ] })
        ] }, n)),
        selectedNames.size > 3 && /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "text-xs text-neutral-600", children: [
          "\u2026and ",
          selectedNames.size - 3,
          " more"
        ] })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "flex justify-end gap-3", children: [
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("button", { onClick: onClose, className: "text-sm text-neutral-500 hover:text-white px-4", children: "Cancel" }),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("button", { onClick: doRename, disabled: loading || !prefix && !suffix, className: "bg-primary-600 hover:bg-primary-500 disabled:bg-neutral-700 text-white text-sm font-bold px-5 py-2 rounded-lg transition-colors flex items-center gap-2", children: [
          loading && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" }),
          "Apply"
        ] })
      ] })
    ] });
  }
  function BulkChmodModal({ isOpen, onClose, serverId, currentPath, selectedNames, onComplete }) {
    const [mode, setMode] = (0, import_react15.useState)("755");
    const [loading, setLoading] = (0, import_react15.useState)(false);
    const [error, setError] = (0, import_react15.useState)("");
    (0, import_react15.useEffect)(() => {
      if (isOpen) {
        setMode("755");
        setError("");
      }
    }, [isOpen]);
    const doChmod = async () => {
      setLoading(true);
      setError("");
      const files = [...selectedNames].map((n) => ({ file: n, mode }));
      try {
        const res = await fetch(`/api/client/servers/${serverId}/files/chmod`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ directory: currentPath, files })
        });
        const p = await res.json();
        if (!res.ok || p.error) throw new Error(p.error || "CHMOD failed");
        onComplete();
        onClose();
      } catch (e) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    };
    return /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)(Modal, { isOpen, onClose, title: `Bulk CHMOD (${selectedNames.size} items)`, maxW: "max-w-sm", children: [
      error && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "text-sm text-red-400 mb-4", children: error }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "mb-6", children: [
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("label", { className: "block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-2", children: "Octal Mode" }),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("input", { autoFocus: true, type: "text", value: mode, onChange: (e) => setMode(e.target.value.replace(/[^0-7]/g, "").slice(0, 4)), placeholder: "755", className: "w-full bg-neutral-950 border border-neutral-700 rounded-lg px-4 py-2.5 font-mono text-neutral-200 focus:outline-none focus:border-primary-500" })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "flex justify-end gap-3", children: [
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("button", { onClick: onClose, className: "text-sm text-neutral-500 hover:text-white px-4", children: "Cancel" }),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("button", { onClick: doChmod, disabled: loading, className: "bg-primary-600 hover:bg-primary-500 disabled:bg-neutral-700 text-white text-sm font-bold px-5 py-2 rounded-lg transition-colors flex items-center gap-2", children: [
          loading && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" }),
          "Apply to ",
          selectedNames.size
        ] })
      ] })
    ] });
  }
  function ArchiveModal({ isOpen, onClose, serverId, currentPath, targetNames, onComplete }) {
    const [name, setName] = (0, import_react15.useState)("");
    const [loading, setLoading] = (0, import_react15.useState)(false);
    const [error, setError] = (0, import_react15.useState)("");
    (0, import_react15.useEffect)(() => {
      if (isOpen) {
        const base = [...targetNames][0] || "archive";
        setName(targetNames.size === 1 ? `${base}.zip` : "archive.zip");
        setError("");
      }
    }, [isOpen, targetNames]);
    const doArchive = async () => {
      if (!name.trim()) return;
      setLoading(true);
      setError("");
      try {
        const res = await fetch(`/api/client/servers/${serverId}/files/archive`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ directory: currentPath, files: [...targetNames], name: name.trim() })
        });
        const p = await res.json();
        if (!res.ok || p.error) throw new Error(p.error || "Archive failed");
        onComplete();
        onClose();
      } catch (e) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    };
    return /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)(Modal, { isOpen, onClose, title: "Create Archive", maxW: "max-w-sm", children: [
      error && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "text-sm text-red-400 mb-4", children: error }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "mb-6", children: [
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("label", { className: "block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-2", children: "Archive Name" }),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("input", { autoFocus: true, type: "text", value: name, onChange: (e) => setName(e.target.value), placeholder: "archive.zip", className: "w-full bg-neutral-950 border border-neutral-700 rounded-lg px-4 py-2.5 text-neutral-200 focus:outline-none focus:border-primary-500" }),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "text-xs text-neutral-600 mt-2", children: [
          targetNames.size,
          " item(s) \u2192 ",
          name || "archive.zip"
        ] })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "flex justify-end gap-3", children: [
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("button", { onClick: onClose, className: "text-sm text-neutral-500 hover:text-white px-4", children: "Cancel" }),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("button", { onClick: doArchive, disabled: loading || !name.trim(), className: "bg-primary-600 hover:bg-primary-500 disabled:bg-neutral-700 text-white text-sm font-bold px-5 py-2 rounded-lg transition-colors flex items-center gap-2", children: [
          loading && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" }),
          "Create"
        ] })
      ] })
    ] });
  }
  function DeleteModal({ isOpen, onClose, serverId, currentPath, targetNames, onComplete }) {
    const [loading, setLoading] = (0, import_react15.useState)(false);
    const [error, setError] = (0, import_react15.useState)("");
    (0, import_react15.useEffect)(() => {
      if (isOpen) setError("");
    }, [isOpen]);
    const doDelete = async () => {
      setLoading(true);
      setError("");
      try {
        const res = await fetch(`/api/client/servers/${serverId}/files/delete`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ directory: currentPath, files: [...targetNames] })
        });
        const p = await res.json();
        if (!res.ok || p.error) throw new Error(p.error || "Delete failed");
        onComplete();
        onClose();
      } catch (e) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    };
    return /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)(Modal, { isOpen, onClose, title: "Confirm Delete", maxW: "max-w-sm", children: [
      error && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "text-sm text-red-400 mb-4", children: error }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "bg-red-950/20 border border-red-900/30 rounded-xl px-4 py-3 mb-6 text-sm text-red-300", children: [
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-exclamation-triangle-fill mr-2 text-red-500" }),
        "This action is ",
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("strong", { children: "permanent" }),
        " and cannot be undone.",
        /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "mt-2 font-mono text-xs text-red-400/80", children: [
          [...targetNames].slice(0, 5).join(", "),
          targetNames.size > 5 ? ` \u2026+${targetNames.size - 5} more` : ""
        ] })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "flex justify-end gap-3", children: [
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("button", { onClick: onClose, className: "text-sm text-neutral-500 hover:text-white px-4", children: "Cancel" }),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("button", { onClick: doDelete, disabled: loading, className: "bg-red-600 hover:bg-red-500 disabled:bg-neutral-700 text-white text-sm font-bold px-5 py-2 rounded-lg transition-colors flex items-center gap-2", children: [
          loading && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" }),
          "Delete ",
          targetNames.size,
          " ",
          targetNames.size === 1 ? "item" : "items"
        ] })
      ] })
    ] });
  }
  function RenameModal({ isOpen, onClose, serverId, currentPath, targetName, onComplete }) {
    const [val, setVal] = (0, import_react15.useState)("");
    const [loading, setLoading] = (0, import_react15.useState)(false);
    const [error, setError] = (0, import_react15.useState)("");
    (0, import_react15.useEffect)(() => {
      if (isOpen) {
        setVal(targetName || "");
        setError("");
      }
    }, [isOpen, targetName]);
    const doRename = async () => {
      if (!val.trim() || val === targetName) return;
      setLoading(true);
      setError("");
      try {
        const res = await fetch(`/api/client/servers/${serverId}/files/rename`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ directory: currentPath, files: [{ from: targetName, to: val.trim() }] })
        });
        const p = await res.json();
        if (!res.ok || p.error) throw new Error(p.error || "Rename failed");
        onComplete();
        onClose();
      } catch (e) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    };
    return /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)(Modal, { isOpen, onClose, title: "Rename", maxW: "max-w-sm", children: [
      error && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "text-sm text-red-400 mb-4", children: error }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("input", { autoFocus: true, type: "text", value: val, onChange: (e) => setVal(e.target.value), onKeyDown: (e) => e.key === "Enter" && doRename(), className: "w-full bg-neutral-950 border border-neutral-700 rounded-lg px-4 py-2.5 text-neutral-200 mb-6 focus:outline-none focus:border-primary-500" }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "flex justify-end gap-3", children: [
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("button", { onClick: onClose, className: "text-sm text-neutral-500 hover:text-white px-4", children: "Cancel" }),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("button", { onClick: doRename, disabled: loading || !val.trim() || val === targetName, className: "bg-primary-600 hover:bg-primary-500 disabled:bg-neutral-700 text-white text-sm font-bold px-5 py-2 rounded-lg transition-colors flex items-center gap-2", children: [
          loading && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" }),
          "Rename"
        ] })
      ] })
    ] });
  }
  function ChmodModal({ isOpen, onClose, serverId, currentPath, targetName, currentPerms, onComplete }) {
    const [mode, setMode] = (0, import_react15.useState)("");
    const [loading, setLoading] = (0, import_react15.useState)(false);
    const [error, setError] = (0, import_react15.useState)("");
    (0, import_react15.useEffect)(() => {
      if (isOpen) {
        setMode(currentPerms || "755");
        setError("");
      }
    }, [isOpen, currentPerms]);
    const doChmod = async () => {
      setLoading(true);
      setError("");
      try {
        const res = await fetch(`/api/client/servers/${serverId}/files/chmod`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ directory: currentPath, files: [{ file: targetName, mode }] })
        });
        const p = await res.json();
        if (!res.ok || p.error) throw new Error(p.error || "CHMOD failed");
        onComplete();
        onClose();
      } catch (e) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    };
    return /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)(Modal, { isOpen, onClose, title: "Change Permissions", maxW: "max-w-xs", children: [
      error && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "text-sm text-red-400 mb-4", children: error }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "mb-2", children: [
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "text-xs text-neutral-500 font-mono truncate mb-3", children: targetName }),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("input", { autoFocus: true, type: "text", value: mode, onChange: (e) => setMode(e.target.value.replace(/[^0-7]/g, "").slice(0, 4)), onKeyDown: (e) => e.key === "Enter" && doChmod(), placeholder: "755", className: "w-full bg-neutral-950 border border-neutral-700 rounded-lg px-4 py-2.5 font-mono text-neutral-200 mb-6 focus:outline-none focus:border-primary-500" })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "flex justify-end gap-3", children: [
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("button", { onClick: onClose, className: "text-sm text-neutral-500 hover:text-white px-4", children: "Cancel" }),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("button", { onClick: doChmod, disabled: loading, className: "bg-primary-600 hover:bg-primary-500 disabled:bg-neutral-700 text-white text-sm font-bold px-5 py-2 rounded-lg transition-colors flex items-center gap-2", children: [
          loading && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" }),
          "Apply"
        ] })
      ] })
    ] });
  }
  function CreateFolderModal({ isOpen, onClose, serverId, currentPath, onComplete }) {
    const [name, setName] = (0, import_react15.useState)("");
    const [loading, setLoading] = (0, import_react15.useState)(false);
    const [error, setError] = (0, import_react15.useState)("");
    (0, import_react15.useEffect)(() => {
      if (isOpen) {
        setName("");
        setError("");
      }
    }, [isOpen]);
    const doCreate = async () => {
      if (!name.trim()) return;
      setLoading(true);
      setError("");
      try {
        const res = await fetch(`/api/client/servers/${serverId}/files/create-folder`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ directory: currentPath, name: name.trim() })
        });
        const p = await res.json();
        if (!res.ok || p.error) throw new Error(p.error || "Failed");
        onComplete();
        onClose();
      } catch (e) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    };
    return /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)(Modal, { isOpen, onClose, title: "Create Folder", maxW: "max-w-sm", children: [
      error && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "text-sm text-red-400 mb-4", children: error }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("input", { autoFocus: true, type: "text", value: name, onChange: (e) => setName(e.target.value), onKeyDown: (e) => e.key === "Enter" && doCreate(), placeholder: "folder-name", className: "w-full bg-neutral-950 border border-neutral-700 rounded-lg px-4 py-2.5 text-neutral-200 mb-2 focus:outline-none focus:border-primary-500" }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "text-xs text-neutral-600 mb-6", children: [
        "Will be created in ",
        currentPath
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "flex justify-end gap-3", children: [
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("button", { onClick: onClose, className: "text-sm text-neutral-500 hover:text-white px-4", children: "Cancel" }),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("button", { onClick: doCreate, disabled: loading || !name.trim(), className: "bg-primary-600 hover:bg-primary-500 disabled:bg-neutral-700 text-white text-sm font-bold px-5 py-2 rounded-lg transition-colors flex items-center gap-2", children: [
          loading && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" }),
          "Create"
        ] })
      ] })
    ] });
  }
  function CreateFileModal({ isOpen, onClose, currentPath, editUrlBase }) {
    const [name, setName] = (0, import_react15.useState)("");
    (0, import_react15.useEffect)(() => {
      if (isOpen) setName("");
    }, [isOpen]);
    const doCreate = () => {
      if (!name.trim()) return;
      const p = (currentPath === "/" ? "" : currentPath) + "/" + name.trim();
      window.location.href = `${editUrlBase}?path=${encodeURIComponent(p)}`;
    };
    return /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)(Modal, { isOpen, onClose, title: "Create File", maxW: "max-w-sm", children: [
      /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("input", { autoFocus: true, type: "text", value: name, onChange: (e) => setName(e.target.value), onKeyDown: (e) => e.key === "Enter" && doCreate(), placeholder: "filename.yml", className: "w-full bg-neutral-950 border border-neutral-700 rounded-lg px-4 py-2.5 text-neutral-200 mb-2 focus:outline-none focus:border-primary-500" }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "text-xs text-neutral-600 mb-6", children: "Opens in editor instantly after creation." }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "flex justify-end gap-3", children: [
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("button", { onClick: onClose, className: "text-sm text-neutral-500 hover:text-white px-4", children: "Cancel" }),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("button", { onClick: doCreate, disabled: !name.trim(), className: "bg-primary-600 hover:bg-primary-500 disabled:bg-neutral-700 text-white text-sm font-bold px-5 py-2 rounded-lg transition-colors", children: "Open in Editor" })
      ] })
    ] });
  }
  function MediaViewer({ isOpen, onClose, src, fileName, kind, serverId }) {
    if (!isOpen) return null;
    const downloadUrl = src;
    return /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "fixed inset-0 z-[300] bg-black/90 backdrop-blur-md flex flex-col", onClick: (e) => {
      if (e.target === e.currentTarget) onClose();
    }, children: [
      /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "flex items-center justify-between px-6 py-4 border-b border-neutral-800 shrink-0", children: [
        /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "flex items-center gap-3", children: [
          /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: `bi ${kind === "video" ? "bi-play-btn" : "bi-image"} text-neutral-400` }),
          /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("span", { className: "text-sm font-bold text-neutral-200 font-mono", children: fileName })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "flex items-center gap-3", children: [
          /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("a", { href: downloadUrl, download: fileName, className: "text-xs text-neutral-400 hover:text-white border border-neutral-700 rounded px-3 py-1.5 transition-colors", children: [
            /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-download mr-1" }),
            "Download"
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("button", { onClick: onClose, className: "w-8 h-8 flex items-center justify-center rounded text-neutral-400 hover:text-white hover:bg-neutral-800", children: /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-x-lg" }) })
        ] })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "flex-1 flex items-center justify-center p-8 overflow-auto", children: kind === "image" ? /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("img", { src, alt: fileName, className: "max-w-full max-h-full object-contain rounded-xl shadow-2xl" }) : /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("video", { src, controls: true, autoPlay: true, className: "max-w-full max-h-full rounded-xl shadow-2xl" }) })
    ] });
  }
  function UploadQueue({ queue, onClear }) {
    const [collapsed, setCollapsed] = (0, import_react15.useState)(false);
    if (queue.length === 0) return null;
    const done = queue.filter((f) => f.status === "done").length;
    const uploading = queue.filter((f) => f.status === "uploading").length;
    return /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "fixed bottom-6 right-6 z-[100] w-80 bg-neutral-900 border border-neutral-700 rounded-2xl shadow-2xl overflow-hidden", children: [
      /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "px-4 py-3 border-b border-neutral-800 flex items-center justify-between cursor-pointer hover:bg-neutral-800/50 transition-colors", onClick: () => setCollapsed((c) => !c), children: [
        /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "flex items-center gap-2.5", children: [
          /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "relative", children: [
            /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-cloud-arrow-up text-lg text-primary-500" }),
            uploading > 0 && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("span", { className: "absolute -top-1 -right-1 w-2.5 h-2.5 bg-primary-500 rounded-full animate-ping" })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { children: [
            /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "text-[9px] font-black text-neutral-500 uppercase tracking-widest leading-none mb-0.5", children: "Upload Queue" }),
            /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "text-xs font-bold text-white leading-none", children: [
              done,
              "/",
              queue.length,
              " uploaded"
            ] })
          ] })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "flex items-center gap-3", children: [
          /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: `bi ${collapsed ? "bi-chevron-up" : "bi-chevron-down"} text-neutral-500 text-xs` }),
          /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("button", { onClick: (e) => {
            e.stopPropagation();
            onClear();
          }, className: "text-neutral-500 hover:text-white transition-colors text-xs", children: /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-x-lg" }) })
        ] })
      ] }),
      !collapsed && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "max-h-60 overflow-y-auto divide-y divide-neutral-800/50", children: queue.map((item) => /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "px-4 py-3", children: [
        /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "flex justify-between items-start gap-2 mb-1.5", children: [
          /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("span", { className: "text-xs font-bold text-neutral-200 truncate flex-1", children: item.name }),
          item.status === "done" && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-check-circle-fill text-green-500 shrink-0" }),
          item.status === "error" && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-exclamation-circle-fill text-red-500 shrink-0" }),
          item.status === "uploading" && /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("span", { className: "text-[10px] font-black text-primary-500 shrink-0", children: [
            item.progress,
            "%"
          ] })
        ] }),
        item.status === "uploading" && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "h-1 w-full bg-neutral-800 rounded-full overflow-hidden", children: /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "h-full bg-primary-500 transition-all rounded-full", style: { width: `${item.progress}%` } }) }),
        item.status === "error" && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "text-[10px] text-red-400 truncate", children: item.error })
      ] }, item.id)) })
    ] });
  }
  function ContextMenu({ x, y, entry, entryPath, writeLocked, canDownload, editUrlBase, previewUrlBase, downloadUrlBase, currentPath, serverId, onClose, onRename, onChmod, onArchive, onUnarchive, onDelete, onNavigate }) {
    const ref = (0, import_react15.useRef)(null);
    (0, import_react15.useEffect)(() => {
      const handle = (e) => {
        if (ref.current && !ref.current.contains(e.target)) {
          onClose();
        }
      };
      document.addEventListener("mousedown", handle, true);
      const escHandle = (e) => {
        if (e.key === "Escape") onClose();
      };
      document.addEventListener("keydown", escHandle);
      return () => {
        document.removeEventListener("mousedown", handle, true);
        document.removeEventListener("keydown", escHandle);
      };
    }, [onClose]);
    const style = { position: "fixed", top: y, left: x, zIndex: 500 };
    const Item = ({ icon, label, onClick, danger, iconClass }) => /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("button", { onClick: () => {
      onClick();
      onClose();
    }, className: `w-full text-left flex items-center gap-2.5 px-3 py-2 text-sm rounded-lg transition-colors ${danger ? "text-red-400 hover:bg-red-900/20 hover:text-red-300" : "text-neutral-300 hover:bg-neutral-800 hover:text-white"}`, children: [
      /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: `bi ${icon} text-sm ${iconClass || ""}` }),
      " ",
      label
    ] });
    const Sep = () => /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "my-1 h-px bg-neutral-800" });
    return /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { ref, style, className: "w-52 bg-neutral-950/95 backdrop-blur-xl border border-neutral-800 rounded-xl shadow-2xl py-1.5 px-1", children: [
      entry.isDirectory ? /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(Item, { icon: "bi-folder-symlink", label: "Open Folder", onClick: () => onNavigate(entryPath), iconClass: "text-amber-400" }) : /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)(import_jsx_runtime15.Fragment, { children: [
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(Item, { icon: "bi-pencil", label: "Edit File", onClick: () => {
          window.location.href = `${editUrlBase}?path=${encodeURIComponent(entryPath)}`;
        } }),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(Item, { icon: "bi-eye", label: "Preview", onClick: () => {
          window.location.href = `${previewUrlBase}?path=${encodeURIComponent(entryPath)}`;
        } }),
        canDownload && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(Item, { icon: "bi-cloud-arrow-down", label: "Download", onClick: () => {
          window.open(`${downloadUrlBase}?path=${encodeURIComponent(entryPath)}`);
        }, iconClass: "text-blue-400" })
      ] }),
      !writeLocked && /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)(import_jsx_runtime15.Fragment, { children: [
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(Sep, {}),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(Item, { icon: "bi-input-cursor-text", label: "Rename", onClick: () => onRename(entry.name) }),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(Item, { icon: "bi-shield-check", label: "Permissions", onClick: () => onChmod(entry.name, entry.permissions) }),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(Item, { icon: "bi-file-zip", label: "Archive", onClick: () => onArchive(/* @__PURE__ */ new Set([entry.name])), iconClass: "text-yellow-400" }),
        !entry.isDirectory && isArchive(entry.name) && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(Item, { icon: "bi-file-earmark-zip", label: "Unarchive", onClick: () => onUnarchive(entry.name), iconClass: "text-green-400" }),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(Sep, {}),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(Item, { icon: "bi-trash3", label: `Delete ${entry.isDirectory ? "Folder" : "File"}`, onClick: () => onDelete(/* @__PURE__ */ new Set([entry.name])), danger: true })
      ] })
    ] });
  }
  function ServerFilesPage({ pageData = data3 }) {
    const manager = pageData.fileManager || {};
    const permissions = pageData.permissions || {};
    const sftpDetails = pageData.sftpDetails || {};
    const [currentPath, setCurrentPath] = (0, import_react15.useState)(() => normalizePath(pageData.initialPath || "/"));
    const [entries, setEntries] = (0, import_react15.useState)([]);
    const [loading, setLoading] = (0, import_react15.useState)(true);
    const [error, setError] = (0, import_react15.useState)("");
    const [selected, setSelected] = (0, import_react15.useState)(/* @__PURE__ */ new Set());
    const [isDragging, setIsDragging] = (0, import_react15.useState)(false);
    const [uploadQueue, setUploadQueue] = (0, import_react15.useState)([]);
    const [contextMenu, setContextMenu] = (0, import_react15.useState)(null);
    const [mediaViewer, setMediaViewer] = (0, import_react15.useState)(null);
    const [modal, setModal] = (0, import_react15.useState)({ type: null, target: null, extra: null });
    const openModal = (type, target = null, extra = null) => setModal({ type, target, extra });
    const closeModal = () => setModal({ type: null, target: null, extra: null });
    const loadDir = (0, import_react15.useCallback)(() => {
      let cancelled = false;
      setLoading(true);
      setError("");
      setSelected(/* @__PURE__ */ new Set());
      fetch(`${manager.fetchUrlBase}?path=${encodeURIComponent(currentPath)}`, {
        credentials: "same-origin",
        headers: { Accept: "application/json" }
      }).then((r) => r.json()).then((payload) => {
        if (cancelled) return;
        if (payload.error) throw new Error(payload.error);
        const list = (Array.isArray(payload.files) ? payload.files : []).sort((a, b) => {
          if (a.isDirectory && !b.isDirectory) return -1;
          if (!a.isDirectory && b.isDirectory) return 1;
          return String(a.name || "").localeCompare(String(b.name || ""), void 0, { numeric: true, sensitivity: "base" });
        });
        setEntries(list);
        setLoading(false);
      }).catch((e) => {
        if (!cancelled) {
          setEntries([]);
          setLoading(false);
          setError(e.message || "Failed to load files.");
        }
      });
      return () => {
        cancelled = true;
      };
    }, [currentPath, manager.fetchUrlBase]);
    (0, import_react15.useEffect)(() => loadDir(), [loadDir]);
    (0, import_react15.useEffect)(() => {
      const handle = (e) => {
        if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") return;
        if (e.ctrlKey || e.metaKey) {
          if (e.key === "f") {
            e.preventDefault();
            openModal("search");
          }
          if (e.key === "r") {
            e.preventDefault();
            loadDir();
          }
          if (e.key === "n" && !e.shiftKey) {
            e.preventDefault();
            openModal("createFile");
          }
          if (e.key === "n" && e.shiftKey) {
            e.preventDefault();
            openModal("createFolder");
          }
          if (e.key === "a") {
            e.preventDefault();
            setSelected(new Set(entries.map((e2) => e2.name)));
          }
        }
        if (e.key === "Escape") {
          setSelected(/* @__PURE__ */ new Set());
          setContextMenu(null);
        }
      };
      window.addEventListener("keydown", handle);
      return () => window.removeEventListener("keydown", handle);
    }, [entries, loadDir]);
    const uploadFile = (0, import_react15.useCallback)((file, queueId) => {
      return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        const url = `${manager.uploadUrlBase || `/server/${pageData.server?.containerId}/files/upload`}?path=${encodeURIComponent(currentPath)}&name=${encodeURIComponent(file.name)}`;
        xhr.upload.onprogress = (e) => {
          if (e.lengthComputable) {
            const pct = Math.round(e.loaded / e.total * 100);
            setUploadQueue((prev) => prev.map((i) => i.id === queueId ? { ...i, progress: pct } : i));
          }
        };
        xhr.onreadystatechange = () => {
          if (xhr.readyState !== 4) return;
          try {
            const p = JSON.parse(xhr.responseText || "{}");
            if (xhr.status >= 200 && xhr.status < 300 && !p.error) {
              setUploadQueue((prev) => prev.map((i) => i.id === queueId ? { ...i, status: "done", progress: 100 } : i));
              resolve();
            } else throw new Error(p.error || "Upload failed");
          } catch (err) {
            setUploadQueue((prev) => prev.map((i) => i.id === queueId ? { ...i, status: "error", error: err.message } : i));
            reject(err);
          }
        };
        xhr.open("POST", url, true);
        xhr.setRequestHeader("Content-Type", "application/octet-stream");
        xhr.setRequestHeader("x-file-name", file.name);
        xhr.withCredentials = true;
        xhr.send(file);
      });
    }, [currentPath, manager.uploadUrlBase, pageData.server?.containerId]);
    const handleFiles = (0, import_react15.useCallback)(async (files) => {
      if (permissions.filesWriteLocked) return;
      const arr = Array.from(files);
      if (arr.length === 0) return;
      const newItems = arr.map((f) => ({ id: Math.random().toString(36).slice(2), name: f.name, size: f.size, progress: 0, status: "uploading" }));
      setUploadQueue((prev) => [...newItems, ...prev]);
      await Promise.allSettled(arr.map((f, i) => uploadFile(f, newItems[i].id)));
      loadDir();
    }, [permissions.filesWriteLocked, uploadFile, loadDir]);
    const handleDragOver = (e) => {
      e.preventDefault();
      if (!permissions.filesWriteLocked) setIsDragging(true);
    };
    const handleDragLeave = (e) => {
      if (!e.currentTarget.contains(e.relatedTarget)) setIsDragging(false);
    };
    const handleDrop = (e) => {
      e.preventDefault();
      setIsDragging(false);
      handleFiles(e.dataTransfer.files);
    };
    const handleUnarchive = async (name) => {
      setLoading(true);
      try {
        const res = await fetch(`/api/client/servers/${pageData.server?.containerId}/files/unarchive`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ directory: currentPath, name })
        });
        const p = await res.json();
        if (!res.ok || p.error) throw new Error(p.error || "Extraction failed");
        loadDir();
      } catch (e) {
        setError(e.message);
        setLoading(false);
      }
    };
    const handleEntryClick = (entry, entryPath) => {
      if (entry.isDirectory) {
        setCurrentPath(entryPath);
        return;
      }
      const mk = mediaKind(entry.name);
      if (mk) {
        setMediaViewer({ src: `${manager.downloadUrlBase}?path=${encodeURIComponent(entryPath)}`, fileName: entry.name, kind: mk });
        return;
      }
      window.location.href = `${manager.editUrlBase}?path=${encodeURIComponent(entryPath)}`;
    };
    const toggleSelect = (name, e) => {
      e.stopPropagation();
      setSelected((prev) => {
        const next = new Set(prev);
        if (next.has(name)) next.delete(name);
        else next.add(name);
        return next;
      });
    };
    const toggleAll = () => {
      setSelected((prev) => prev.size === entries.length ? /* @__PURE__ */ new Set() : new Set(entries.map((e) => e.name)));
    };
    const handleContextMenu = (e, entry, entryPath) => {
      e.preventDefault();
      e.stopPropagation();
      const x = Math.min(e.clientX, window.innerWidth - 220);
      const y = Math.min(e.clientY, window.innerHeight - 300);
      setContextMenu({ x, y, entry, entryPath });
    };
    const breadcrumbs = buildBreadcrumbs(currentPath);
    const activeServer = pageData.server || {};
    const allSelected = entries.length > 0 && selected.size === entries.length;
    return /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)(ReactAppShell, { pageData, subtitle: "File Manager", children: [
      /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "max-w-7xl mx-auto px-0 sm:px-4", children: [
        /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "flex flex-wrap items-center justify-between gap-3 mb-5", children: [
          /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "flex flex-wrap gap-2", children: [
            !permissions.filesWriteLocked && /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)(import_jsx_runtime15.Fragment, { children: [
              /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("button", { onClick: () => openModal("createFile"), className: "flex items-center gap-2 bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 text-neutral-200 text-sm font-semibold px-4 py-2 rounded-lg transition-colors", children: [
                /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-file-earmark-plus" }),
                " New File"
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("button", { onClick: () => openModal("createFolder"), className: "flex items-center gap-2 bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 text-neutral-200 text-sm font-semibold px-4 py-2 rounded-lg transition-colors", children: [
                /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-folder-plus" }),
                " New Folder"
              ] }),
              manager.webUploadEnabled && /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("button", { onClick: () => document.getElementById("_hiddenUpload").click(), className: "flex items-center gap-2 bg-primary-600 hover:bg-primary-500 text-white text-sm font-bold px-4 py-2 rounded-lg transition-colors", children: [
                /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-cloud-upload" }),
                " Upload"
              ] }),
              permissions.canFixPermissions && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("form", { method: "POST", action: `/server/${activeServer.containerId}/fix-permissions`, className: "inline-flex", children: /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("button", { type: "submit", className: "flex items-center gap-2 bg-amber-900/20 hover:bg-amber-900/30 border border-amber-800/40 text-amber-300 text-sm font-semibold px-4 py-2 rounded-lg transition-colors", children: [
                /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-tools" }),
                " Fix Perms"
              ] }) })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("input", { type: "file", id: "_hiddenUpload", multiple: true, className: "hidden", onChange: (e) => handleFiles(e.target.files) })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "flex items-center gap-2", children: [
            /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("button", { onClick: () => openModal("search"), className: "flex items-center gap-2 bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 text-neutral-300 text-sm px-3 py-2 rounded-lg transition-colors", children: [
              /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-search" }),
              " ",
              /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("span", { className: "hidden sm:inline", children: "Search" })
            ] }),
            sftpDetails.available && /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("button", { onClick: () => openModal("sftp"), className: "flex items-center gap-2 bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 text-neutral-300 text-sm px-3 py-2 rounded-lg transition-colors", children: [
              /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-hdd-network" }),
              " ",
              /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("span", { className: "hidden sm:inline", children: "SFTP" })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("button", { onClick: loadDir, className: "flex items-center gap-2 bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 text-neutral-300 text-sm px-3 py-2 rounded-lg transition-colors", title: "Refresh (Ctrl+R)", children: /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-arrow-clockwise" }) }),
            /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("a", { href: `${manager.legacyUrl}?legacy=1`, className: "flex items-center gap-2 bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 text-neutral-400 text-xs px-3 py-2 rounded-lg transition-colors", children: [
              /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-box-arrow-up-right" }),
              " Legacy"
            ] })
          ] })
        ] }),
        permissions.filesWriteLocked && /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "mb-4 flex items-center gap-2 px-4 py-3 bg-amber-900/10 border border-amber-800/30 text-amber-200 rounded-xl text-sm", children: [
          /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-shield-lock-fill text-amber-500" }),
          "File writes are locked by policy. Read-only mode."
        ] }),
        !permissions.filesWriteLocked && (pageData.policyReadOnlyPatterns || []).length > 0 && /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "mb-4 flex items-center gap-2 px-4 py-3 bg-blue-900/10 border border-blue-800/30 text-blue-200 rounded-xl text-sm", children: [
          /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-shield-lock text-blue-400" }),
          "Read-only pattern policy is active for ",
          pageData.policyReadOnlyPatterns.length,
          " path(s)."
        ] }),
        manager.webUploadEnabled && /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "text-xs text-neutral-600 mb-3", children: [
          "Max upload: ",
          manager.webUploadMaxMb,
          " MB per file \xB7 Drag & drop anywhere below"
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(
          BulkBar,
          {
            selected,
            writeLocked: permissions.filesWriteLocked,
            onClear: () => setSelected(/* @__PURE__ */ new Set()),
            onBulkDelete: () => openModal("bulkDelete", null, selected),
            onBulkRename: () => openModal("bulkRename", null, selected),
            onBulkChmod: () => openModal("bulkChmod", null, selected),
            onBulkArchive: () => openModal("archive", null, selected)
          }
        ),
        /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)(
          "div",
          {
            className: "bg-neutral-900 border border-neutral-800 rounded-2xl overflow-hidden relative",
            onDragOver: handleDragOver,
            onDragLeave: handleDragLeave,
            onDrop: handleDrop,
            onContextMenu: (e) => {
              e.preventDefault();
              setContextMenu(null);
            },
            onClick: () => setContextMenu(null),
            children: [
              isDragging && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "absolute inset-0 z-50 bg-primary-600/10 border-2 border-dashed border-primary-500 rounded-2xl flex items-center justify-center pointer-events-none", children: /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "bg-neutral-950 rounded-2xl px-12 py-10 shadow-2xl border border-neutral-700 flex flex-col items-center", children: [
                /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-cloud-arrow-up text-5xl text-primary-500 mb-3" }),
                /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("span", { className: "text-xl font-black text-white uppercase tracking-wider", children: "Drop to Upload" }),
                /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("span", { className: "text-xs text-neutral-500 mt-2", children: [
                  "into ",
                  currentPath
                ] })
              ] }) }),
              /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "px-5 py-3 border-b border-neutral-800 bg-neutral-900/60 flex items-center flex-wrap gap-1", children: breadcrumbs.map((seg, idx) => /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)(import_react15.default.Fragment, { children: [
                /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(
                  "button",
                  {
                    type: "button",
                    onClick: () => idx !== breadcrumbs.length - 1 && setCurrentPath(seg.path),
                    className: `flex items-center gap-1 text-sm font-semibold transition-colors px-1 ${idx === breadcrumbs.length - 1 ? "text-neutral-200 cursor-default" : "text-neutral-500 hover:text-white"}`,
                    children: seg.icon ? /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-house-door-fill text-base" }) : seg.label
                  }
                ),
                idx < breadcrumbs.length - 1 && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("span", { className: "text-neutral-700 font-bold", children: "/" })
              ] }, seg.path)) }),
              error && /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "px-5 py-3 border-b border-red-900/30 bg-red-900/10 text-red-300 text-sm flex items-center gap-2", children: [
                /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-exclamation-triangle-fill text-red-500" }),
                " ",
                error
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "grid grid-cols-12 px-4 py-2.5 border-b border-neutral-800 bg-neutral-950/40 text-[10px] font-black text-neutral-500 uppercase tracking-widest", children: [
                /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "col-span-1 flex items-center justify-center", children: /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(
                  "input",
                  {
                    type: "checkbox",
                    checked: allSelected,
                    onChange: toggleAll,
                    className: "w-4 h-4 rounded border-neutral-700 bg-neutral-900 accent-primary-500 cursor-pointer"
                  }
                ) }),
                /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "col-span-6", children: "Name" }),
                /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "hidden md:block col-span-2", children: "Permissions" }),
                /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "hidden md:block col-span-2 text-right", children: "Size" }),
                /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "col-span-5 md:col-span-1 text-right", children: "Actions" })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "min-h-[300px]", children: [
                loading && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "flex justify-center items-center py-20", children: /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "flex flex-col items-center gap-4", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "w-10 h-10 border-4 border-neutral-800 border-t-primary-500 rounded-full animate-spin" }),
                  /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("span", { className: "text-xs text-neutral-500 uppercase tracking-widest font-bold", children: "Loading\u2026" })
                ] }) }),
                !loading && entries.length === 0 && /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "flex flex-col items-center justify-center py-20 text-neutral-600", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-folder2-open text-4xl mb-3" }),
                  /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("span", { className: "text-sm", children: "This directory is empty" })
                ] }),
                !loading && entries.map((entry) => {
                  const entryPath = normalizePath(`${currentPath === "/" ? "" : currentPath}/${entry.name}`);
                  const isSelected = selected.has(entry.name);
                  const icon = getFileIcon(entry);
                  const mk = !entry.isDirectory ? mediaKind(entry.name) : null;
                  return /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)(
                    "div",
                    {
                      onContextMenu: (e) => handleContextMenu(e, entry, entryPath),
                      className: `grid grid-cols-12 items-center px-4 py-2.5 border-b border-neutral-800/40 transition-colors group relative ${isSelected ? "bg-primary-900/10 border-primary-900/20" : "hover:bg-neutral-800/30"}`,
                      children: [
                        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "col-span-1 flex justify-center", children: /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(
                          "input",
                          {
                            type: "checkbox",
                            checked: isSelected,
                            onClick: (e) => toggleSelect(entry.name, e),
                            onChange: () => {
                            },
                            className: "w-4 h-4 rounded border-neutral-700 bg-neutral-900 accent-primary-500 cursor-pointer"
                          }
                        ) }),
                        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "col-span-6 flex items-center min-w-0", children: /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)(
                          "button",
                          {
                            type: "button",
                            onClick: () => handleEntryClick(entry, entryPath),
                            className: "flex items-center gap-3 text-left min-w-0 flex-1 py-1.5 group/name",
                            children: [
                              /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: `bi ${icon} text-xl shrink-0` }),
                              /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "min-w-0", children: [
                                /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "text-sm font-semibold text-neutral-200 group-hover/name:text-white truncate transition-colors", children: entry.name }),
                                entry.isDirectory && /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "text-[10px] text-neutral-600", children: [
                                  "Folder \xB7 ",
                                  formatDate(entry.modified)
                                ] }),
                                !entry.isDirectory && /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "text-[10px] text-neutral-600 md:hidden", children: [
                                  formatBytes(entry.size),
                                  " \xB7 ",
                                  entry.permissions || ""
                                ] })
                              ] })
                            ]
                          }
                        ) }),
                        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "hidden md:flex col-span-2 items-center", children: /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("span", { className: "text-xs font-mono text-neutral-500", children: entry.permissions || "\u2014" }) }),
                        /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("div", { className: "hidden md:flex col-span-2 items-center justify-end", children: /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("span", { className: "text-xs font-mono text-neutral-500", children: entry.isDirectory ? "\u2014" : formatBytes(entry.size) }) }),
                        /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "col-span-5 md:col-span-1 flex items-center justify-end gap-1", children: [
                          mk && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(
                            "button",
                            {
                              onClick: () => setMediaViewer({ src: `${manager.downloadUrlBase}?path=${encodeURIComponent(entryPath)}`, fileName: entry.name, kind: mk }),
                              className: "w-7 h-7 flex items-center justify-center rounded text-neutral-600 hover:text-purple-400 hover:bg-purple-900/20 transition-colors opacity-0 group-hover:opacity-100",
                              title: "Preview",
                              children: /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-play-circle text-sm" })
                            }
                          ),
                          !entry.isDirectory && permissions.canDownloadFiles && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(
                            "a",
                            {
                              href: `${manager.downloadUrlBase}?path=${encodeURIComponent(entryPath)}`,
                              className: "w-7 h-7 flex items-center justify-center rounded text-neutral-600 hover:text-blue-400 hover:bg-blue-900/20 transition-colors opacity-0 group-hover:opacity-100",
                              title: "Download",
                              children: /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-cloud-arrow-down text-sm" })
                            }
                          ),
                          !permissions.filesWriteLocked && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(
                            "button",
                            {
                              onClick: () => openModal("rename", entry.name),
                              className: "w-7 h-7 flex items-center justify-center rounded text-neutral-600 hover:text-amber-400 hover:bg-amber-900/20 transition-colors opacity-0 group-hover:opacity-100",
                              title: "Rename",
                              children: /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-input-cursor-text text-sm" })
                            }
                          ),
                          !permissions.filesWriteLocked && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(
                            "button",
                            {
                              onClick: () => openModal("delete", null, /* @__PURE__ */ new Set([entry.name])),
                              className: "w-7 h-7 flex items-center justify-center rounded text-neutral-600 hover:text-red-400 hover:bg-red-900/20 transition-colors opacity-0 group-hover:opacity-100",
                              title: "Delete",
                              children: /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-trash3 text-sm" })
                            }
                          ),
                          /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(
                            "button",
                            {
                              onClick: (e) => {
                                e.stopPropagation();
                                handleContextMenu(e, entry, entryPath);
                              },
                              className: "w-7 h-7 flex items-center justify-center rounded text-neutral-500 hover:text-white hover:bg-neutral-700 transition-colors border border-neutral-700 md:border-0",
                              title: "More",
                              children: /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("i", { className: "bi bi-three-dots text-sm" })
                            }
                          )
                        ] })
                      ]
                    },
                    entryPath
                  );
                })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("div", { className: "px-5 py-2.5 border-t border-neutral-800 bg-neutral-950/30 flex justify-between items-center text-[10px] text-neutral-600 font-mono", children: [
                /* @__PURE__ */ (0, import_jsx_runtime15.jsxs)("span", { children: [
                  entries.length,
                  " item",
                  entries.length !== 1 ? "s" : ""
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime15.jsx)("span", { className: "hidden sm:inline", children: "Ctrl+F search \xB7 Ctrl+A select all \xB7 Right-click for options" })
              ] })
            ]
          }
        )
      ] }),
      contextMenu && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(
        ContextMenu,
        {
          x: contextMenu.x,
          y: contextMenu.y,
          entry: contextMenu.entry,
          entryPath: contextMenu.entryPath,
          writeLocked: permissions.filesWriteLocked,
          canDownload: permissions.canDownloadFiles,
          editUrlBase: manager.editUrlBase,
          previewUrlBase: manager.previewUrlBase,
          downloadUrlBase: manager.downloadUrlBase,
          currentPath,
          serverId: activeServer.containerId,
          onClose: () => setContextMenu(null),
          onRename: (name) => openModal("rename", name),
          onChmod: (name, perms) => openModal("chmod", name, perms),
          onArchive: (names) => openModal("archive", null, names),
          onUnarchive: (name) => handleUnarchive(name),
          onDelete: (names) => openModal("delete", null, names),
          onNavigate: (path) => setCurrentPath(path)
        }
      ),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(SearchModal, { isOpen: modal.type === "search", onClose: closeModal, serverId: activeServer.containerId, onNavigate: setCurrentPath }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(SftpModal, { isOpen: modal.type === "sftp", onClose: closeModal, sftpDetails }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(CreateFileModal, { isOpen: modal.type === "createFile", onClose: closeModal, currentPath, editUrlBase: manager.editUrlBase }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(CreateFolderModal, { isOpen: modal.type === "createFolder", onClose: closeModal, serverId: activeServer.containerId, currentPath, onComplete: loadDir }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(RenameModal, { isOpen: modal.type === "rename", onClose: closeModal, serverId: activeServer.containerId, currentPath, targetName: modal.target, onComplete: loadDir }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(ChmodModal, { isOpen: modal.type === "chmod", onClose: closeModal, serverId: activeServer.containerId, currentPath, targetName: modal.target, currentPerms: modal.extra, onComplete: loadDir }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(DeleteModal, { isOpen: modal.type === "delete", onClose: closeModal, serverId: activeServer.containerId, currentPath, targetNames: modal.extra || /* @__PURE__ */ new Set(), onComplete: loadDir }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(ArchiveModal, { isOpen: modal.type === "archive", onClose: closeModal, serverId: activeServer.containerId, currentPath, targetNames: modal.extra || /* @__PURE__ */ new Set(), onComplete: loadDir }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(BulkRenameModal, { isOpen: modal.type === "bulkRename", onClose: closeModal, serverId: activeServer.containerId, currentPath, selectedNames: modal.extra || /* @__PURE__ */ new Set(), onComplete: () => {
        loadDir();
        setSelected(/* @__PURE__ */ new Set());
      } }),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(BulkChmodModal, { isOpen: modal.type === "bulkChmod", onClose: closeModal, serverId: activeServer.containerId, currentPath, selectedNames: modal.extra || /* @__PURE__ */ new Set(), onComplete: () => {
        loadDir();
        setSelected(/* @__PURE__ */ new Set());
      } }),
      mediaViewer && /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(
        MediaViewer,
        {
          isOpen: true,
          onClose: () => setMediaViewer(null),
          src: mediaViewer.src,
          fileName: mediaViewer.fileName,
          kind: mediaViewer.kind,
          serverId: activeServer.containerId
        }
      ),
      /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(UploadQueue, { queue: uploadQueue, onClear: () => setUploadQueue([]) })
    ] });
  }
  if (root3) {
    root3.render(
      /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(ThemeProvider, { pageData: data3, children: /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(BrowserRouter, { children: /* @__PURE__ */ (0, import_jsx_runtime15.jsx)(ServerFilesPage, { pageData: data3 }) }) })
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === "function") {
      window.__CPANEL_REACT_BOOTED__();
    }
  }

  // views/react/server-backups.jsx
  var import_react16 = __toESM(require_react());
  var import_client4 = __toESM(require_client());
  var import_jsx_runtime16 = __toESM(require_jsx_runtime());
  var data4 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry4 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "server-backups";
  var root4 = standaloneEntry4 ? (0, import_client4.createRoot)(document.getElementById("reactRoot")) : null;
  function formatBytes2(value) {
    const bytes = Math.max(0, Number(value) || 0);
    if (!bytes) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    let current = bytes;
    let index = 0;
    while (current >= 1024 && index < units.length - 1) {
      current /= 1024;
      index += 1;
    }
    return `${current >= 100 || index === 0 ? current.toFixed(0) : current.toFixed(2)} ${units[index]}`;
  }
  function formatWhen(value) {
    if (!value) return "Never";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "Never" : date.toLocaleString();
  }
  function statusTone2(status) {
    const value = String(status || "").toLowerCase();
    if (["completed", "success", "ready"].includes(value)) return "success";
    if (["queued", "running", "retrying"].includes(value)) return "warning";
    return "danger";
  }
  function statusColorClass(status) {
    const tone = statusTone2(status);
    if (tone === "success") return "bg-green-600/20 text-green-400 border border-green-600/30";
    if (tone === "warning") return "bg-yellow-600/20 text-yellow-400 border border-yellow-600/30";
    return "bg-red-600/20 text-red-400 border border-red-600/30";
  }
  function ServerBackupsPage({ pageData = data4 }) {
    const server = pageData.server || {};
    const backups = Array.isArray(pageData.backups) ? pageData.backups : [];
    const driveState = pageData.googleDriveState || {};
    const permissions = pageData.permissions || {};
    const policy = pageData.backupPolicy || {};
    const actions = pageData.actions || {};
    const inputClass = "w-full bg-neutral-900 border border-neutral-700/50 rounded p-2.5 text-sm text-neutral-200 focus:ring-2 focus:ring-primary-500 focus:border-transparent outline-none transition-shadow";
    const labelClass = "block text-xs font-bold text-neutral-400 uppercase tracking-wide mb-1.5";
    const [isClearing, setIsClearing] = import_react16.default.useState(false);
    const handleClearHistory = async () => {
      if (!window.confirm("Are you sure you want to clear the backup history for this server? This only removes the database records; actual files in Google Drive will not be deleted.")) {
        return;
      }
      setIsClearing(true);
      try {
        const response = await fetch(`/server/${server.containerId}/backups/clear`, {
          method: "POST",
          headers: { "Accept": "application/json" }
        });
        const payload = await response.json();
        if (payload.success) {
          window.location.reload();
        } else {
          alert(payload.error || "Failed to clear backup history.");
          setIsClearing(false);
        }
      } catch (err) {
        alert("An error occurred while clearing backup history.");
        setIsClearing(false);
      }
    };
    return /* @__PURE__ */ (0, import_jsx_runtime16.jsx)(ReactAppShell, { pageData, subtitle: "Backups", children: /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)(
      PageContentBlock,
      {
        title: "Backups",
        description: "Review backup history, connect Google Drive for storage, and trigger fresh snapshots.",
        eyebrow: "Recovery",
        children: [
          /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { className: "flex justify-end gap-3 mb-6", children: [
            permissions.canManageBackups && /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)(
              "button",
              {
                onClick: handleClearHistory,
                disabled: isClearing,
                className: "bg-red-900/10 hover:bg-red-600/20 text-red-400 border border-red-500/30 font-semibold py-2 px-4 rounded transition-colors text-sm flex items-center gap-2 disabled:opacity-50",
                children: [
                  /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("i", { className: `bi ${isClearing ? "bi-hourglass-split" : "bi-trash3"}` }),
                  isClearing ? "Clearing..." : "Clear History"
                ]
              }
            ),
            permissions.canManageBackups ? /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("form", { method: "POST", action: actions.run, children: /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("button", { type: "submit", className: "bg-primary-600 hover:bg-primary-500 text-white font-semibold py-2 px-6 rounded transition-colors text-sm shadow-sm flex items-center gap-2", children: [
              /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("i", { className: "bi bi-hdd-rack" }),
              " Create Backup"
            ] }) }) : null
          ] }),
          pageData.success && /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { className: "bg-green-600/20 border border-green-600/50 text-green-100 p-4 rounded-lg mb-6 shadow-sm flex items-center gap-3", children: [
            /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("i", { className: "bi bi-check-circle-fill text-green-500" }),
            pageData.success
          ] }),
          pageData.error && /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { className: "bg-red-600/20 border border-red-600/50 text-red-100 p-4 rounded-lg mb-6 shadow-sm flex items-center gap-3", children: [
            /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("i", { className: "bi bi-exclamation-triangle-fill text-red-500" }),
            pageData.error
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { className: "grid grid-cols-1 lg:grid-cols-2 gap-6 items-start mb-6", children: [
            /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-lg p-6", children: [
              /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { className: "flex items-center gap-3 mb-6", children: [
                /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("i", { className: "bi bi-google text-2xl text-primary-400" }),
                /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("h2", { className: "text-lg font-bold text-neutral-100", children: "Drive Integration" })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { className: "flex flex-col gap-4 mb-4", children: [
                /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { className: "flex justify-between items-center border-b border-neutral-700/50 pb-3", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("span", { className: "text-sm font-semibold text-neutral-400", children: "Server" }),
                  /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("strong", { className: "text-neutral-200", children: server.name || "Server" })
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { className: "flex justify-between items-center border-b border-neutral-700/50 pb-3", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("span", { className: "text-sm font-semibold text-neutral-400", children: "Drive Ready" }),
                  /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("strong", { className: driveState.ready ? "text-green-400" : "text-neutral-400", children: driveState.ready ? "Ready" : "Needs setup" })
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { className: "flex justify-between items-center pb-2", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("span", { className: "text-sm font-semibold text-neutral-400", children: "Last Run" }),
                  /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("strong", { className: "text-neutral-200 font-mono text-sm", children: formatWhen(policy.lastRunAt) })
                ] })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("p", { className: "text-sm text-neutral-400 italic mb-4", children: driveState.statusText || "Google Drive state is unavailable." }),
              driveState.canConnect ? /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("a", { href: actions.connectGoogle || driveState.connectUrl, className: "inline-block bg-neutral-700 hover:bg-neutral-600 text-white font-semibold py-2 px-6 rounded transition-colors text-sm text-center w-full shadow-sm", children: "Connect Google Drive" }) : null
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-lg p-6 flex flex-col h-full", children: [
              /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { className: "flex items-center gap-3 mb-6", children: [
                /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("i", { className: "bi bi-calendar-event text-2xl text-primary-400" }),
                /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("h2", { className: "text-lg font-bold text-neutral-100", children: "Automated Policy" })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("form", { method: "POST", action: actions.savePolicy, className: "flex flex-col gap-5 flex-1", children: [
                /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("label", { className: "flex items-start gap-3 cursor-pointer group mb-2", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime16.jsx)(
                    "input",
                    {
                      type: "checkbox",
                      name: "enabled",
                      defaultChecked: Boolean(policy.autoEnabled),
                      className: "w-5 h-5 mt-0.5 rounded border-neutral-600 bg-neutral-900 text-primary-600 focus:ring-primary-600 focus:ring-offset-neutral-800"
                    }
                  ),
                  /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { children: [
                    /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("span", { className: "block text-sm font-bold text-neutral-200 group-hover:text-white transition-colors", children: "Enable scheduled backups" }),
                    /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("span", { className: "block text-xs text-neutral-500 mt-1", children: "Automatically generates periodic backups in the background." })
                  ] })
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("label", { className: "mb-2", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("span", { className: labelClass, children: "Interval in minutes" }),
                  /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { className: "relative", children: [
                    /* @__PURE__ */ (0, import_jsx_runtime16.jsx)(
                      "input",
                      {
                        type: "number",
                        name: "intervalMinutes",
                        min: "5",
                        max: "10080",
                        defaultValue: policy.intervalMinutes || 360,
                        className: inputClass
                      }
                    ),
                    /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("div", { className: "absolute inset-y-0 right-0 flex items-center pr-4 pointer-events-none text-neutral-500 text-xs font-bold", children: "MIN" })
                  ] })
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("div", { className: "mt-auto flex justify-end flex-wrap pt-4", children: /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("button", { type: "submit", className: "w-full bg-primary-600 hover:bg-primary-500 text-white font-semibold py-2 px-6 rounded transition-colors text-sm shadow-sm disabled:opacity-50", disabled: !permissions.canManageBackupPolicy, children: "Save Policy" }) })
              ] })
            ] })
          ] }),
          pageData.activeJob ? /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { className: "bg-primary-900/20 border-2 border-primary-600/50 rounded-lg p-6 mb-6", children: [
            /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("h2", { className: "text-lg font-bold text-white mb-4 flex items-center gap-2", children: [
              /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("i", { className: "bi bi-arrow-repeat animate-spin text-primary-400" }),
              " Active Backup Job"
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { className: "grid grid-cols-1 md:grid-cols-3 gap-4", children: [
              /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { className: "bg-neutral-900/50 p-3 rounded", children: [
                /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("span", { className: "block text-xs font-bold text-neutral-500 uppercase", children: "Status" }),
                /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("strong", { className: "block text-sm text-primary-300 mt-1", children: pageData.activeJob.status })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { className: "bg-neutral-900/50 p-3 rounded", children: [
                /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("span", { className: "block text-xs font-bold text-neutral-500 uppercase", children: "Type" }),
                /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("strong", { className: "block text-sm text-neutral-200 mt-1", children: pageData.activeJob.type })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { className: "bg-neutral-900/50 p-3 rounded", children: [
                /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("span", { className: "block text-xs font-bold text-neutral-500 uppercase", children: "Updated" }),
                /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("strong", { className: "block text-sm text-neutral-200 mt-1 font-mono", children: formatWhen(pageData.activeJob.updatedAt) })
              ] })
            ] })
          ] }) : null,
          /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-lg overflow-hidden", children: [
            /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("div", { className: "px-6 py-4 border-b border-neutral-700 bg-neutral-800/80", children: /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("h2", { className: "text-lg font-bold text-neutral-100", children: "Backup History" }) }),
            /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { className: "flex flex-col", children: [
              !backups.length ? /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("div", { className: "p-8 text-center text-sm text-neutral-500", children: "No backups were recorded yet." }) : null,
              backups.map((entry, index) => /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { className: `p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-colors hover:bg-neutral-700/20 ${index !== backups.length - 1 ? "border-b border-neutral-700/50" : ""}`, children: [
                /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { className: "flex flex-col gap-2", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { className: "flex items-center gap-3", children: [
                    /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("i", { className: "bi bi-archive text-xl text-neutral-400" }),
                    /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("strong", { className: "text-neutral-100 font-mono text-sm tracking-wide", children: formatWhen(entry.createdAt) }),
                    /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("div", { className: `px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide inline-block ${statusColorClass(entry.status)}`, children: entry.status || "unknown" })
                  ] }),
                  /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { className: "text-sm text-neutral-400 flex items-center gap-2 pl-8", children: [
                    /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("span", { className: "capitalize", children: entry.trigger || "manual" }),
                    /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("span", { className: "text-neutral-600", children: "\u2022" }),
                    /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("span", { className: "font-mono", children: formatBytes2(entry.sizeBytes) })
                  ] }),
                  entry.error ? /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { className: "text-xs text-red-400 font-mono mt-1 pl-8 bg-red-900/10 p-2 rounded", children: [
                    /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("i", { className: "bi bi-exclamation-triangle mr-1" }),
                    " ",
                    entry.error
                  ] }) : null
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("div", { className: "flex flex-wrap items-center gap-2 sm:justify-end shrink-0 pt-3 sm:pt-0 border-t border-neutral-700 sm:border-0 pl-8 sm:pl-0", children: [
                  entry.webViewLink ? /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("a", { href: entry.webViewLink, className: "bg-transparent hover:bg-neutral-700 text-neutral-300 hover:text-white border border-neutral-600 hover:border-neutral-500 text-xs font-semibold py-1.5 px-4 rounded transition-colors flex items-center gap-2", target: "_blank", rel: "noreferrer", children: [
                    /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("i", { className: "bi bi-link-45deg" }),
                    " Open File"
                  ] }) : null,
                  entry.folderLink ? /* @__PURE__ */ (0, import_jsx_runtime16.jsxs)("a", { href: entry.folderLink, className: "bg-neutral-700 hover:bg-neutral-600 text-white border border-neutral-600 hover:border-neutral-500 text-xs font-semibold py-1.5 px-4 rounded transition-colors flex items-center gap-2", target: "_blank", rel: "noreferrer", children: [
                    /* @__PURE__ */ (0, import_jsx_runtime16.jsx)("i", { className: "bi bi-folder2-open" }),
                    " Folder"
                  ] }) : null
                ] })
              ] }, entry.id))
            ] })
          ] })
        ]
      }
    ) });
  }
  if (root4) {
    root4.render(
      /* @__PURE__ */ (0, import_jsx_runtime16.jsx)(ThemeContext_default, { pageData: data4, children: /* @__PURE__ */ (0, import_jsx_runtime16.jsx)(ServerBackupsPage, { pageData: data4 }) })
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === "function") {
      window.__CPANEL_REACT_BOOTED__();
    }
  }

  // views/react/server-network.jsx
  var import_react17 = __toESM(require_react());
  var import_client5 = __toESM(require_client());
  var import_jsx_runtime17 = __toESM(require_jsx_runtime());
  var data5 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry5 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "server-network";
  var root5 = standaloneEntry5 ? (0, import_client5.createRoot)(document.getElementById("reactRoot")) : null;
  function ServerNetworkPage({ pageData = data5 }) {
    const allocations = Array.isArray(pageData.allocations) ? pageData.allocations : [];
    const availableAllocations = Array.isArray(pageData.availableAllocations) ? pageData.availableAllocations : [];
    const summary = pageData.networkSummary || {};
    const canManage = Boolean(pageData.permissions && pageData.permissions.canManageNetwork);
    const actions = pageData.actions || {};
    const inputClass = "w-full bg-neutral-900 border border-neutral-700/50 rounded p-2.5 text-sm text-neutral-200 focus:ring-2 focus:ring-primary-500 focus:border-transparent outline-none transition-shadow";
    const labelClass = "block text-xs font-bold text-neutral-400 uppercase tracking-wide mb-1.5";
    return /* @__PURE__ */ (0, import_jsx_runtime17.jsx)(ReactAppShell, { pageData, subtitle: "Network", children: /* @__PURE__ */ (0, import_jsx_runtime17.jsxs)(PageContentBlock, { title: "Network Settings", description: "Review assigned allocations, switch the primary binding, and assign additional ports.", eyebrow: "Routing", children: [
      pageData.success && /* @__PURE__ */ (0, import_jsx_runtime17.jsxs)("div", { className: "bg-green-600/20 border border-green-600/50 text-green-100 p-4 rounded-lg mb-6 shadow-sm flex items-center gap-3", children: [
        /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("i", { className: "bi bi-check-circle-fill text-green-500" }),
        pageData.success
      ] }),
      pageData.error && /* @__PURE__ */ (0, import_jsx_runtime17.jsxs)("div", { className: "bg-red-600/20 border border-red-600/50 text-red-100 p-4 rounded-lg mb-6 shadow-sm flex items-center gap-3", children: [
        /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("i", { className: "bi bi-exclamation-triangle-fill text-red-500" }),
        pageData.error
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime17.jsxs)("div", { className: "grid grid-cols-1 lg:grid-cols-3 gap-6 items-start mb-6", children: [
        /* @__PURE__ */ (0, import_jsx_runtime17.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-lg p-6 lg:col-span-1", children: [
          /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("h2", { className: "text-lg font-bold text-neutral-100 mb-4", children: "Allocation Summary" }),
          /* @__PURE__ */ (0, import_jsx_runtime17.jsxs)("div", { className: "flex flex-col gap-4", children: [
            /* @__PURE__ */ (0, import_jsx_runtime17.jsxs)("div", { className: "flex justify-between items-center border-b border-neutral-700/50 pb-3", children: [
              /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("span", { className: "text-sm font-semibold text-neutral-400", children: "Total assigned" }),
              /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("strong", { className: "text-neutral-200 font-mono", children: allocations.length })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime17.jsxs)("div", { className: "flex justify-between items-center border-b border-neutral-700/50 pb-3", children: [
              /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("span", { className: "text-sm font-semibold text-neutral-400", children: "Token inventory" }),
              /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("strong", { className: "text-neutral-200 font-mono", children: summary.allocationTokens || 0 })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime17.jsxs)("div", { className: "flex justify-between items-center", children: [
              /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("span", { className: "text-sm font-semibold text-neutral-400", children: "Assignable left" }),
              /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("strong", { className: "text-neutral-200 font-mono", children: summary.remainingAssignable || 0 })
            ] })
          ] }),
          summary.inventoryAssignBlockedReason && /* @__PURE__ */ (0, import_jsx_runtime17.jsxs)("div", { className: "mt-6 bg-yellow-900/20 border border-yellow-500/30 text-yellow-200 p-3 rounded text-sm flex items-start gap-2", children: [
            /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("i", { className: "bi bi-exclamation-circle text-yellow-500 mt-0.5" }),
            summary.inventoryAssignBlockedReason
          ] })
        ] }),
        canManage && availableAllocations.length ? /* @__PURE__ */ (0, import_jsx_runtime17.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-lg p-6 lg:col-span-2", children: [
          /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("h2", { className: "text-lg font-bold text-neutral-100 mb-6", children: "Assign Allocation" }),
          /* @__PURE__ */ (0, import_jsx_runtime17.jsxs)("form", { method: "POST", action: actions.assign, className: "flex flex-col gap-5", children: [
            /* @__PURE__ */ (0, import_jsx_runtime17.jsxs)("label", { children: [
              /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("span", { className: labelClass, children: "Available Port" }),
              /* @__PURE__ */ (0, import_jsx_runtime17.jsxs)("div", { className: "relative", children: [
                /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("select", { name: "allocationId", defaultValue: availableAllocations[0].id, className: `${inputClass} font-mono appearance-none`, children: availableAllocations.map((entry) => /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("option", { value: entry.id, children: `${entry.ip}:${entry.port}` }, entry.id)) }),
                /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("div", { className: "pointer-events-none absolute inset-y-0 right-0 flex items-center px-4 text-neutral-400", children: /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("i", { className: "bi bi-chevron-down" }) })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("span", { className: "block text-xs text-neutral-500 mt-2", children: "These are unassigned ports mapped to your node that are currently reserved exclusively for you." })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("div", { className: "mt-2 flex justify-end", children: /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("button", { type: "submit", className: "bg-primary-600 hover:bg-primary-500 text-white font-semibold py-2 px-6 rounded transition-colors text-sm shadow-sm", children: "Assign Port" }) })
          ] })
        ] }) : canManage && !availableAllocations.length ? /* @__PURE__ */ (0, import_jsx_runtime17.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-lg p-6 lg:col-span-2 flex flex-col justify-center items-center text-center", children: [
          /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("i", { className: "bi bi-hdd-network text-4xl text-neutral-600 mb-3" }),
          /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("h2", { className: "text-lg font-bold text-neutral-100 mb-1", children: "No Ports Available" }),
          /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("p", { className: "text-sm text-neutral-400", children: "You do not have any free allocations available to assign." })
        ] }) : null
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime17.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-lg overflow-hidden", children: [
        /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("div", { className: "px-6 py-4 border-b border-neutral-700 bg-neutral-800/80", children: /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("h2", { className: "text-lg font-bold text-neutral-100", children: "Assigned Allocations" }) }),
        /* @__PURE__ */ (0, import_jsx_runtime17.jsxs)("div", { className: "flex flex-col", children: [
          !allocations.length ? /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("div", { className: "p-8 text-center text-sm text-neutral-500", children: "No allocations are assigned to this server." }) : null,
          allocations.map((entry, index) => /* @__PURE__ */ (0, import_jsx_runtime17.jsxs)("div", { className: `p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4 ${index !== allocations.length - 1 ? "border-b border-neutral-700/50" : ""}`, children: [
            /* @__PURE__ */ (0, import_jsx_runtime17.jsxs)("div", { className: "flex flex-col gap-2", children: [
              /* @__PURE__ */ (0, import_jsx_runtime17.jsxs)("div", { className: "flex items-center gap-3", children: [
                /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("strong", { className: "text-neutral-100 font-mono text-lg tracking-wide bg-neutral-900 border border-neutral-700 px-3 py-1 rounded", children: `${entry.ip}:${entry.port}` }),
                /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("div", { className: `px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wide inline-block ${entry.isPrimary ? "bg-primary-600/20 text-primary-400 border border-primary-600/30" : "bg-neutral-700 text-neutral-400 border border-neutral-600"}`, children: entry.isPrimary ? "Primary" : "Secondary" })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("span", { className: "text-sm text-neutral-500 itlaic", children: entry.notes || "No notes configured." })
            ] }),
            canManage ? /* @__PURE__ */ (0, import_jsx_runtime17.jsxs)("div", { className: "flex flex-wrap items-center gap-2 sm:justify-end shrink-0 pt-3 sm:pt-0 border-t border-neutral-700 sm:border-0 mt-2 sm:mt-0", children: [
              !entry.isPrimary ? /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("form", { method: "POST", action: `${actions.primaryBase}/${entry.id}/primary`, children: /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("button", { type: "submit", className: "bg-transparent hover:bg-neutral-700 text-neutral-300 hover:text-white border border-neutral-600 hover:border-neutral-500 text-xs font-semibold py-2 px-4 rounded transition-colors disabled:opacity-50", children: "Make Primary" }) }) : null,
              !entry.isPrimary ? /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("form", { method: "POST", action: `${actions.removeBase}/${entry.id}/delete`, children: /* @__PURE__ */ (0, import_jsx_runtime17.jsx)("button", { type: "submit", className: "bg-red-600/20 hover:bg-red-600 text-red-400 hover:text-white border border-red-600/30 hover:border-red-600 text-xs font-semibold py-2 px-4 rounded transition-colors disabled:opacity-50", children: "Remove" }) }) : null
            ] }) : null
          ] }, entry.id))
        ] })
      ] })
    ] }) });
  }
  if (root5) {
    root5.render(
      /* @__PURE__ */ (0, import_jsx_runtime17.jsx)(ThemeContext_default, { pageData: data5, children: /* @__PURE__ */ (0, import_jsx_runtime17.jsx)(ServerNetworkPage, { pageData: data5 }) })
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === "function") {
      window.__CPANEL_REACT_BOOTED__();
    }
  }

  // views/react/server-api.jsx
  var import_react18 = __toESM(require_react());
  var import_client6 = __toESM(require_client());
  var import_jsx_runtime18 = __toESM(require_jsx_runtime());
  var data6 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry6 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "server-api";
  var root6 = standaloneEntry6 ? (0, import_client6.createRoot)(document.getElementById("reactRoot")) : null;
  function formatDate2(value, fallback = "Never") {
    if (!value) return fallback;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? fallback : date.toLocaleString();
  }
  function CopyTokenButton({ value }) {
    const [copied, setCopied] = import_react18.default.useState(false);
    if (!value) return null;
    return /* @__PURE__ */ (0, import_jsx_runtime18.jsx)(
      "button",
      {
        type: "button",
        className: "bg-neutral-800 hover:bg-neutral-700 text-neutral-300 hover:text-white border border-neutral-700 font-semibold py-1.5 px-3 rounded text-sm transition-colors opacity-90 hover:opacity-100 flex items-center justify-center min-w-[70px]",
        onClick: async () => {
          try {
            await navigator.clipboard.writeText(value);
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1200);
          } catch {
            setCopied(false);
          }
        },
        children: copied ? "Copied" : "Copy"
      }
    );
  }
  function ServerApiPage({ pageData = data6 }) {
    const apiKeys = Array.isArray(pageData.apiKeys) ? pageData.apiKeys : [];
    const canManage = Boolean(pageData.permissions && pageData.permissions.canManageApiKeys);
    const permissionCatalog = Array.isArray(pageData.apiPermissionCatalog) ? pageData.apiPermissionCatalog : [];
    const actions = pageData.actions || {};
    const inputClass = "w-full bg-neutral-900 border border-neutral-700/50 rounded p-2.5 text-sm text-neutral-200 focus:ring-2 focus:ring-primary-500 focus:border-transparent outline-none transition-shadow";
    const labelClass = "block text-xs font-bold text-neutral-400 uppercase tracking-wide mb-1.5";
    return /* @__PURE__ */ (0, import_jsx_runtime18.jsx)(ReactAppShell, { pageData, subtitle: "API keys", children: /* @__PURE__ */ (0, import_jsx_runtime18.jsxs)(PageContentBlock, { title: "API Keys", description: "Create and rotate per-server API credentials without leaving the React view. Existing POST flows remain unchanged.", eyebrow: "Automation", children: [
      pageData.success && /* @__PURE__ */ (0, import_jsx_runtime18.jsxs)("div", { className: "bg-green-600/20 border border-green-600/50 text-green-100 p-4 rounded-lg mb-6 shadow-sm flex items-center gap-3", children: [
        /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("i", { className: "bi bi-check-circle-fill text-green-500" }),
        pageData.success
      ] }),
      pageData.error && /* @__PURE__ */ (0, import_jsx_runtime18.jsxs)("div", { className: "bg-red-600/20 border border-red-600/50 text-red-100 p-4 rounded-lg mb-6 shadow-sm flex items-center gap-3", children: [
        /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("i", { className: "bi bi-exclamation-triangle-fill text-red-500" }),
        pageData.error
      ] }),
      pageData.freshToken && pageData.freshToken.token ? /* @__PURE__ */ (0, import_jsx_runtime18.jsxs)("section", { className: "bg-neutral-800 border-2 border-primary-600/50 rounded-lg p-6 mb-6", children: [
        /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("h2", { className: "text-lg font-bold text-white mb-2", children: "New Token Created" }),
        /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("p", { className: "text-sm text-primary-300 mb-4 font-semibold", children: "This is the only time the full token is shown. Please copy it now." }),
        /* @__PURE__ */ (0, import_jsx_runtime18.jsxs)("div", { className: "bg-neutral-900 border border-neutral-700 flex flex-col sm:flex-row items-center justify-between rounded p-4 gap-4", children: [
          /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("code", { className: "text-primary-400 font-mono text-sm break-all", children: pageData.freshToken.token }),
          /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("div", { className: "shrink-0 w-full sm:w-auto flex justify-end", children: /* @__PURE__ */ (0, import_jsx_runtime18.jsx)(CopyTokenButton, { value: pageData.freshToken.token }) })
        ] })
      ] }) : null,
      /* @__PURE__ */ (0, import_jsx_runtime18.jsxs)("div", { className: "grid grid-cols-1 lg:grid-cols-12 gap-6 items-start", children: [
        /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("div", { className: "lg:col-span-4 flex flex-col gap-6", children: /* @__PURE__ */ (0, import_jsx_runtime18.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-lg p-6", children: [
          /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("h2", { className: "text-lg font-bold text-neutral-100 mb-6", children: "Create API Key" }),
          /* @__PURE__ */ (0, import_jsx_runtime18.jsxs)("form", { method: "POST", action: actions.create, className: "flex flex-col gap-5", children: [
            /* @__PURE__ */ (0, import_jsx_runtime18.jsxs)("label", { children: [
              /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("span", { className: labelClass, children: "Description" }),
              /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("input", { type: "text", name: "name", maxLength: 120, required: true, placeholder: "CI deploy key", className: inputClass })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime18.jsxs)("label", { children: [
              /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("span", { className: labelClass, children: "Expires at" }),
              /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("input", { type: "datetime-local", name: "expiresAt", className: `${inputClass} text-neutral-400` })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime18.jsxs)("div", { className: "mt-2", children: [
              /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("span", { className: labelClass, children: "Permissions" }),
              /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("div", { className: "bg-neutral-900/50 border border-neutral-700/50 rounded-lg p-4 flex flex-col gap-3 max-h-[300px] overflow-y-auto mt-2", children: permissionCatalog.map((permission) => /* @__PURE__ */ (0, import_jsx_runtime18.jsxs)("label", { className: "flex items-start gap-3 cursor-pointer group", children: [
                /* @__PURE__ */ (0, import_jsx_runtime18.jsx)(
                  "input",
                  {
                    type: "checkbox",
                    name: "permissions",
                    value: permission,
                    defaultChecked: permission === "server.view",
                    className: "w-4 h-4 mt-0.5 rounded border-neutral-600 bg-neutral-900 text-primary-600 focus:ring-primary-600 focus:ring-offset-neutral-800"
                  }
                ),
                /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("span", { className: "text-sm text-neutral-300 font-mono group-hover:text-white transition-colors", children: permission })
              ] }, permission)) })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("div", { className: "mt-2 flex justify-end", children: /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("button", { type: "submit", className: "w-full bg-primary-600 hover:bg-primary-500 text-white font-semibold py-2 px-6 rounded transition-colors text-sm shadow-sm disabled:opacity-50", disabled: !canManage, children: "Create Key" }) })
          ] })
        ] }) }),
        /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("div", { className: "lg:col-span-8 flex flex-col gap-6", children: /* @__PURE__ */ (0, import_jsx_runtime18.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-lg overflow-hidden", children: [
          /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("div", { className: "px-6 py-4 border-b border-neutral-700 bg-neutral-800/80", children: /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("h2", { className: "text-lg font-bold text-neutral-100", children: "Active API Keys" }) }),
          /* @__PURE__ */ (0, import_jsx_runtime18.jsxs)("div", { className: "flex flex-col", children: [
            !apiKeys.length ? /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("div", { className: "p-8 text-center text-sm text-neutral-500", children: "No API keys exist for this server yet." }) : null,
            apiKeys.map((entry, index) => /* @__PURE__ */ (0, import_jsx_runtime18.jsxs)("div", { className: `p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4 ${index !== apiKeys.length - 1 ? "border-b border-neutral-700/50" : ""}`, children: [
              /* @__PURE__ */ (0, import_jsx_runtime18.jsxs)("div", { className: "flex flex-col gap-1.5", children: [
                /* @__PURE__ */ (0, import_jsx_runtime18.jsxs)("div", { className: "flex flex-wrap items-center gap-3", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("strong", { className: "text-neutral-100", children: entry.name }),
                  /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("div", { className: `px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide ${entry.active ? "bg-green-600/20 text-green-400 border border-green-600/30" : "bg-red-600/20 text-red-400 border border-red-600/30"}`, children: entry.active ? "Active" : "Inactive" })
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("div", { className: "flex items-center gap-2 mt-1", children: /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("span", { className: "text-sm font-mono text-neutral-400 bg-neutral-900 px-2 py-0.5 rounded", children: entry.keyPrefixMasked }) }),
                /* @__PURE__ */ (0, import_jsx_runtime18.jsxs)("small", { className: "text-xs text-neutral-500 mt-1 flex items-center gap-1.5", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("i", { className: "bi bi-clock-history" }),
                  "Last used: ",
                  formatDate2(entry.lastUsedAt, "Never")
                ] })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime18.jsxs)("div", { className: "flex flex-wrap items-center gap-2 sm:justify-end shrink-0 pt-2 sm:pt-0 mt-3 sm:mt-0 border-t border-neutral-700 sm:border-0", children: [
                /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("form", { method: "POST", action: `${actions.keyBase}/${entry.id}/rotate`, children: /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("button", { type: "submit", className: "bg-transparent hover:bg-neutral-700 text-neutral-300 hover:text-white border border-neutral-600 hover:border-neutral-500 text-xs font-semibold py-1.5 px-3 rounded transition-colors disabled:opacity-50", disabled: !canManage || !entry.active, children: "Rotate" }) }),
                /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("form", { method: "POST", action: `${actions.keyBase}/${entry.id}/revoke`, children: /* @__PURE__ */ (0, import_jsx_runtime18.jsx)("button", { type: "submit", className: "bg-red-600/20 hover:bg-red-600 text-red-400 hover:text-white border border-red-600/30 hover:border-red-600 text-xs font-semibold py-1.5 px-3 rounded transition-colors disabled:opacity-50", disabled: !canManage || !entry.active, children: "Revoke" }) })
              ] })
            ] }, entry.id))
          ] })
        ] }) })
      ] })
    ] }) });
  }
  if (root6) {
    root6.render(
      /* @__PURE__ */ (0, import_jsx_runtime18.jsx)(ThemeContext_default, { pageData: data6, children: /* @__PURE__ */ (0, import_jsx_runtime18.jsx)(ServerApiPage, { pageData: data6 }) })
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === "function") {
      window.__CPANEL_REACT_BOOTED__();
    }
  }

  // views/react/server-databases.jsx
  var import_react19 = __toESM(require_react());
  var import_client7 = __toESM(require_client());
  var import_jsx_runtime19 = __toESM(require_jsx_runtime());
  var data7 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry7 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "server-databases";
  var root7 = standaloneEntry7 ? (0, import_client7.createRoot)(document.getElementById("reactRoot")) : null;
  function ServerDatabasesPage({ pageData = data7 }) {
    const server = pageData.server || {};
    const hostsList = Array.isArray(pageData.hosts) ? pageData.hosts : [];
    const dbList = Array.isArray(pageData.databases) ? pageData.databases : [];
    const limit = Math.max(0, Number.parseInt(pageData.databaseLimit, 10) || 0);
    const used = dbList.length;
    const remaining = Math.max(0, limit - used);
    const canManage = Boolean(pageData.canManageDatabases);
    const canCreate = canManage && hostsList.length > 0 && remaining > 0;
    const [revealedPasswords, setRevealedPasswords] = (0, import_react19.useState)({});
    const togglePassword = (idx) => {
      setRevealedPasswords((prev) => ({ ...prev, [idx]: !prev[idx] }));
    };
    const copyPassword = async (pass) => {
      try {
        await navigator.clipboard.writeText(pass);
      } catch {
      }
    };
    const deleteDatabase = async (id, e) => {
      if (!window.confirm("Delete this database and its DB user from the host? This cannot be undone.")) {
        e.preventDefault();
      }
    };
    return /* @__PURE__ */ (0, import_jsx_runtime19.jsx)(ReactAppShell, { pageData, subtitle: "Databases", children: /* @__PURE__ */ (0, import_jsx_runtime19.jsxs)(PageContentBlock, { title: "Databases", description: "Manage database instances for this server.", children: [
      !hostsList.length && /* @__PURE__ */ (0, import_jsx_runtime19.jsxs)("div", { className: "bg-yellow-500/10 border-l-4 border-yellow-500 text-yellow-500 p-4 rounded-r-lg mb-6 shadow-sm", children: [
        /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("i", { className: "bi bi-exclamation-triangle-fill me-2" }),
        "No database host is configured on this server location. Ask an admin to add one."
      ] }),
      limit <= 0 && /* @__PURE__ */ (0, import_jsx_runtime19.jsxs)("div", { className: "bg-blue-500/10 border-l-4 border-blue-500 text-blue-400 p-4 rounded-r-lg mb-6 shadow-sm", children: [
        /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("i", { className: "bi bi-info-circle-fill me-2" }),
        "This server has ",
        /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("strong", { children: "0 database slots" }),
        ". Increase database slots from the configuration panel before creating databases."
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime19.jsxs)("div", { className: "flex gap-4 mb-6 pt-2", children: [
        /* @__PURE__ */ (0, import_jsx_runtime19.jsxs)("span", { className: "px-3 py-1 bg-neutral-800 border border-neutral-700 text-neutral-300 rounded text-sm font-bold shadow-sm", children: [
          "Used: ",
          used,
          " / ",
          limit
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime19.jsxs)("span", { className: `px-3 py-1 border text-sm font-bold shadow-sm rounded ${remaining > 0 ? "bg-green-500/10 border-green-500/30 text-green-400" : "bg-red-500/10 border-red-500/30 text-red-500"}`, children: [
          "Remaining: ",
          remaining
        ] })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime19.jsxs)("div", { className: "bg-neutral-900 border border-neutral-700 rounded-lg p-5 mb-8 shadow-sm", children: [
        /* @__PURE__ */ (0, import_jsx_runtime19.jsxs)("div", { className: "flex justify-between items-center mb-4", children: [
          /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("h2", { className: "text-lg font-bold text-neutral-100", children: "Create Database" }),
          !canManage && /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("span", { className: "text-xs px-2 py-1 bg-neutral-800 border border-neutral-700 rounded text-neutral-400", children: "Read Only" })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime19.jsxs)("form", { method: "POST", action: `/server/${server.containerId}/databases/create`, className: "flex flex-col md:flex-row gap-4", "data-turbo": "false", children: [
          /* @__PURE__ */ (0, import_jsx_runtime19.jsxs)("div", { className: "flex-1 md:max-w-xs", children: [
            /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("label", { className: "block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-2", children: "Host" }),
            /* @__PURE__ */ (0, import_jsx_runtime19.jsx)(
              "input",
              {
                type: "text",
                className: "w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-400 focus:outline-none",
                value: "Auto selected by location policy",
                readOnly: true
              }
            )
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime19.jsxs)("div", { className: "flex-1", children: [
            /* @__PURE__ */ (0, import_jsx_runtime19.jsxs)("label", { className: "block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-2", children: [
              "Database Name ",
              /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("span", { className: "text-neutral-500 lowercase ml-1", children: "(Optional)" })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime19.jsx)(
              "input",
              {
                type: "text",
                name: "databaseName",
                maxLength: "64",
                className: "w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500",
                placeholder: "example_db",
                disabled: !canCreate
              }
            )
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("div", { className: "flex items-end", children: /* @__PURE__ */ (0, import_jsx_runtime19.jsx)(
            "button",
            {
              type: "submit",
              className: "bg-primary-600 hover:bg-primary-500 text-white text-sm font-bold px-6 py-2 rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-sm",
              disabled: !canCreate,
              children: "Create Database"
            }
          ) })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("div", { className: "text-xs text-neutral-500 mt-4", children: "Username and password are generated automatically when a database is created." })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime19.jsxs)("div", { className: "bg-neutral-900 border border-neutral-700 rounded-lg overflow-hidden shadow-sm", children: [
        /* @__PURE__ */ (0, import_jsx_runtime19.jsxs)("div", { className: "bg-neutral-800/50 px-5 py-4 border-b border-neutral-700 flex justify-between items-center", children: [
          /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("h2", { className: "text-base font-bold text-neutral-100", children: "Provisioned Databases" }),
          /* @__PURE__ */ (0, import_jsx_runtime19.jsxs)("span", { className: "text-sm font-bold text-neutral-400", children: [
            dbList.length,
            " Items"
          ] })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("div", { className: "overflow-x-auto", children: /* @__PURE__ */ (0, import_jsx_runtime19.jsxs)("table", { className: "w-full text-left border-collapse", children: [
          /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("thead", { children: /* @__PURE__ */ (0, import_jsx_runtime19.jsxs)("tr", { className: "bg-neutral-800 border-b border-neutral-700", children: [
            /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("th", { className: "px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest", children: "Host" }),
            /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("th", { className: "px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest", children: "Database" }),
            /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("th", { className: "px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest", children: "User" }),
            /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("th", { className: "px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest w-64", children: "Password" }),
            /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("th", { className: "px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest", children: "Created" }),
            /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("th", { className: "px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest text-right", children: "Actions" })
          ] }) }),
          /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("tbody", { children: dbList.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("tr", { children: /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("td", { colSpan: "6", className: "text-center py-8 text-neutral-500 text-sm", children: "No databases created yet." }) }) : dbList.map((entry, idx) => /* @__PURE__ */ (0, import_jsx_runtime19.jsxs)("tr", { className: "border-b border-neutral-700/50 hover:bg-neutral-800/30 transition-colors", children: [
            /* @__PURE__ */ (0, import_jsx_runtime19.jsxs)("td", { className: "px-5 py-4", children: [
              /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("div", { className: "font-bold text-neutral-200 text-sm", children: entry.host ? entry.host.name : "Unknown host" }),
              /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("div", { className: "text-xs text-neutral-500 mt-1", children: entry.host ? `${entry.host.host}:${entry.host.port}` : "-" })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("td", { className: "px-5 py-4", children: /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("span", { className: "px-2 py-1 bg-primary-600/10 text-primary-400 border border-primary-600/20 rounded text-xs font-bold shadow-sm", children: entry.name }) }),
            /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("td", { className: "px-5 py-4", children: /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("code", { className: "text-xs text-green-400 bg-neutral-900 border border-neutral-700 px-2 py-1 rounded shadow-sm", children: entry.username }) }),
            /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("td", { className: "px-5 py-4", children: /* @__PURE__ */ (0, import_jsx_runtime19.jsxs)("div", { className: "flex bg-neutral-900 border border-neutral-700 rounded overflow-hidden shadow-sm", children: [
              /* @__PURE__ */ (0, import_jsx_runtime19.jsx)(
                "input",
                {
                  type: revealedPasswords[idx] ? "text" : "password",
                  className: "w-full bg-transparent border-none px-2 py-1 text-xs text-neutral-300 focus:outline-none",
                  value: entry.password,
                  readOnly: true
                }
              ),
              /* @__PURE__ */ (0, import_jsx_runtime19.jsx)(
                "button",
                {
                  type: "button",
                  className: "px-2 py-1 text-neutral-400 hover:text-white hover:bg-neutral-700 transition",
                  onClick: () => togglePassword(idx),
                  children: /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("i", { className: `bi ${revealedPasswords[idx] ? "bi-eye-slash" : "bi-eye"}` })
                }
              ),
              /* @__PURE__ */ (0, import_jsx_runtime19.jsx)(
                "button",
                {
                  type: "button",
                  className: "px-2 py-1 text-primary-400 hover:text-primary-300 hover:bg-primary-900/50 transition border-l border-neutral-700",
                  onClick: () => copyPassword(entry.password),
                  children: /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("i", { className: "bi bi-clipboard" })
                }
              )
            ] }) }),
            /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("td", { className: "px-5 py-4 text-xs text-neutral-500 whitespace-nowrap", children: new Date(entry.createdAt).toLocaleString() }),
            /* @__PURE__ */ (0, import_jsx_runtime19.jsxs)("td", { className: "px-5 py-4 flex items-center justify-end gap-2", children: [
              /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("a", { href: `/server/${server.containerId}/database/${encodeURIComponent(entry.name)}`, className: "text-neutral-400 hover:text-primary-400 transition", title: "Open Database Manager", children: /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("i", { className: "bi bi-box-arrow-up-right" }) }),
              canManage && /* @__PURE__ */ (0, import_jsx_runtime19.jsxs)(import_jsx_runtime19.Fragment, { children: [
                /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("form", { method: "POST", action: `/server/${server.containerId}/databases/${entry.id}/password`, "data-turbo": "false", children: /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("button", { type: "submit", className: "text-yellow-500 hover:text-yellow-400 transition", title: "Rotate Password", children: /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("i", { className: "bi bi-key" }) }) }),
                /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("form", { method: "POST", action: `/server/${server.containerId}/databases/${entry.id}/delete`, onClick: (e) => deleteDatabase(entry.id, e), "data-turbo": "false", children: /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("button", { type: "submit", className: "text-red-500 hover:text-red-400 transition", title: "Delete Database", children: /* @__PURE__ */ (0, import_jsx_runtime19.jsx)("i", { className: "bi bi-trash" }) }) })
              ] })
            ] })
          ] }, entry.id)) })
        ] }) })
      ] })
    ] }) });
  }
  if (root7) {
    root7.render(
      /* @__PURE__ */ (0, import_jsx_runtime19.jsx)(ThemeContext_default, { pageData: data7, children: /* @__PURE__ */ (0, import_jsx_runtime19.jsx)(ServerDatabasesPage, { pageData: data7 }) })
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === "function") {
      window.__CPANEL_REACT_BOOTED__();
    }
  }

  // views/react/server-users.jsx
  var import_react20 = __toESM(require_react());
  var import_client8 = __toESM(require_client());
  var import_jsx_runtime20 = __toESM(require_jsx_runtime());
  var data8 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry8 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "server-users";
  var root8 = standaloneEntry8 ? (0, import_client8.createRoot)(document.getElementById("reactRoot")) : null;
  var userPermissionDescriptions = {
    "server.view": "Access the server overview and basic details.",
    "server.tags.manage": "Edit server folder and tags on overview.",
    "server.console": "View the console and send commands.",
    "server.power": "Start, stop, restart, or kill the server.",
    "server.files": "View and edit server files.",
    "server.startup": "Change startup command and variables.",
    "server.minecraft": "Access Minecraft tools (mods/plugins).",
    "server.proxy.manage": "Manage proxy network panel, backends, groups, and sync.",
    "server.ai.use": "Use Rocky AI assistant in console.",
    "server.ai.manage": "Manage Rocky AI permissions for this server.",
    "minecraft.inspect": "Inspect player inventory, health, gamemode, location.",
    "minecraft.freeze": "Freeze/unfreeze players using effects.",
    "minecraft.kick": "Kick players from the Minecraft server.",
    "minecraft.ban": "Ban players from the Minecraft server.",
    "minecraft.banlist": "View banlist and unban players.",
    "minecraft.op": "Grant operator rights with /op.",
    "minecraft.deop": "Remove operator rights with /deop.",
    "minecraft.tempban": "Temporarily ban players from the Minecraft server.",
    "minecraft.teleport": "Teleport players with /tp.",
    "minecraft.chat": "Control slow chat or mute chat server-wide.",
    "minecraft.whitelist": "Manage server whitelist (add/remove/import).",
    "server.backups.view": "View backups list.",
    "server.backups.manage": "Create/delete backups (if enabled).",
    "server.gdrive": "Use Google Drive backup actions (manual/auto policy).",
    "server.databases.view": "View databases linked to the server.",
    "server.databases.manage": "Create/update/delete databases.",
    "server.schedules.view": "View schedules.",
    "server.schedules.manage": "Create/update/delete schedules.",
    "server.network.view": "View allocations and ports.",
    "server.network.manage": "Manage allocations/ports.",
    "server.mounts": "Attach/detach mounts.",
    "server.users.view": "View subusers list.",
    "server.users.manage": "Invite/remove subusers and edit permissions.",
    "server.activity.view": "View activity logs.",
    "server.audit.read": "Read audit console events (read-only).",
    "server.timeline.view": "View live resource timeline.",
    "server.performance.view": "View performance insights (plugins/mods).",
    "server.macros": "Manage and run command macros.",
    "server.recovery": "Use recovery assistant actions.",
    "server.smartalerts": "Configure smart alerts.",
    "server.policy": "Configure policy engine."
  };
  function PermissionBadge({ permissions }) {
    const [isHovered, setIsHovered] = import_react20.default.useState(false);
    if (!Array.isArray(permissions)) return null;
    return /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)(
      "div",
      {
        className: "relative inline-block",
        onMouseEnter: () => setIsHovered(true),
        onMouseLeave: () => setIsHovered(false),
        children: [
          /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)("div", { className: "bg-primary-900/30 text-primary-400 border border-primary-500/30 px-3 py-1 rounded-full text-[11px] font-bold tracking-tight cursor-help shadow-sm hover:bg-primary-900/50 transition-colors flex items-center gap-2", children: [
            /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("i", { className: "bi bi-shield-check" }),
            permissions.length,
            " Permissions"
          ] }),
          isHovered && /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)("div", { className: "absolute z-50 left-0 mt-2 p-4 bg-neutral-900 border border-neutral-700 rounded-xl shadow-2xl w-72 animate-in fade-in zoom-in-95 duration-200 pointer-events-none", children: [
            /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)("div", { className: "text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-3 border-b border-neutral-800 pb-2 flex justify-between", children: [
              /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("span", { children: "Permission Bundle" }),
              /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)("span", { className: "text-primary-500", children: [
                permissions.length,
                " items"
              ] })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("div", { className: "flex flex-wrap gap-1.5 max-h-64 overflow-y-auto no-scrollbar", children: permissions.map((p) => /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("span", { className: "text-[10px] font-semibold bg-neutral-800 text-neutral-200 px-2 py-0.5 rounded border border-neutral-700", children: p }, p)) }),
            /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("div", { className: "mt-3 text-[10px] text-neutral-500 italic", children: "Move mouse away to close list" })
          ] })
        ]
      }
    );
  }
  function ServerUsersPage({ pageData = data8 }) {
    const server = pageData.server || {};
    const memberships = Array.isArray(pageData.memberships) ? pageData.memberships : [];
    const owner = pageData.owner || null;
    const canManageUsers = Boolean(pageData.canManageUsers);
    const [isModalOpen, setIsModalOpen] = (0, import_react20.useState)(false);
    const [editingMembership, setEditingMembership] = (0, import_react20.useState)(null);
    const [identifier, setIdentifier] = (0, import_react20.useState)("");
    const [selectedPermissions, setSelectedPermissions] = (0, import_react20.useState)(["server.view"]);
    const [selectedPreset, setSelectedPreset] = (0, import_react20.useState)("");
    const presets = pageData.permissionPresets || [];
    const catalog = pageData.permissionCatalog || [];
    const handleOpenCreate = () => {
      setEditingMembership(null);
      setIdentifier("");
      setSelectedPermissions(["server.view"]);
      setSelectedPreset("");
      setIsModalOpen(true);
    };
    const handleOpenEdit = (membership) => {
      setEditingMembership(membership);
      setIdentifier(membership.user?.email || membership.user?.username || "");
      const perms = Array.isArray(membership.permissions) && membership.permissions.length > 0 ? membership.permissions : ["server.view"];
      setSelectedPermissions(perms);
      const sortedSelected = [...perms].sort();
      const matchedPreset = presets.find((p) => {
        const presetPerms = [...p.permissions].sort();
        return presetPerms.length === sortedSelected.length && presetPerms.every((v, i) => v === sortedSelected[i]);
      });
      setSelectedPreset(matchedPreset ? matchedPreset.id : "");
      setIsModalOpen(true);
    };
    const handleTogglePerm = (perm) => {
      if (perm === "server.view") return;
      setSelectedPermissions(
        (current) => current.includes(perm) ? current.filter((p) => p !== perm) : [...current, perm]
      );
      setSelectedPreset("");
    };
    const applyPreset = () => {
      if (!selectedPreset) return;
      const preset = presets.find((p) => String(p.id) === String(selectedPreset));
      if (preset) {
        setSelectedPermissions(Array.from(/* @__PURE__ */ new Set([...preset.permissions, "server.view"])));
      }
    };
    const resetPermissions = () => {
      setSelectedPermissions(["server.view"]);
      setSelectedPreset("");
    };
    return /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)(ReactAppShell, { pageData, subtitle: "Users", children: [
      /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)(PageContentBlock, { title: "Users", description: "Manage subusers and configure access control lists.", children: [
        pageData.success && /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("div", { className: "bg-green-600/20 border-l-4 border-green-600 text-green-100 p-4 rounded-r-lg mb-6 shadow-sm", children: pageData.success }),
        pageData.error && /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("div", { className: "bg-red-600/20 border-l-4 border-red-600 text-red-100 p-4 rounded-r-lg mb-6 shadow-sm", children: pageData.error }),
        /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("div", { className: "grid grid-cols-1 md:grid-cols-3 gap-6 mb-8", children: /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)("div", { className: "bg-neutral-900 border border-neutral-700 rounded-lg p-5 shadow-sm col-span-1 border-t-2 border-t-primary-500", children: [
          /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("div", { className: "text-xs font-bold text-neutral-500 uppercase tracking-widest mb-3", children: "Owner" }),
          /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("div", { className: "font-bold text-white text-lg", children: owner ? owner.username : "Unknown" }),
          /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("div", { className: "text-sm text-neutral-400 mt-1", children: owner ? owner.email : "-" })
        ] }) }),
        /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)("div", { className: "bg-neutral-900 border border-neutral-700 rounded-lg overflow-hidden shadow-sm", children: [
          /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)("div", { className: "bg-neutral-800/50 px-5 py-4 border-b border-neutral-700 flex justify-between items-center", children: [
            /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("h2", { className: "text-base font-bold text-neutral-100", children: "Subusers" }),
            canManageUsers && /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)(
              "button",
              {
                onClick: handleOpenCreate,
                className: "bg-primary-600 hover:bg-primary-500 text-white text-xs font-bold px-3 py-1.5 rounded transition-colors shadow-sm",
                children: [
                  /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("i", { className: "bi bi-person-plus me-1" }),
                  " Invite"
                ]
              }
            )
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("div", { className: "overflow-x-auto", children: /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)("table", { className: "w-full text-left border-collapse", children: [
            /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("thead", { children: /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)("tr", { className: "bg-neutral-800 border-b border-neutral-700", children: [
              /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("th", { className: "px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest", children: "User" }),
              /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("th", { className: "px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest", children: "Permissions" }),
              /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("th", { className: "px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest", children: "Invited By" }),
              /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("th", { className: "px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest text-right", children: "Actions" })
            ] }) }),
            /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("tbody", { children: !memberships.length ? /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("tr", { children: /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("td", { colSpan: "4", className: "text-center py-8 text-neutral-500 text-sm", children: "No subusers yet." }) }) : memberships.map((entry) => /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)("tr", { className: "border-b border-neutral-700/50 hover:bg-neutral-800/30 transition-colors", children: [
              /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)("td", { className: "px-5 py-4", children: [
                /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("div", { className: "font-bold text-neutral-200 text-sm", children: entry.user ? entry.user.username : `#${entry.userId}` }),
                /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("div", { className: "text-xs text-neutral-500", children: entry.user?.email || "" })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("td", { className: "px-5 py-4", children: /* @__PURE__ */ (0, import_jsx_runtime20.jsx)(PermissionBadge, { permissions: entry.permissions }) }),
              /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("td", { className: "px-5 py-4 text-sm text-neutral-400", children: entry.invitedBy ? entry.invitedBy.username : "-" }),
              /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("td", { className: "px-5 py-4 text-right", children: canManageUsers ? /* @__PURE__ */ (0, import_jsx_runtime20.jsx)(
                "button",
                {
                  onClick: () => handleOpenEdit(entry),
                  className: "bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 text-white text-xs font-bold px-3 py-1.5 rounded transition-colors shadow-sm",
                  children: "Manage"
                }
              ) : /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("span", { className: "text-neutral-500", children: "-" }) })
            ] }, entry.id)) })
          ] }) })
        ] })
      ] }),
      isModalOpen && /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("div", { className: "fixed inset-0 z-50 flex items-center justify-center p-4 bg-neutral-900/80 backdrop-blur-sm overflow-y-auto", children: /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)("div", { className: "bg-neutral-900 border border-neutral-700 rounded-xl shadow-2xl w-full max-w-3xl my-8", children: [
        /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)("div", { className: "flex justify-between items-center p-5 border-b border-neutral-700", children: [
          /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("h3", { className: "text-lg font-bold text-white", children: editingMembership ? `Manage ${editingMembership.user?.username || "Subuser"}` : "Invite Subuser" }),
          /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("button", { onClick: () => setIsModalOpen(false), className: "text-neutral-400 hover:text-white transition", children: /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("i", { className: "bi bi-x-lg" }) })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("div", { className: "p-5 overflow-y-auto max-h-[70vh]", children: /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)("form", { id: "subuserForm", method: "POST", action: `/server/${server.containerId}/users`, "data-turbo": "false", children: [
          /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("input", { type: "hidden", name: "membershipId", value: editingMembership ? editingMembership.id : "" }),
          /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)("div", { className: "mb-6", children: [
            /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("label", { className: "block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-2", children: "User Identifier" }),
            /* @__PURE__ */ (0, import_jsx_runtime20.jsx)(
              "input",
              {
                name: "identifier",
                className: `w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-primary-500 ${editingMembership ? "opacity-50 cursor-not-allowed" : ""}`,
                placeholder: "Username or email",
                value: identifier,
                onChange: (e) => setIdentifier(e.target.value),
                readOnly: !!editingMembership
              }
            )
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)("div", { className: "mb-4", children: [
            /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("label", { className: "block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-2", children: "Permissions" }),
            /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-lg p-3 mb-4 flex flex-col md:flex-row gap-3 items-end", children: [
              /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)("div", { className: "flex-1 w-full", children: [
                /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("label", { className: "block text-xs font-bold text-neutral-500 uppercase tracking-widest mb-1", children: "Preset Bundle" }),
                /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)(
                  "select",
                  {
                    className: "w-full bg-neutral-900 border border-neutral-700 rounded px-3 py-2 text-sm text-white focus:outline-none",
                    value: selectedPreset,
                    onChange: (e) => setSelectedPreset(e.target.value),
                    children: [
                      /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("option", { value: "", children: "Custom Selection" }),
                      presets.map((p) => /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("option", { value: p.id, children: p.label }, p.id))
                    ]
                  }
                )
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)("div", { className: "flex gap-2 w-full md:w-auto", children: [
                /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)("button", { type: "button", onClick: applyPreset, className: "bg-primary-600/20 text-primary-400 border border-primary-600/30 hover:bg-primary-600/30 rounded px-4 py-2 text-sm font-bold transition flex-1 md:flex-none", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("i", { className: "bi bi-magic me-1" }),
                  " Apply Preset"
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("button", { type: "button", onClick: resetPermissions, className: "bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 rounded px-4 py-2 text-sm font-bold text-white transition flex-1 md:flex-none", children: "Reset" })
              ] })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-3", children: catalog.map((perm) => /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)("label", { className: "flex items-start gap-3 p-3 bg-neutral-800/50 border border-neutral-700 rounded-lg cursor-pointer hover:bg-neutral-800 transition-colors", children: [
              /* @__PURE__ */ (0, import_jsx_runtime20.jsx)(
                "input",
                {
                  type: "checkbox",
                  name: "permissions",
                  value: perm,
                  checked: selectedPermissions.includes(perm),
                  onChange: () => handleTogglePerm(perm),
                  disabled: perm === "server.view",
                  className: "mt-0.5 bg-neutral-900 border-neutral-600 text-primary-500 focus:ring-0 rounded"
                }
              ),
              /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)("div", { children: [
                /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("div", { className: "text-sm font-bold text-white", children: perm }),
                /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("div", { className: "text-xs text-neutral-500 mt-0.5 whitespace-normal break-words", children: userPermissionDescriptions[perm] || "Access standard endpoints" })
              ] })
            ] }, perm)) })
          ] })
        ] }) }),
        /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)("div", { className: "flex items-center justify-between p-5 border-t border-neutral-700 bg-neutral-900 rounded-b-xl", children: [
          editingMembership ? /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("form", { method: "POST", action: `/server/${server.containerId}/users/${editingMembership.id}/delete`, "data-turbo": "false", children: /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("button", { type: "submit", className: "text-red-500 hover:text-red-400 text-sm font-bold transition", children: "Remove Subuser" }) }) : /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("div", {}),
          /* @__PURE__ */ (0, import_jsx_runtime20.jsxs)("div", { className: "flex gap-3", children: [
            /* @__PURE__ */ (0, import_jsx_runtime20.jsx)("button", { onClick: () => setIsModalOpen(false), className: "px-4 py-2 bg-neutral-800 hover:bg-neutral-700 text-white rounded text-sm font-bold", children: "Cancel" }),
            /* @__PURE__ */ (0, import_jsx_runtime20.jsx)(
              "button",
              {
                onClick: () => document.getElementById("subuserForm").submit(),
                className: "px-4 py-2 bg-primary-600 hover:bg-primary-500 text-white rounded text-sm font-bold shadow-sm",
                children: editingMembership ? "Update Subuser" : "Save Subuser"
              }
            )
          ] })
        ] })
      ] }) })
    ] });
  }
  if (root8) {
    root8.render(
      /* @__PURE__ */ (0, import_jsx_runtime20.jsx)(ThemeContext_default, { pageData: data8, children: /* @__PURE__ */ (0, import_jsx_runtime20.jsx)(ServerUsersPage, { pageData: data8 }) })
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === "function") {
      window.__CPANEL_REACT_BOOTED__();
    }
  }

  // views/react/server-schedules.jsx
  var import_react21 = __toESM(require_react());
  var import_client9 = __toESM(require_client());
  var import_jsx_runtime21 = __toESM(require_jsx_runtime());
  var data9 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry9 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "server-schedules";
  var root9 = standaloneEntry9 ? (0, import_client9.createRoot)(document.getElementById("reactRoot")) : null;
  function ServerSchedulesPage({ pageData = data9 }) {
    const server = pageData.server || {};
    const schedules = Array.isArray(pageData.schedules) ? pageData.schedules : [];
    const canManageSchedules = Boolean(pageData.canManageSchedules);
    const timezone = pageData.settings?.timezone || "system default";
    const [isTutorialOpen, setIsTutorialOpen] = (0, import_react21.useState)(false);
    return /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)(ReactAppShell, { pageData, subtitle: "Schedules", children: [
      /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)(PageContentBlock, { title: "Schedules", description: "Automate server actions with cron-based tasks.", children: [
        pageData.success && /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("div", { className: "bg-green-600/20 border-l-4 border-green-600 text-green-100 p-4 rounded-r-lg mb-6 shadow-sm", children: pageData.success }),
        pageData.error && /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("div", { className: "bg-red-600/20 border-l-4 border-red-600 text-red-100 p-4 rounded-r-lg mb-6 shadow-sm", children: pageData.error }),
        /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("div", { className: "flex justify-end mb-4", children: /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)(
          "button",
          {
            onClick: () => setIsTutorialOpen(true),
            className: "bg-neutral-800 hover:bg-neutral-700 text-neutral-300 px-3 py-1.5 rounded text-sm font-bold transition-colors border border-neutral-700",
            children: [
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("i", { className: "bi bi-question-circle me-1" }),
              " Tutorial"
            ]
          }
        ) }),
        canManageSchedules && /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("div", { className: "bg-neutral-900 border border-neutral-700 rounded-lg p-5 mb-8 shadow-sm", children: [
          /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("h2", { className: "text-lg font-bold text-neutral-100 mb-4", children: "Create Schedule" }),
          /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("form", { method: "POST", action: `/server/${server.containerId}/schedules`, className: "flex flex-col gap-4", "data-turbo": "false", children: [
            /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("div", { className: "grid grid-cols-1 md:grid-cols-12 gap-4 items-end", children: [
              /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("div", { className: "md:col-span-3", children: [
                /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("label", { className: "block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-1.5", children: "Name" }),
                /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("input", { type: "text", name: "name", required: true, className: "w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500" })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("div", { className: "md:col-span-2", children: [
                /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("label", { className: "block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-1.5", children: "Action" }),
                /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("select", { name: "action", className: "w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("option", { value: "command", children: "Command" }),
                  /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("option", { value: "power", children: "Power" })
                ] })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("div", { className: "md:col-span-2", children: [
                /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("label", { className: "block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-1.5", children: "Cron" }),
                /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("input", { type: "text", name: "cron", defaultValue: "* * * * *", className: "w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500 font-mono" })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("div", { className: "md:col-span-3", children: [
                /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("label", { className: "block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-1.5", children: "Payload" }),
                /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("input", { type: "text", name: "payload", placeholder: "say hello / restart", className: "w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500 font-mono" })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("div", { className: "md:col-span-2", children: /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("button", { type: "submit", className: "w-full bg-primary-600 hover:bg-primary-500 text-white text-sm font-bold px-4 py-2 rounded transition-colors shadow-sm", children: "Save" }) })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("div", { className: "flex flex-wrap gap-6 mt-2", children: [
              /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("label", { className: "flex items-center gap-2 cursor-pointer", children: [
                /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("input", { type: "checkbox", name: "enabled", value: "1", defaultChecked: true, className: "bg-neutral-900 border-neutral-600 text-primary-500 focus:ring-0 rounded" }),
                /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("span", { className: "text-sm text-neutral-300 font-semibold", children: "Enabled" })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("label", { className: "flex items-center gap-2 cursor-pointer", children: [
                /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("input", { type: "checkbox", name: "onlyWhenOnline", value: "1", className: "bg-neutral-900 border-neutral-600 text-primary-500 focus:ring-0 rounded" }),
                /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("span", { className: "text-sm text-neutral-300 font-semibold", children: "Run only when server is online" })
              ] })
            ] })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("div", { className: "text-xs text-neutral-500 mt-4 bg-neutral-800/50 p-3 rounded border border-neutral-700/50", children: [
            /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("strong", { children: "Note:" }),
            " Power payload accepts ",
            /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("code", { className: "text-primary-400 mx-1", children: "start|stop|restart|kill" }),
            ". Command payload accepts any raw console text command."
          ] })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("div", { className: "bg-neutral-900 border border-neutral-700 rounded-lg overflow-hidden shadow-sm", children: [
          /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("div", { className: "bg-neutral-800/50 px-5 py-4 border-b border-neutral-700", children: /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("h2", { className: "text-base font-bold text-neutral-100", children: "Configured Schedules" }) }),
          /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("div", { className: "overflow-x-auto", children: /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("table", { className: "w-full text-left border-collapse", children: [
            /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("thead", { children: /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("tr", { className: "bg-neutral-800 border-b border-neutral-700", children: [
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("th", { className: "px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest", children: "Name" }),
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("th", { className: "px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest", children: "Action" }),
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("th", { className: "px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest", children: "Cron" }),
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("th", { className: "px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest", children: "Payload" }),
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("th", { className: "px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest", children: "Status" }),
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("th", { className: "px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest", children: "Last Run" }),
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("th", { className: "px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest text-right", children: "Actions" })
            ] }) }),
            /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("tbody", { children: schedules.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("tr", { children: /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("td", { colSpan: "7", className: "text-center py-8 text-neutral-500 text-sm", children: "No schedules configured." }) }) : schedules.map((entry) => /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("tr", { className: "border-b border-neutral-700/50 hover:bg-neutral-800/30 transition-colors", children: [
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("td", { className: "px-5 py-4 text-sm font-bold text-white", children: entry.name }),
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("td", { className: "px-5 py-4", children: /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("span", { className: "px-2 py-1 bg-primary-600/20 text-primary-400 border border-primary-600/30 rounded text-xs font-bold", children: entry.action }) }),
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("td", { className: "px-5 py-4", children: /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("code", { className: "text-xs bg-neutral-900 border border-neutral-700 px-2 py-1 rounded text-neutral-300 font-mono", children: entry.cron || "-" }) }),
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("td", { className: "px-5 py-4", children: /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("code", { className: "text-xs bg-neutral-900 border border-neutral-700 px-2 py-1 rounded text-neutral-300 font-mono break-all max-w-[200px] inline-block", children: entry.payload || "-" }) }),
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("td", { className: "px-5 py-4", children: /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("div", { className: "flex gap-2", children: [
                /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("span", { className: `px-2 py-1 rounded text-xs font-bold ${entry.enabled === false ? "bg-neutral-800 text-neutral-400" : "bg-green-600/20 text-green-400 border border-green-600/30"}`, children: entry.enabled === false ? "Disabled" : "Enabled" }),
                entry.onlyWhenOnline && /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("span", { className: "px-2 py-1 rounded text-xs font-bold bg-yellow-500/20 text-yellow-500 border border-yellow-500/30", children: "Online Only" })
              ] }) }),
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("td", { className: "px-5 py-4 text-xs text-neutral-400", children: entry.lastRunAt ? new Date(entry.lastRunAt).toLocaleString() : "Never" }),
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("td", { className: "px-5 py-4 text-right", children: canManageSchedules ? /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("div", { className: "flex justify-end gap-2", children: [
                /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("form", { method: "POST", action: `/server/${server.containerId}/schedules/${entry.id}/run`, "data-turbo": "false", children: /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("button", { type: "submit", className: "text-green-500 hover:text-green-400 bg-neutral-900 border border-neutral-700 hover:bg-neutral-800 p-1.5 rounded transition", children: /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("i", { className: "bi bi-play-fill text-sm" }) }) }),
                /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("form", { method: "POST", action: `/server/${server.containerId}/schedules/${entry.id}/delete`, "data-turbo": "false", onSubmit: (e) => {
                  if (!window.confirm("Delete this schedule?")) e.preventDefault();
                }, children: /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("button", { type: "submit", className: "text-red-500 hover:text-red-400 bg-neutral-900 border border-neutral-700 hover:bg-neutral-800 p-1.5 rounded transition", children: /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("i", { className: "bi bi-trash text-sm" }) }) })
              ] }) : /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("span", { className: "text-neutral-500", children: "-" }) })
            ] }, entry.id)) })
          ] }) })
        ] })
      ] }),
      isTutorialOpen && /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("div", { className: "fixed inset-0 z-50 flex items-center justify-center p-4 bg-neutral-900/80 backdrop-blur-sm", children: /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("div", { className: "bg-neutral-900 border border-neutral-700 rounded-xl shadow-2xl w-full max-w-2xl overflow-hidden", children: [
        /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("div", { className: "flex justify-between items-center p-5 border-b border-neutral-700", children: [
          /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("h3", { className: "text-lg font-bold text-white", children: "Schedules Tutorial" }),
          /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("button", { onClick: () => setIsTutorialOpen(false), className: "text-neutral-400 hover:text-white transition", children: /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("i", { className: "bi bi-x-lg" }) })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("div", { className: "p-6 overflow-y-auto max-h-[70vh]", children: [
          /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("p", { className: "text-neutral-400 mb-6 leading-relaxed", children: [
            "Use schedules to execute commands automatically. Everything is processed according to the panel's timezone (",
            /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("code", { className: "bg-neutral-800 px-1 rounded text-primary-400", children: timezone }),
            ")."
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("h4", { className: "text-white font-bold mb-3 flex items-center gap-2", children: [
            /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("span", { className: "bg-primary-600/20 text-primary-400 w-6 h-6 flex items-center justify-center rounded-full text-xs", children: "1" }),
            "Core Fields"
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("ul", { className: "text-neutral-400 mb-6 space-y-2 ml-2 border-l-2 border-neutral-800 pl-4", children: [
            /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("li", { children: [
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("strong", { children: "Name:" }),
              " Name of the task (e.g. ",
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("code", { className: "bg-neutral-800 px-1 rounded", children: "Auto Save" }),
              ")."
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("li", { children: [
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("strong", { children: "Action:" }),
              " ",
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("code", { className: "bg-neutral-800 px-1 rounded", children: "command" }),
              " or ",
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("code", { className: "bg-neutral-800 px-1 rounded", children: "power" }),
              "."
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("li", { children: [
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("strong", { children: "Cron:" }),
              " Format is ",
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("code", { className: "bg-neutral-800 px-1 rounded", children: "minute hour day month weekday" }),
              "."
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("li", { children: [
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("strong", { children: "Payload:" }),
              " The console command for `command` tasks, or ",
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("code", { className: "bg-neutral-800 px-1 rounded", children: "start|stop|restart|kill" }),
              " for power."
            ] })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("h4", { className: "text-white font-bold mb-3 flex items-center gap-2", children: [
            /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("span", { className: "bg-primary-600/20 text-primary-400 w-6 h-6 flex items-center justify-center rounded-full text-xs", children: "2" }),
            "Quick Examples"
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-lg p-4 mb-4", children: [
            /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("div", { className: "text-sm font-bold text-white mb-2 pb-2 border-b border-neutral-700/50", children: "Autosave every 5 minutes" }),
            /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("pre", { className: "text-sm text-primary-300 font-mono", children: "Name: Auto Save Action: command Cron: */5 * * * * Payload: save-all" })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-lg p-4 mb-6", children: [
            /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("div", { className: "text-sm font-bold text-white mb-2 pb-2 border-b border-neutral-700/50", children: "Daily Restart at 04:00" }),
            /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("pre", { className: "text-sm text-primary-300 font-mono", children: "Name: Daily Restart Action: power Cron: 0 4 * * * Payload: restart" })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("h4", { className: "text-white font-bold mb-3 flex items-center gap-2", children: [
            /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("span", { className: "bg-primary-600/20 text-primary-400 w-6 h-6 flex items-center justify-center rounded-full text-xs", children: "3" }),
            "Recommendations"
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("ul", { className: "text-neutral-400 mb-2 space-y-2 ml-2 border-l-2 border-neutral-800 pl-4", children: [
            /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("li", { children: [
              "Check ",
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("em", { children: "Run only when server is online" }),
              " for in-game commands that require the runtime to be active."
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime21.jsxs)("li", { children: [
              "For critical tasks, click ",
              /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("strong", { children: "Run" }),
              " immediately after creation to test the payload directly."
            ] })
          ] })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("div", { className: "p-4 border-t border-neutral-700 bg-neutral-800/50 flex justify-end", children: /* @__PURE__ */ (0, import_jsx_runtime21.jsx)("button", { onClick: () => setIsTutorialOpen(false), className: "px-5 py-2 bg-neutral-700 hover:bg-neutral-600 text-white rounded text-sm font-bold transition", children: "Got It" }) })
      ] }) })
    ] });
  }
  if (root9) {
    root9.render(
      /* @__PURE__ */ (0, import_jsx_runtime21.jsx)(ThemeContext_default, { pageData: data9, children: /* @__PURE__ */ (0, import_jsx_runtime21.jsx)(ServerSchedulesPage, { pageData: data9 }) })
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === "function") {
      window.__CPANEL_REACT_BOOTED__();
    }
  }

  // views/react/server-startup.jsx
  var import_react22 = __toESM(require_react());
  var import_client10 = __toESM(require_client());
  var import_jsx_runtime22 = __toESM(require_jsx_runtime());
  var data10 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry10 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "server-startup";
  var root10 = standaloneEntry10 ? (0, import_client10.createRoot)(document.getElementById("reactRoot")) : null;
  function ServerStartupPage({ pageData = data10 }) {
    const server = pageData.server || {};
    const image = pageData.image || {};
    const resolvedStartup = pageData.resolvedStartup || "";
    const startupWriteLocked = Boolean(pageData.startupWriteLocked);
    const presets = pageData.startupPresets || [];
    const dockerChoices = pageData.dockerChoices || [];
    const variableDefinitions = pageData.variableDefinitions || [];
    const resolvedVariables = pageData.resolvedVariables || {};
    const [selectedPresetId, setSelectedPresetId] = (0, import_react22.useState)(pageData.selectedStartupPresetId || "custom");
    const [dockerTag, setDockerTag] = (0, import_react22.useState)(pageData.selectedDockerImage || "");
    const [dynamicVars, setDynamicVars] = (0, import_react22.useState)(resolvedVariables);
    const handleVarChange = (key, val) => {
      setDynamicVars((prev) => ({ ...prev, [key]: val }));
    };
    (0, import_react22.useEffect)(() => {
      if (dynamicVars.VPS_PRESET && dynamicVars.VPS_PRESET.includes("|")) {
        const [distro, release] = dynamicVars.VPS_PRESET.split("|", 2);
        if (distro && release) {
          if (dynamicVars.VPS_DISTRO !== distro || dynamicVars.VPS_RELEASE !== release) {
            setDynamicVars((prev) => ({
              ...prev,
              VPS_DISTRO: distro,
              VPS_RELEASE: release
            }));
          }
        }
      }
    }, [dynamicVars.VPS_PRESET]);
    const handleReinstall = (e) => {
      e.preventDefault();
      if (startupWriteLocked) return;
      if (window.confirm("Reinstall Server?\n\nThis will rebuild the container and may overwrite runtime changes. Are you completely sure you want to reinstall?")) {
        const form = document.getElementById("startupForm");
        if (form) {
          const input = document.createElement("input");
          input.type = "hidden";
          input.name = "action";
          input.value = "reinstall";
          form.appendChild(input);
          form.submit();
        }
      }
    };
    const imageNameLower = String(image.name || "").toLowerCase();
    const mcVersionValue = dynamicVars["MINECRAFT_VERSION"] ? String(dynamicVars["MINECRAFT_VERSION"]).trim() : "";
    const showPaperWarning = imageNameLower.includes("paper") && mcVersionValue === "1.8.9";
    return /* @__PURE__ */ (0, import_jsx_runtime22.jsx)(ReactAppShell, { pageData, subtitle: "Startup", children: /* @__PURE__ */ (0, import_jsx_runtime22.jsxs)(PageContentBlock, { title: "Startup configuration", description: "Manage Docker image, environment variables, and startup command templates.", children: [
      pageData.success && /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("div", { className: "bg-green-600/20 border-l-4 border-green-600 text-green-100 p-4 rounded-r-lg mb-6 shadow-sm", children: pageData.success }),
      pageData.error && /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("div", { className: "bg-red-600/20 border-l-4 border-red-600 text-red-100 p-4 rounded-r-lg mb-6 shadow-sm", children: pageData.error }),
      startupWriteLocked && /* @__PURE__ */ (0, import_jsx_runtime22.jsxs)("div", { className: "bg-red-900/20 border border-red-900/50 text-red-200 p-4 rounded-lg mb-6 shadow-sm", children: [
        /* @__PURE__ */ (0, import_jsx_runtime22.jsxs)("div", { className: "font-bold mb-1", children: [
          /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("i", { className: "bi bi-lock-fill me-2" }),
          "Startup Locked"
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("p", { className: "text-sm opacity-90", children: "Edits are locked for this server. Only admins can change runtime variables, startup commands, or reinstall right now." })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("form", { id: "startupForm", method: "POST", action: `/server/${server.containerId}/startup`, "data-turbo": "false", children: /* @__PURE__ */ (0, import_jsx_runtime22.jsxs)("fieldset", { disabled: startupWriteLocked, className: "space-y-6", children: [
        /* @__PURE__ */ (0, import_jsx_runtime22.jsxs)("div", { className: "bg-neutral-900 border border-neutral-700 rounded-lg shadow-sm overflow-hidden", children: [
          /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("div", { className: "bg-neutral-800/50 px-5 py-4 border-b border-neutral-700", children: /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("h6", { className: "m-0 font-bold text-neutral-100", children: "Startup Command" }) }),
          /* @__PURE__ */ (0, import_jsx_runtime22.jsxs)("div", { className: "p-5", children: [
            /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("label", { className: "block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-2", children: "Startup Template" }),
            /* @__PURE__ */ (0, import_jsx_runtime22.jsx)(
              "textarea",
              {
                name: "startupTemplate",
                className: "w-full bg-neutral-800/80 border border-neutral-700 rounded px-4 py-3 text-sm text-neutral-200 focus:outline-none focus:border-primary-500 font-mono mb-2",
                rows: "3",
                placeholder: "Leave blank to use image default...",
                defaultValue: server.startup || image.startup
              }
            ),
            /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("div", { className: "text-xs text-neutral-500 mb-5", children: "Optional override. Clear the field to use the image default template." }),
            /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("label", { className: "block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-2", children: "Resolved Startup" }),
            /* @__PURE__ */ (0, import_jsx_runtime22.jsx)(
              "textarea",
              {
                className: "w-full bg-neutral-900 border border-neutral-800 rounded px-4 py-3 text-sm text-neutral-500 font-mono opacity-80 cursor-not-allowed",
                readOnly: true,
                value: resolvedStartup
              }
            ),
            /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("div", { className: "text-xs text-neutral-600 mt-2", children: "Resolved command is computed from the template + current variables." })
          ] })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime22.jsxs)("div", { className: "bg-neutral-900 border border-neutral-700 rounded-lg shadow-sm overflow-hidden", children: [
          /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("div", { className: "bg-neutral-800/50 px-5 py-4 border-b border-neutral-700", children: /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("h6", { className: "m-0 font-bold text-neutral-100", children: "Docker Image" }) }),
          /* @__PURE__ */ (0, import_jsx_runtime22.jsxs)("div", { className: "p-5", children: [
            /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("label", { className: "block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-2", children: "Startup Preset" }),
            /* @__PURE__ */ (0, import_jsx_runtime22.jsxs)(
              "select",
              {
                name: "startupPreset",
                className: "w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500 mb-2",
                value: selectedPresetId,
                onChange: (e) => setSelectedPresetId(e.target.value),
                children: [
                  /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("option", { value: "custom", children: "Custom (no preset)" }),
                  presets.map((p) => /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("option", { value: p.id, children: p.label }, p.id))
                ]
              }
            ),
            /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("div", { className: "text-xs text-neutral-500 mb-4", children: "Presets auto-fill common variables (Paper, Purpur, Forge, Fabric) and pass the same validation rules as manual values." }),
            selectedPresetId && selectedPresetId !== "custom" && /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("div", { className: "mb-4", children: presets.filter((p) => p.id === selectedPresetId).map((preset) => /* @__PURE__ */ (0, import_jsx_runtime22.jsxs)("div", { className: "bg-neutral-800/50 border border-neutral-700/50 rounded-lg p-4", children: [
              /* @__PURE__ */ (0, import_jsx_runtime22.jsxs)("div", { className: "text-xs font-bold text-primary-400 uppercase tracking-wider mb-1", children: [
                preset.label,
                " Preview"
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("div", { className: "text-sm text-neutral-400 mb-3", children: preset.description }),
              /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("pre", { className: "text-xs text-neutral-300 font-mono bg-neutral-900 p-3 rounded overflow-x-auto border border-neutral-800", children: JSON.stringify(preset.variables, null, 2) })
            ] }, preset.id)) }),
            /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("label", { className: "block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-2", children: "Docker Tag" }),
            /* @__PURE__ */ (0, import_jsx_runtime22.jsx)(
              "select",
              {
                name: "dockerImage",
                className: "w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500",
                value: dockerTag,
                onChange: (e) => setDockerTag(e.target.value),
                children: dockerChoices.length > 0 ? dockerChoices.map((c) => /* @__PURE__ */ (0, import_jsx_runtime22.jsxs)("option", { value: c.tag, children: [
                  c.label,
                  " - ",
                  c.tag
                ] }, c.tag)) : /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("option", { value: dockerTag, children: dockerTag })
              }
            ),
            /* @__PURE__ */ (0, import_jsx_runtime22.jsxs)("div", { className: "text-xs text-neutral-500 mt-2", children: [
              "Changing image and startup command are applied after ",
              /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("strong", { children: "Save and Restart" }),
              " or reinstall."
            ] })
          ] })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime22.jsxs)("div", { className: "bg-neutral-900 border border-neutral-700 rounded-lg shadow-sm overflow-hidden", children: [
          /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("div", { className: "bg-neutral-800/50 px-5 py-4 border-b border-neutral-700", children: /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("h6", { className: "m-0 font-bold text-neutral-100", children: "Environment Variables" }) }),
          /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("div", { className: "p-5", children: /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-6", children: variableDefinitions.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("div", { className: "col-span-1 md:col-span-2 text-sm text-neutral-500", children: "No configurable startup variables for this image." }) : variableDefinitions.map((variable) => {
            const key = variable.env_variable;
            const isViewable = variable.user_viewable == 1 || variable.user_viewable === true;
            const isEditable = variable.user_editable == 1 || variable.user_editable === true;
            if (!isViewable) return null;
            const label = typeof variable.name === "string" && variable.name.trim() ? variable.name.trim() : key;
            const currentValue = dynamicVars[key] ?? variable.default_value ?? "";
            const selectOptions = Array.isArray(variable.options) ? variable.options : Array.isArray(variable.select_options) ? variable.select_options : [];
            const isSelectField = String(variable.field_type || "").toLowerCase() === "select" && selectOptions.length > 0;
            return /* @__PURE__ */ (0, import_jsx_runtime22.jsxs)("div", { className: "flex flex-col", children: [
              /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("label", { className: "block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-1.5", children: label }),
              isSelectField ? /* @__PURE__ */ (0, import_jsx_runtime22.jsx)(
                "select",
                {
                  name: `variables[${key}]`,
                  className: `w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500 ${!isEditable ? "opacity-70" : ""}`,
                  disabled: !isEditable,
                  value: String(currentValue),
                  onChange: (e) => handleVarChange(key, e.target.value),
                  children: selectOptions.map((opt) => {
                    const optVal = typeof opt === "object" && opt !== null ? opt.value ?? "" : opt;
                    const optLabel = typeof opt === "object" && opt !== null ? opt.label ?? opt.value ?? "" : opt;
                    return /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("option", { value: String(optVal), children: String(optLabel) }, optVal);
                  })
                }
              ) : /* @__PURE__ */ (0, import_jsx_runtime22.jsx)(
                "input",
                {
                  type: "text",
                  name: `variables[${key}]`,
                  className: `w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500 ${!isEditable ? "opacity-70 bg-neutral-800/50" : ""}`,
                  readOnly: !isEditable,
                  value: String(currentValue),
                  onChange: (e) => handleVarChange(key, e.target.value)
                }
              ),
              (variable.description || variable.rules) && /* @__PURE__ */ (0, import_jsx_runtime22.jsxs)("div", { className: "text-xs text-neutral-500 mt-2", children: [
                variable.description,
                variable.rules && /* @__PURE__ */ (0, import_jsx_runtime22.jsxs)("span", { className: "block mt-1 font-mono text-neutral-600 bg-neutral-800 rounded px-1.5 py-0.5 inline-block w-max", children: [
                  "Rules: ",
                  variable.rules
                ] })
              ] })
            ] }, key);
          }) }) })
        ] }),
        showPaperWarning && /* @__PURE__ */ (0, import_jsx_runtime22.jsxs)("div", { className: "bg-red-900/20 border border-red-900/50 text-red-200 p-4 rounded-lg shadow-sm", children: [
          /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("i", { className: "bi bi-exclamation-triangle-fill me-2 text-red-500" }),
          "Paper does not provide build ",
          /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("strong", { children: "1.8.9" }),
          ". The install script falls back to latest, which usually needs Java 17+. Use ",
          /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("strong", { children: "1.8.8" }),
          " or switch Docker image to Java 17+."
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime22.jsxs)("div", { className: "bg-blue-500/10 border border-blue-500/20 p-4 rounded-lg text-sm text-blue-300", children: [
          /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("strong", { children: "Note:" }),
          " Save updates the database settings only. Use ",
          /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("strong", { children: "Save and Restart" }),
          " to redeploy the runtime container with the new startup/image settings. Reinstall is optional and only needed if the container is broken."
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime22.jsxs)("div", { className: "flex flex-wrap gap-4 mt-8 bg-neutral-900 border border-neutral-700 p-4 rounded-lg", children: [
          /* @__PURE__ */ (0, import_jsx_runtime22.jsxs)("button", { type: "submit", name: "action", value: "save", className: "bg-primary-600 hover:bg-primary-500 text-white font-bold px-6 py-2.5 rounded transition shadow-sm ml-auto order-1 md:order-3", children: [
            /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("i", { className: "bi bi-save me-2" }),
            " Save Changes"
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime22.jsxs)("button", { type: "submit", name: "action", value: "apply", className: "bg-yellow-500 hover:bg-yellow-400 text-neutral-900 font-bold px-6 py-2.5 rounded transition shadow-sm order-2 md:order-2", children: [
            /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("i", { className: "bi bi-arrow-repeat me-2" }),
            " Save and Restart"
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime22.jsxs)("button", { type: "button", onClick: handleReinstall, className: "bg-transparent border border-red-500/50 text-red-500 hover:bg-red-500/10 font-bold px-6 py-2.5 rounded transition mr-auto order-3 md:order-1", children: [
            /* @__PURE__ */ (0, import_jsx_runtime22.jsx)("i", { className: "bi bi-exclamation-triangle me-2" }),
            " Reinstall"
          ] })
        ] })
      ] }) })
    ] }) });
  }
  if (root10) {
    root10.render(
      /* @__PURE__ */ (0, import_jsx_runtime22.jsx)(ThemeContext_default, { pageData: data10, children: /* @__PURE__ */ (0, import_jsx_runtime22.jsx)(ServerStartupPage, { pageData: data10 }) })
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === "function") {
      window.__CPANEL_REACT_BOOTED__();
    }
  }

  // views/react/server-file-editor.jsx
  var import_react23 = __toESM(require_react());
  var import_client11 = __toESM(require_client());
  var import_jsx_runtime23 = __toESM(require_jsx_runtime());
  var data11 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry11 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "server-file-editor";
  var root11 = standaloneEntry11 ? (0, import_client11.createRoot)(document.getElementById("reactRoot")) : null;
  var EXT_LANG_MAP = {
    js: "javascript",
    mjs: "javascript",
    cjs: "javascript",
    ts: "typescript",
    tsx: "typescript",
    jsx: "javascript",
    json: "json",
    jsonc: "json",
    yaml: "yaml",
    yml: "yaml",
    toml: "ini",
    xml: "xml",
    html: "html",
    htm: "html",
    css: "css",
    scss: "scss",
    less: "less",
    sh: "shell",
    bash: "shell",
    zsh: "shell",
    py: "python",
    rb: "ruby",
    php: "php",
    java: "java",
    kt: "kotlin",
    rs: "rust",
    go: "go",
    cs: "csharp",
    cpp: "cpp",
    c: "c",
    h: "cpp",
    sql: "sql",
    md: "markdown",
    mdx: "markdown",
    ini: "ini",
    conf: "ini",
    cfg: "ini",
    env: "ini",
    lua: "lua",
    properties: "ini",
    dockerfile: "dockerfile",
    tf: "hcl",
    groovy: "groovy",
    gradle: "groovy"
  };
  function detectLanguage(fileName = "") {
    const base = fileName.split("/").pop().toLowerCase();
    if (base === "dockerfile" || base === ".env") return base === "dockerfile" ? "dockerfile" : "ini";
    const ext = base.split(".").pop();
    return EXT_LANG_MAP[ext] || "plaintext";
  }
  var monacoLoadPromise = null;
  function loadMonaco() {
    if (monacoLoadPromise) return monacoLoadPromise;
    monacoLoadPromise = new Promise((resolve) => {
      if (window.monaco) {
        resolve(window.monaco);
        return;
      }
      const script = document.createElement("script");
      script.src = "https://cdn.jsdelivr.net/npm/monaco-editor@0.46.0/min/vs/loader.js";
      script.onload = () => {
        window.require.config({
          paths: { vs: "https://cdn.jsdelivr.net/npm/monaco-editor@0.46.0/min/vs" }
        });
        window.require(["vs/editor/editor.main"], (monaco) => {
          window.monaco = monaco;
          resolve(monaco);
        });
      };
      document.head.appendChild(script);
    });
    return monacoLoadPromise;
  }
  function FileTreeItem({ item, currentPath, onFileSwitch, serverId, depth = 0 }) {
    const [isExpanded, setIsExpanded] = (0, import_react23.useState)(false);
    const [children, setChildren] = (0, import_react23.useState)([]);
    const [loading, setLoading] = (0, import_react23.useState)(false);
    const fullPath = (item.directory === "/" ? "" : item.directory) + "/" + item.name;
    const isActive = fullPath === currentPath;
    const handleClick = async () => {
      if (!item.isDirectory) {
        onFileSwitch(fullPath);
        return;
      }
      const next = !isExpanded;
      setIsExpanded(next);
      if (next && children.length === 0) {
        setLoading(true);
        try {
          const res = await fetch(`/api/client/servers/${serverId}/files/list?path=${encodeURIComponent(fullPath)}`, {
            headers: { Accept: "application/json" },
            credentials: "same-origin"
          });
          const payload = await res.json();
          if (payload.files) {
            setChildren(payload.files.sort((a, b) => {
              if (a.isDirectory && !b.isDirectory) return -1;
              if (!a.isDirectory && b.isDirectory) return 1;
              return a.name.localeCompare(b.name);
            }));
          }
        } catch (e) {
        } finally {
          setLoading(false);
        }
      }
    };
    return /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)("div", { children: [
      /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)(
        "div",
        {
          onClick: handleClick,
          style: { paddingLeft: `${depth * 14 + 10}px` },
          className: `flex items-center gap-2 py-[5px] pr-2 cursor-pointer rounded transition-colors select-none text-[12px] ${isActive ? "bg-primary-900/30 text-primary-300 font-semibold" : "hover:bg-neutral-800/50 text-neutral-400 hover:text-neutral-200"}`,
          children: [
            item.isDirectory ? /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("i", { className: `bi ${isExpanded ? "bi-chevron-down text-[9px] text-neutral-500" : "bi-chevron-right text-[9px] text-neutral-500"} w-3 shrink-0` }) : /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("span", { className: "w-3 shrink-0" }),
            /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("i", { className: `bi ${item.isDirectory ? isExpanded ? "bi-folder2-open text-amber-400/80" : "bi-folder-fill text-amber-500/70" : "bi-file-earmark-text text-neutral-500"} shrink-0` }),
            /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("span", { className: "truncate min-w-0 flex-1", children: item.name }),
            loading && /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("div", { className: "w-2 h-2 border border-t-primary-500 border-neutral-700 rounded-full animate-spin shrink-0" })
          ]
        }
      ),
      item.isDirectory && isExpanded && /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)("div", { children: [
        children.map((child) => /* @__PURE__ */ (0, import_jsx_runtime23.jsx)(
          FileTreeItem,
          {
            item: { ...child, directory: fullPath },
            currentPath,
            onFileSwitch,
            serverId,
            depth: depth + 1
          },
          `${fullPath}/${child.name}`
        )),
        children.length === 0 && !loading && /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("div", { style: { paddingLeft: `${(depth + 1) * 14 + 23}px` }, className: "text-[10px] text-neutral-600 italic py-1", children: "empty" })
      ] })
    ] });
  }
  function ServerFileEditorPage({ pageData = data11 }) {
    const server = pageData.server || {};
    const urlParams = new URLSearchParams(window.location.search);
    const filePath = urlParams.get("path") || pageData.filePath || "/";
    const fileName = filePath.split("/").pop() || "file";
    const parentPath = filePath.split("/").slice(0, -1).join("/") || "/";
    const language = detectLanguage(fileName);
    const [content, setContent] = (0, import_react23.useState)("");
    const [loading, setLoading] = (0, import_react23.useState)(true);
    const [saving, setSaving] = (0, import_react23.useState)(false);
    const [status, setStatus] = (0, import_react23.useState)({ type: "idle", message: "" });
    const [isUnsaved, setIsUnsaved] = (0, import_react23.useState)(false);
    const [editorMode, setEditorMode] = (0, import_react23.useState)("monaco");
    const [sidebarOpen, setSidebarOpen] = (0, import_react23.useState)(true);
    const [wordWrap, setWordWrap] = (0, import_react23.useState)(false);
    const [rootFiles, setRootFiles] = (0, import_react23.useState)([]);
    const [rootLoading, setRootLoading] = (0, import_react23.useState)(false);
    const [monacoReady, setMonacoReady] = (0, import_react23.useState)(false);
    const [cursorInfo, setCursorInfo] = (0, import_react23.useState)({ line: 1, col: 1 });
    const editorContainerRef = (0, import_react23.useRef)(null);
    const monacoEditorRef = (0, import_react23.useRef)(null);
    const monacoRef = (0, import_react23.useRef)(null);
    const contentRef = (0, import_react23.useRef)(content);
    contentRef.current = content;
    (0, import_react23.useEffect)(() => {
      let cancelled = false;
      setLoading(true);
      setStatus({ type: "idle", message: "" });
      fetch(`/api/client/servers/${server.containerId}/files/content?path=${encodeURIComponent(filePath)}`, {
        headers: { Accept: "application/json" },
        credentials: "same-origin"
      }).then((r) => r.json()).then((payload) => {
        if (cancelled) return;
        if (payload.error) throw new Error(payload.error);
        setContent(payload.content || "");
        setLoading(false);
        setIsUnsaved(false);
      }).catch((err) => {
        if (cancelled) return;
        setStatus({ type: "error", message: err.message || "Failed to load file." });
        setLoading(false);
      });
      setRootLoading(true);
      fetch(`/api/client/servers/${server.containerId}/files/list?path=/`, {
        headers: { Accept: "application/json" },
        credentials: "same-origin"
      }).then((r) => r.json()).then((payload) => {
        if (cancelled) return;
        if (payload.files) {
          setRootFiles(payload.files.sort((a, b) => {
            if (a.isDirectory && !b.isDirectory) return -1;
            if (!a.isDirectory && b.isDirectory) return 1;
            return a.name.localeCompare(b.name);
          }));
        }
        setRootLoading(false);
      }).catch(() => {
        if (!cancelled) setRootLoading(false);
      });
      return () => {
        cancelled = true;
      };
    }, [server.containerId, filePath]);
    (0, import_react23.useEffect)(() => {
      if (editorMode !== "monaco" || loading) return;
      if (!editorContainerRef.current) return;
      let destroyed = false;
      loadMonaco().then((monaco) => {
        if (destroyed || !editorContainerRef.current) return;
        monacoRef.current = monaco;
        if (monacoEditorRef.current) {
          monacoEditorRef.current.setValue(contentRef.current);
          monacoEditorRef.current.updateOptions({ wordWrap: wordWrap ? "on" : "off", readOnly: Boolean(pageData.editWriteLocked) });
          return;
        }
        const editor = monaco.editor.create(editorContainerRef.current, {
          value: contentRef.current,
          language,
          theme: "vs-dark",
          fontSize: 14,
          fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
          fontLigatures: true,
          lineNumbers: "on",
          minimap: { enabled: true },
          scrollBeyondLastLine: false,
          wordWrap: wordWrap ? "on" : "off",
          tabSize: 4,
          insertSpaces: true,
          automaticLayout: true,
          padding: { top: 16 },
          readOnly: Boolean(pageData.editWriteLocked),
          renderLineHighlight: "all",
          cursorBlinking: "smooth",
          smoothScrolling: true,
          bracketPairColorization: { enabled: true }
        });
        editor.onDidChangeModelContent(() => {
          if (!destroyed) {
            setContent(editor.getValue());
            setIsUnsaved(true);
          }
        });
        editor.onDidChangeCursorPosition((e) => {
          if (!destroyed) {
            setCursorInfo({ line: e.position.lineNumber, col: e.position.column });
          }
        });
        editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, () => {
          handleSaveRef.current();
        });
        monacoEditorRef.current = editor;
        setMonacoReady(true);
      });
      return () => {
        destroyed = true;
      };
    }, [editorMode, loading]);
    (0, import_react23.useEffect)(() => {
      if (monacoEditorRef.current) {
        monacoEditorRef.current.updateOptions({ wordWrap: wordWrap ? "on" : "off" });
      }
    }, [wordWrap]);
    const handleSave = (0, import_react23.useCallback)(async () => {
      if (saving || loading || pageData.editWriteLocked) return;
      const valueToSave = monacoEditorRef.current ? monacoEditorRef.current.getValue() : contentRef.current;
      setSaving(true);
      setStatus({ type: "idle", message: "" });
      try {
        const response = await fetch(`/api/client/servers/${server.containerId}/files/write`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            path: filePath,
            content: valueToSave
          }),
          credentials: "same-origin"
        });
        const payload = await response.json();
        if (!response.ok || payload.error) throw new Error(payload.error || "Failed to save");
        setStatus({ type: "success", message: "Saved successfully." });
        setIsUnsaved(false);
        setTimeout(() => setStatus({ type: "idle", message: "" }), 3e3);
      } catch (err) {
        setStatus({ type: "error", message: err.message || "Error saving file." });
      } finally {
        setSaving(false);
      }
    }, [saving, loading, pageData.editWriteLocked, server.containerId, filePath]);
    const handleSaveRef = (0, import_react23.useRef)(handleSave);
    handleSaveRef.current = handleSave;
    const handleFileSwitch = (newPath) => {
      if (newPath === filePath) return;
      if (isUnsaved && !window.confirm("You have unsaved changes. Switch files anyway?")) return;
      window.location.href = `/server/${server.containerId}/files/edit?path=${encodeURIComponent(newPath)}`;
    };
    const switchMode = (mode) => {
      if (mode === editorMode) return;
      if (monacoEditorRef.current && editorMode === "monaco") {
        setContent(monacoEditorRef.current.getValue());
        monacoEditorRef.current.dispose();
        monacoEditorRef.current = null;
        setMonacoReady(false);
      }
      setEditorMode(mode);
    };
    (0, import_react23.useEffect)(() => {
      const handler = (e) => {
        if (isUnsaved) {
          e.preventDefault();
          e.returnValue = "";
        }
      };
      window.addEventListener("beforeunload", handler);
      return () => window.removeEventListener("beforeunload", handler);
    }, [isUnsaved]);
    (0, import_react23.useEffect)(() => {
      const handler = (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === "s") {
          e.preventDefault();
          handleSaveRef.current();
        }
      };
      window.addEventListener("keydown", handler);
      return () => window.removeEventListener("keydown", handler);
    }, []);
    const lineCount = content.split("\n").length;
    const charCount = content.length;
    return /* @__PURE__ */ (0, import_jsx_runtime23.jsx)(ReactAppShell, { pageData, subtitle: `Editing ${fileName}`, children: /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)(
      "div",
      {
        className: "flex flex-col bg-[#0d0f12] rounded-2xl border border-neutral-800 shadow-2xl overflow-hidden",
        style: { height: "calc(100vh - 140px)", minHeight: "520px" },
        children: [
          /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)("div", { className: "bg-neutral-900/90 backdrop-blur-md px-4 py-2.5 border-b border-neutral-800 flex items-center justify-between shrink-0 gap-4 flex-wrap", children: [
            /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)("div", { className: "flex items-center gap-3 min-w-0", children: [
              /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)(
                "a",
                {
                  href: `/server/${server.containerId}/files?path=${encodeURIComponent(parentPath)}`,
                  className: "flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest text-neutral-500 hover:text-white transition-colors shrink-0",
                  children: [
                    /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("i", { className: "bi bi-arrow-left" }),
                    " Files"
                  ]
                }
              ),
              /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("div", { className: "w-px h-4 bg-neutral-800 shrink-0" }),
              /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)("div", { className: "flex items-center gap-2 min-w-0", children: [
                /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("i", { className: "bi bi-file-earmark-code text-neutral-500 shrink-0" }),
                /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("span", { className: "text-sm font-bold text-neutral-200 truncate font-mono", children: fileName }),
                /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("span", { className: "text-[10px] px-1.5 py-0.5 rounded bg-neutral-800 text-neutral-500 font-mono shrink-0", children: language })
              ] }),
              isUnsaved && /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)("span", { className: "flex items-center gap-1 text-[10px] font-black text-amber-500 uppercase tracking-widest shrink-0", children: [
                /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("span", { className: "w-1.5 h-1.5 rounded-full bg-amber-500 animate-pulse" }),
                " Unsaved"
              ] }),
              pageData.editWriteLocked && /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)("span", { className: "flex items-center gap-1 text-[10px] font-black text-red-400 uppercase tracking-widest shrink-0", children: [
                /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("i", { className: "bi bi-lock-fill" }),
                " Read Only"
              ] })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)("div", { className: "flex items-center gap-2 shrink-0 flex-wrap", children: [
              /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("div", { className: "flex items-center bg-neutral-950 border border-neutral-800 rounded-lg p-0.5 gap-0.5", children: ["monaco", "plain"].map((m) => /* @__PURE__ */ (0, import_jsx_runtime23.jsx)(
                "button",
                {
                  onClick: () => switchMode(m),
                  className: `px-3 py-1 rounded text-[10px] font-black uppercase tracking-widest transition-all ${editorMode === m ? "bg-neutral-700 text-white" : "text-neutral-500 hover:text-white"}`,
                  children: m === "monaco" ? "Monaco" : "Plain"
                },
                m
              )) }),
              /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)(
                "button",
                {
                  onClick: () => setSidebarOpen((v) => !v),
                  className: `flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest px-3 py-1.5 rounded-lg border transition-all ${sidebarOpen ? "border-primary-700/50 bg-primary-900/20 text-primary-400" : "border-neutral-800 text-neutral-500 hover:text-white hover:border-neutral-700"}`,
                  children: [
                    /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("i", { className: `bi ${sidebarOpen ? "bi-layout-sidebar-inset" : "bi-layout-sidebar"}` }),
                    " Tree"
                  ]
                }
              ),
              /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)(
                "button",
                {
                  onClick: () => setWordWrap((v) => !v),
                  className: `flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest px-3 py-1.5 rounded-lg border transition-all ${wordWrap ? "border-primary-700/50 bg-primary-900/20 text-primary-400" : "border-neutral-800 text-neutral-500 hover:text-white hover:border-neutral-700"}`,
                  children: [
                    /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("i", { className: "bi bi-text-wrap" }),
                    " Wrap"
                  ]
                }
              ),
              status.message && /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)("span", { className: `text-[10px] font-black uppercase tracking-widest px-3 py-1 rounded-full border ${status.type === "error" ? "text-red-400 border-red-900/30 bg-red-950/20" : "text-green-400 border-green-900/30 bg-green-950/20"}`, children: [
                status.type === "error" ? /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("i", { className: "bi bi-exclamation-triangle me-1" }) : /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("i", { className: "bi bi-check-circle me-1" }),
                status.message
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)(
                "button",
                {
                  onClick: handleSave,
                  disabled: saving || loading || Boolean(pageData.editWriteLocked),
                  className: `flex items-center gap-2 px-5 py-1.5 rounded-lg text-[11px] font-black uppercase tracking-widest transition-all ${saving || loading || pageData.editWriteLocked ? "bg-neutral-800 text-neutral-600 cursor-not-allowed" : "bg-primary-600 hover:bg-primary-500 text-white shadow-lg shadow-primary-900/30"}`,
                  children: [
                    saving ? /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("div", { className: "w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" }) : /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("i", { className: "bi bi-cloud-arrow-up" }),
                    saving ? "Saving\u2026" : "Save"
                  ]
                }
              )
            ] })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)("div", { className: "flex-1 flex overflow-hidden", children: [
            sidebarOpen && /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)("div", { className: "w-60 bg-[#0a0c0f] border-r border-neutral-800 flex flex-col shrink-0 overflow-hidden", children: [
              /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)("div", { className: "px-3 py-2.5 border-b border-neutral-800/50 flex items-center justify-between", children: [
                /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("span", { className: "text-[9px] font-black text-neutral-500 uppercase tracking-widest", children: "Explorer" }),
                rootLoading && /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("div", { className: "w-2.5 h-2.5 border border-t-primary-500 border-neutral-700 rounded-full animate-spin" })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)("div", { className: "flex-1 overflow-y-auto py-1.5 scrollbar-thin scrollbar-track-transparent scrollbar-thumb-neutral-800", children: [
                rootFiles.map((file) => /* @__PURE__ */ (0, import_jsx_runtime23.jsx)(
                  FileTreeItem,
                  {
                    item: { ...file, directory: "/" },
                    currentPath: filePath,
                    onFileSwitch: handleFileSwitch,
                    serverId: server.containerId
                  },
                  file.name
                )),
                rootFiles.length === 0 && !rootLoading && /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("div", { className: "p-4 text-center text-[10px] text-neutral-600 uppercase tracking-widest", children: "No files" })
              ] })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)("div", { className: "flex-1 relative overflow-hidden", children: [
              loading && /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("div", { className: "absolute inset-0 flex items-center justify-center bg-[#0d0f12] z-20", children: /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)("div", { className: "flex flex-col items-center gap-4", children: [
                /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("div", { className: "w-12 h-12 border-4 border-neutral-800 border-t-primary-500 rounded-full animate-spin" }),
                /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("span", { className: "text-[10px] font-black text-neutral-500 uppercase tracking-widest", children: "Loading Buffer\u2026" })
              ] }) }),
              editorMode === "monaco" && !loading && /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("div", { ref: editorContainerRef, className: "absolute inset-0" }),
              editorMode === "plain" && !loading && /* @__PURE__ */ (0, import_jsx_runtime23.jsx)(
                "textarea",
                {
                  value: content,
                  onChange: (e) => {
                    setContent(e.target.value);
                    setIsUnsaved(true);
                  },
                  spellCheck: false,
                  disabled: Boolean(pageData.editWriteLocked),
                  className: "absolute inset-0 w-full h-full p-6 bg-[#0d0f12] text-neutral-300 font-mono text-sm leading-relaxed resize-none focus:outline-none",
                  style: { tabSize: 4 },
                  placeholder: "File is empty..."
                }
              )
            ] })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)("div", { className: "bg-neutral-900/50 px-5 py-1.5 border-t border-neutral-800 flex justify-between items-center text-[10px] font-mono text-neutral-600 shrink-0", children: [
            /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)("div", { className: "flex items-center gap-4", children: [
              /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("span", { children: language }),
              /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)("span", { children: [
                charCount.toLocaleString(),
                " chars"
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)("span", { children: [
                lineCount.toLocaleString(),
                " lines"
              ] }),
              editorMode === "monaco" && monacoReady && /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)("span", { children: [
                "Ln ",
                cursorInfo.line,
                ", Col ",
                cursorInfo.col
              ] })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)("div", { className: "flex items-center gap-3", children: [
              /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("span", { children: "UTF-8" }),
              editorMode === "monaco" && /* @__PURE__ */ (0, import_jsx_runtime23.jsxs)("span", { className: "text-primary-600", children: [
                "Monaco ",
                isUnsaved ? "\u25CF" : "\u25CB"
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime23.jsx)("span", { children: "Ctrl+S to save" })
            ] })
          ] })
        ]
      }
    ) });
  }
  if (root11) {
    root11.render(
      /* @__PURE__ */ (0, import_jsx_runtime23.jsx)(ThemeContext_default, { pageData: data11, children: /* @__PURE__ */ (0, import_jsx_runtime23.jsx)(BrowserRouter, { children: /* @__PURE__ */ (0, import_jsx_runtime23.jsx)(ServerFileEditorPage, { pageData: data11 }) }) })
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === "function") {
      window.__CPANEL_REACT_BOOTED__();
    }
  }

  // views/react/server-minecraft-center.jsx
  var import_react24 = __toESM(require_react());
  var import_client12 = __toESM(require_client());
  var import_jsx_runtime24 = __toESM(require_jsx_runtime());
  var data12 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry12 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "server-minecraft-center";
  var root12 = standaloneEntry12 ? (0, import_client12.createRoot)(document.getElementById("reactRoot")) : null;
  function MinecraftToolCard({ title, description, icon, href, colorClass }) {
    return /* @__PURE__ */ (0, import_jsx_runtime24.jsxs)(
      "a",
      {
        href,
        className: "group relative bg-neutral-900 border border-neutral-800 rounded-3xl p-6 transition-all duration-300 hover:border-primary-500/50 hover:shadow-2xl hover:shadow-primary-900/10 hover:translate-y-[-4px]",
        children: [
          /* @__PURE__ */ (0, import_jsx_runtime24.jsx)("div", { className: `w-14 h-14 rounded-2xl ${colorClass} flex items-center justify-center text-2xl mb-6 shadow-lg transition-transform group-hover:scale-110 duration-500`, children: /* @__PURE__ */ (0, import_jsx_runtime24.jsx)("i", { className: `bi ${icon}` }) }),
          /* @__PURE__ */ (0, import_jsx_runtime24.jsxs)("div", { children: [
            /* @__PURE__ */ (0, import_jsx_runtime24.jsx)("h3", { className: "text-lg font-black text-white mb-2 uppercase tracking-tight", children: title }),
            /* @__PURE__ */ (0, import_jsx_runtime24.jsx)("p", { className: "text-sm text-neutral-500 leading-relaxed font-medium", children: description })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime24.jsx)("div", { className: "absolute top-6 right-6 opacity-0 group-hover:opacity-100 transition-opacity", children: /* @__PURE__ */ (0, import_jsx_runtime24.jsx)("i", { className: "bi bi-arrow-up-right text-primary-500" }) })
        ]
      }
    );
  }
  function ServerMinecraftCenterPage({ pageData = data12 }) {
    const server = pageData.server || {};
    const tools = [
      {
        title: "Addons",
        description: "Browse and install thousands of Mods and Plugins from Modrinth.",
        icon: "bi-box",
        href: `/server/${server.containerId}/minecraft/addons`,
        colorClass: "bg-blue-600/10 text-blue-500"
      },
      {
        title: "World Center",
        description: "Advanced world management: Swap, clone, backup, or prune dimensions.",
        icon: "bi-globe-americas",
        href: `/server/${server.containerId}/minecraft/world-center`,
        colorClass: "bg-emerald-600/10 text-emerald-500"
      },
      {
        title: "Minecraft Control",
        description: "Manage server.properties, MOTD, whitelist, and essential rules.",
        icon: "bi-controller",
        href: `/server/${server.containerId}/minecraft/configs`,
        colorClass: "bg-amber-600/10 text-amber-500"
      },
      {
        title: "Admin & Players",
        description: "Inspect players, manage bans, chat, and server security permissions.",
        icon: "bi-shield-check",
        href: `/server/${server.containerId}/minecraft/admin`,
        colorClass: "bg-rose-600/10 text-rose-500"
      },
      {
        title: "Proxy Network",
        description: "Configuration for BungeeCord and Velocity proxy environments.",
        icon: "bi-diagram-3",
        href: `/server/${server.containerId}/minecraft/proxy`,
        colorClass: "bg-purple-600/10 text-purple-500"
      },
      {
        title: "Advanced Metrics",
        description: "TPS, MSPT, and real-time performance analytics for your Minecraft instance.",
        icon: "bi-bar-chart",
        href: `/server/${server.containerId}/minecraft/metrics`,
        colorClass: "bg-sky-600/10 text-sky-500"
      }
    ];
    return /* @__PURE__ */ (0, import_jsx_runtime24.jsx)(ReactAppShell, { pageData, subtitle: "Minecraft Center", children: /* @__PURE__ */ (0, import_jsx_runtime24.jsxs)(
      PageContentBlock,
      {
        title: "Minecraft Center",
        description: `Specialized tools and management for ${server.name}.`,
        eyebrow: "Game Management",
        children: [
          /* @__PURE__ */ (0, import_jsx_runtime24.jsx)("div", { className: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6", children: tools.map((tool, idx) => /* @__PURE__ */ (0, import_jsx_runtime24.jsx)(MinecraftToolCard, { ...tool }, idx)) }),
          /* @__PURE__ */ (0, import_jsx_runtime24.jsxs)("div", { className: "mt-12 bg-neutral-900 border border-neutral-800 rounded-3xl p-8 flex flex-col md:flex-row items-center justify-between gap-6", children: [
            /* @__PURE__ */ (0, import_jsx_runtime24.jsxs)("div", { className: "flex items-center gap-6", children: [
              /* @__PURE__ */ (0, import_jsx_runtime24.jsx)("div", { className: "w-16 h-16 rounded-2xl bg-primary-600/10 flex items-center justify-center text-3xl text-primary-500", children: /* @__PURE__ */ (0, import_jsx_runtime24.jsx)("i", { className: "bi bi-info-circle" }) }),
              /* @__PURE__ */ (0, import_jsx_runtime24.jsxs)("div", { children: [
                /* @__PURE__ */ (0, import_jsx_runtime24.jsx)("h4", { className: "text-xl font-black text-white mb-1 uppercase", children: "Version Installer" }),
                /* @__PURE__ */ (0, import_jsx_runtime24.jsx)("p", { className: "text-sm text-neutral-500", children: "Looking to switch Minecraft versions? Use the automated installer to deploy new builds." })
              ] })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime24.jsx)(
              "a",
              {
                href: `/server/${server.containerId}/minecraft/installer`,
                className: "px-8 py-3 bg-neutral-100 hover:bg-white text-neutral-950 font-black uppercase tracking-widest rounded-xl transition-all shadow-xl shadow-white/5 active:scale-95 text-sm",
                children: "Open Installer"
              }
            )
          ] })
        ]
      }
    ) });
  }
  if (root12) {
    root12.render(
      /* @__PURE__ */ (0, import_jsx_runtime24.jsx)(ThemeContext_default, { pageData: data12, children: /* @__PURE__ */ (0, import_jsx_runtime24.jsx)(BrowserRouter, { children: /* @__PURE__ */ (0, import_jsx_runtime24.jsx)(ServerMinecraftCenterPage, { pageData: data12 }) }) })
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === "function") {
      window.__CPANEL_REACT_BOOTED__();
    }
  }

  // views/react/server-minecraft-world-center.jsx
  var import_react25 = __toESM(require_react());
  var import_client13 = __toESM(require_client());
  var import_jsx_runtime25 = __toESM(require_jsx_runtime());
  var data13 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry13 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "server-minecraft-world-center";
  var root13 = standaloneEntry13 ? (0, import_client13.createRoot)(document.getElementById("reactRoot")) : null;
  function formatBytes3(bytes) {
    if (!bytes) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
  }
  function WorldEntryRow({ world, isActive, serverId }) {
    return /* @__PURE__ */ (0, import_jsx_runtime25.jsxs)("div", { className: `grid grid-cols-1 md:grid-cols-12 gap-4 items-center p-5 border-b border-neutral-800 last:border-0 transition-colors ${isActive ? "bg-primary-600/5" : "hover:bg-neutral-800/30"}`, children: [
      /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("div", { className: "md:col-span-1 flex justify-center", children: /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("i", { className: `text-2xl ${world.isZip ? "bi bi-file-earmark-zip text-amber-500" : "bi bi-folder-fill text-primary-500"}` }) }),
      /* @__PURE__ */ (0, import_jsx_runtime25.jsxs)("div", { className: "md:col-span-5 flex flex-col min-w-0", children: [
        /* @__PURE__ */ (0, import_jsx_runtime25.jsxs)("div", { className: "flex items-center gap-2", children: [
          /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("span", { className: "font-bold text-neutral-100 truncate", children: world.name }),
          isActive && /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("span", { className: "bg-primary-600 text-[9px] text-white px-2 py-0.5 rounded-full font-black uppercase tracking-widest shadow-lg shadow-primary-900/20", children: "Active" })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime25.jsxs)("div", { className: "text-[10px] text-neutral-500 uppercase font-black tracking-widest mt-1", children: [
          world.isZip ? "Archive" : "Directory",
          " \xB7 ",
          formatBytes3(world.size)
        ] })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime25.jsxs)("div", { className: "md:col-span-2 flex items-center gap-2 overflow-x-auto no-scrollbar", children: [
        world.hasNether && /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("span", { className: "text-[10px] bg-red-900/20 text-red-500 border border-red-900/30 px-2 py-0.5 rounded uppercase font-bold", children: "Nether" }),
        world.hasEnd && /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("span", { className: "text-[10px] bg-purple-900/20 text-purple-500 border border-purple-900/30 px-2 py-0.5 rounded uppercase font-bold", children: "End" }),
        !world.hasNether && !world.hasEnd && !world.isZip && /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("span", { className: "text-[10px] text-neutral-600 uppercase font-bold", children: "Overworld Only" })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime25.jsxs)("div", { className: "md:col-span-4 flex justify-end items-center gap-2", children: [
        !isActive && !world.isZip && /* @__PURE__ */ (0, import_jsx_runtime25.jsxs)("form", { action: `/server/${serverId}/minecraft/world-center/swap`, method: "POST", children: [
          /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("input", { type: "hidden", name: "activeWorld", value: world.name }),
          /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("button", { type: "submit", className: "px-4 py-2 bg-neutral-800 hover:bg-neutral-700 text-neutral-200 text-xs font-bold uppercase tracking-widest rounded border border-neutral-700 transition active:scale-95 shadow-lg", children: "Activate" })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("div", { className: "h-6 w-px bg-neutral-800 hidden md:block mx-1" }),
        /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("button", { className: "p-2 text-neutral-500 hover:text-white transition", title: "Delete World (Not Implemented)", children: /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("i", { className: "bi bi-trash" }) })
      ] })
    ] });
  }
  function ServerMinecraftWorldCenterPage({ pageData = data13 }) {
    const server = pageData.server || {};
    const worldData = pageData.worldData || { worlds: [], activeWorld: "" };
    const feedback = pageData.feedback || {};
    return /* @__PURE__ */ (0, import_jsx_runtime25.jsx)(ReactAppShell, { pageData, subtitle: "World Center", children: /* @__PURE__ */ (0, import_jsx_runtime25.jsxs)(
      PageContentBlock,
      {
        title: "World Center",
        description: `Switch between different regions and managing your world folders for ${server.name}.`,
        eyebrow: "Game Management",
        children: [
          feedback.error && /* @__PURE__ */ (0, import_jsx_runtime25.jsxs)("div", { className: "mb-8 bg-rose-600/10 border border-rose-600/30 text-rose-400 p-4 rounded-2xl flex items-center gap-4 animate-in fade-in slide-in-from-top-4", children: [
            /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("i", { className: "bi bi-exclamation-octagon text-xl" }),
            /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("span", { className: "text-sm font-bold uppercase tracking-widest", children: feedback.error })
          ] }),
          feedback.success && /* @__PURE__ */ (0, import_jsx_runtime25.jsxs)("div", { className: "mb-8 bg-emerald-600/10 border border-emerald-600/30 text-emerald-400 p-4 rounded-2xl flex items-center gap-4 animate-in fade-in slide-in-from-top-4", children: [
            /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("i", { className: "bi bi-check2-circle text-xl" }),
            /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("span", { className: "text-sm font-bold uppercase tracking-widest", children: feedback.success })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime25.jsxs)("div", { className: "grid grid-cols-1 lg:grid-cols-4 gap-8", children: [
            /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("div", { className: "lg:col-span-3", children: /* @__PURE__ */ (0, import_jsx_runtime25.jsxs)("div", { className: "bg-neutral-900 border border-neutral-800 rounded-3xl overflow-hidden shadow-2xl", children: [
              /* @__PURE__ */ (0, import_jsx_runtime25.jsxs)("div", { className: "px-6 py-5 bg-neutral-800/50 border-b border-neutral-800 flex items-center justify-between", children: [
                /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("h3", { className: "text-sm font-black text-white uppercase tracking-widest", children: "Detected World Containers" }),
                /* @__PURE__ */ (0, import_jsx_runtime25.jsxs)("div", { className: "text-[10px] text-neutral-500 font-bold uppercase tracking-widest", children: [
                  "Total: ",
                  worldData.worlds?.length || 0
                ] })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("div", { className: "flex flex-col min-h-[400px]", children: worldData.worlds && worldData.worlds.length > 0 ? worldData.worlds.map((world, idx) => /* @__PURE__ */ (0, import_jsx_runtime25.jsx)(
                WorldEntryRow,
                {
                  world,
                  isActive: world.name === worldData.activeWorld,
                  serverId: server.containerId
                },
                idx
              )) : /* @__PURE__ */ (0, import_jsx_runtime25.jsxs)("div", { className: "flex-1 flex flex-col items-center justify-center p-12 text-center", children: [
                /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("i", { className: "bi bi-globe-americas text-6xl text-neutral-800 mb-6 pulse" }),
                /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("div", { className: "text-lg font-bold text-neutral-600 uppercase tracking-[0.2em]", children: "No worlds found" }),
                /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("p", { className: "text-sm text-neutral-700 mt-2", children: "Initialize your server to create your first world." })
              ] }) })
            ] }) }),
            /* @__PURE__ */ (0, import_jsx_runtime25.jsxs)("div", { className: "lg:col-span-1 space-y-6", children: [
              /* @__PURE__ */ (0, import_jsx_runtime25.jsxs)("div", { className: "bg-neutral-900 border border-neutral-800 rounded-3xl p-6 shadow-xl", children: [
                /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("h4", { className: "text-[10px] font-black text-primary-500 uppercase tracking-[0.3em] mb-4", children: "Storage Info" }),
                /* @__PURE__ */ (0, import_jsx_runtime25.jsxs)("div", { className: "space-y-4", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime25.jsxs)("div", { className: "flex justify-between items-center text-sm", children: [
                    /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("span", { className: "text-neutral-500", children: "Active World" }),
                    /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("span", { className: "font-bold text-white font-mono", children: worldData.activeWorld || "N/A" })
                  ] }),
                  /* @__PURE__ */ (0, import_jsx_runtime25.jsxs)("div", { className: "flex justify-between items-center text-sm", children: [
                    /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("span", { className: "text-neutral-500", children: "Location" }),
                    /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("span", { className: "text-neutral-300", children: "Root Directory" })
                  ] }),
                  /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("div", { className: "pt-4 border-t border-neutral-800", children: /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("p", { className: "text-[10px] text-neutral-500 leading-relaxed italic", children: "Changing the active world will update your server.properties automatically. A restart is required for changes to take effect." }) })
                ] })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime25.jsxs)("div", { className: "bg-primary-600/5 border border-primary-600/20 rounded-3xl p-6 shadow-inner", children: [
                /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("h4", { className: "text-[10px] font-black text-primary-400 uppercase tracking-[0.3em] mb-4 text-center", children: "World Swap Alert" }),
                /* @__PURE__ */ (0, import_jsx_runtime25.jsx)("p", { className: "text-[11px] text-neutral-400 text-center leading-relaxed", children: "Always stop your server before cloning or downloading massive world folders to prevent session lock corruption." })
              ] })
            ] })
          ] })
        ]
      }
    ) });
  }
  if (root13) {
    root13.render(
      /* @__PURE__ */ (0, import_jsx_runtime25.jsx)(ThemeContext_default, { pageData: data13, children: /* @__PURE__ */ (0, import_jsx_runtime25.jsx)(BrowserRouter, { children: /* @__PURE__ */ (0, import_jsx_runtime25.jsx)(ServerMinecraftWorldCenterPage, { pageData: data13 }) }) })
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === "function") {
      window.__CPANEL_REACT_BOOTED__();
    }
  }

  // views/react/server-minecraft-addons.jsx
  var import_react26 = __toESM(require_react());
  var import_client14 = __toESM(require_client());
  var import_jsx_runtime26 = __toESM(require_jsx_runtime());
  var data14 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry14 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "server-minecraft-addons";
  var root14 = standaloneEntry14 ? (0, import_client14.createRoot)(document.getElementById("reactRoot")) : null;
  function AddonCard({ project, onInstall }) {
    return /* @__PURE__ */ (0, import_jsx_runtime26.jsxs)("div", { className: "bg-neutral-900 border border-neutral-800 rounded-3xl overflow-hidden group hover:border-primary-500/50 transition-all duration-300 flex flex-col hover:shadow-2xl hover:shadow-primary-900/10 hover:translate-y-[-2px]", children: [
      /* @__PURE__ */ (0, import_jsx_runtime26.jsxs)("div", { className: "relative aspect-video overflow-hidden bg-neutral-950", children: [
        /* @__PURE__ */ (0, import_jsx_runtime26.jsx)(
          "img",
          {
            src: project.gallery && project.gallery[0] ? project.gallery[0].url : project.icon_url || "https://cdn.modrinth.com/assets/images/default_project_icon.svg",
            alt: project.title,
            className: "w-full h-full object-cover opacity-60 group-hover:opacity-100 transition-opacity duration-500"
          }
        ),
        /* @__PURE__ */ (0, import_jsx_runtime26.jsx)("div", { className: "absolute top-4 right-4 bg-neutral-900/80 backdrop-blur-md px-3 py-1 rounded-full text-[10px] font-black text-primary-400 uppercase tracking-widest border border-primary-900/30", children: project.project_type })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime26.jsxs)("div", { className: "p-6 flex-1 flex flex-col", children: [
        /* @__PURE__ */ (0, import_jsx_runtime26.jsx)("h3", { className: "text-lg font-black text-white mb-2 line-clamp-1", children: project.title }),
        /* @__PURE__ */ (0, import_jsx_runtime26.jsx)("p", { className: "text-xs text-neutral-500 leading-relaxed line-clamp-3 mb-6 flex-1", children: project.description }),
        /* @__PURE__ */ (0, import_jsx_runtime26.jsxs)("div", { className: "flex items-center justify-between mt-auto", children: [
          /* @__PURE__ */ (0, import_jsx_runtime26.jsxs)("div", { className: "flex items-center gap-2", children: [
            /* @__PURE__ */ (0, import_jsx_runtime26.jsx)("i", { className: "bi bi-download text-neutral-600" }),
            /* @__PURE__ */ (0, import_jsx_runtime26.jsxs)("span", { className: "text-[10px] font-bold text-neutral-500 uppercase tracking-widest", children: [
              Math.round(project.downloads / 1e3),
              "K DLs"
            ] })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime26.jsx)(
            "button",
            {
              onClick: () => onInstall(project),
              className: "px-4 py-2 bg-neutral-800 hover:bg-neutral-700 text-white text-[10px] font-black uppercase tracking-widest rounded-xl border border-neutral-700 transition",
              children: "View Details"
            }
          )
        ] })
      ] })
    ] });
  }
  function ServerMinecraftAddonsPage({ pageData = data14 }) {
    const server = pageData.server || {};
    const defaults = pageData.minecraftDefaults || {};
    const [search, setSearch] = (0, import_react26.useState)("");
    const [kind, setKind] = (0, import_react26.useState)(defaults.kind || "mod");
    const [results, setResults] = (0, import_react26.useState)([]);
    const [loading, setLoading] = (0, import_react26.useState)(false);
    const [error, setError] = (0, import_react26.useState)("");
    (0, import_react26.useEffect)(() => {
      let cancelled = false;
      const timer = setTimeout(() => {
        setLoading(true);
        setError("");
        fetch(`/server/${server.containerId}/minecraft/addons/search?q=${encodeURIComponent(search)}&kind=${kind}&limit=12`).then((res) => res.json()).then((payload) => {
          if (cancelled) return;
          if (payload.success) {
            setResults(payload.projects || []);
          } else {
            throw new Error(payload.error || "Failed to search modrinth");
          }
          setLoading(false);
        }).catch((err) => {
          if (cancelled) return;
          console.error(err);
          setError(err.message || "Search failed");
          setLoading(false);
        });
      }, 500);
      return () => {
        cancelled = true;
        clearTimeout(timer);
      };
    }, [search, kind, server.containerId]);
    return /* @__PURE__ */ (0, import_jsx_runtime26.jsx)(ReactAppShell, { pageData, subtitle: "Addons", children: /* @__PURE__ */ (0, import_jsx_runtime26.jsxs)(
      PageContentBlock,
      {
        title: "Addons Hub",
        description: `Browse and install thousands of mods and plugins for your ${server.name} instance.`,
        eyebrow: "Resource Catalog",
        children: [
          /* @__PURE__ */ (0, import_jsx_runtime26.jsxs)("div", { className: "flex flex-col md:flex-row gap-6 mb-12", children: [
            /* @__PURE__ */ (0, import_jsx_runtime26.jsxs)("div", { className: "flex-1 relative", children: [
              /* @__PURE__ */ (0, import_jsx_runtime26.jsx)("i", { className: "bi bi-search absolute left-5 top-1/2 -translate-y-1/2 text-neutral-600 text-lg" }),
              /* @__PURE__ */ (0, import_jsx_runtime26.jsx)(
                "input",
                {
                  type: "text",
                  value: search,
                  onChange: (e) => setSearch(e.target.value),
                  placeholder: "Search Modrinth (e.g. WorldEdit, Essentials, Sodium)...",
                  className: "w-full bg-neutral-900 border border-neutral-800 rounded-3xl py-5 pl-14 pr-6 text-white text-sm focus:outline-none focus:border-primary-500/50 shadow-2xl shadow-black/20"
                }
              )
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime26.jsxs)("div", { className: "flex bg-neutral-900 border border-neutral-800 rounded-3xl p-1 gap-1", children: [
              /* @__PURE__ */ (0, import_jsx_runtime26.jsx)(
                "button",
                {
                  onClick: () => setKind("mod"),
                  className: `px-8 py-3 rounded-2xl text-[10px] font-black uppercase tracking-widest transition-all ${kind === "mod" ? "bg-primary-600 text-white shadow-lg shadow-primary-900/20" : "text-neutral-500 hover:text-neutral-300"}`,
                  children: "Mods"
                }
              ),
              /* @__PURE__ */ (0, import_jsx_runtime26.jsx)(
                "button",
                {
                  onClick: () => setKind("plugin"),
                  className: `px-8 py-3 rounded-2xl text-[10px] font-black uppercase tracking-widest transition-all ${kind === "plugin" ? "bg-primary-600 text-white shadow-lg shadow-primary-900/20" : "text-neutral-500 hover:text-neutral-300"}`,
                  children: "Plugins"
                }
              )
            ] })
          ] }),
          error && /* @__PURE__ */ (0, import_jsx_runtime26.jsxs)("div", { className: "bg-rose-600/10 border border-rose-600/30 text-rose-400 p-6 rounded-3xl mb-8 flex items-center gap-4", children: [
            /* @__PURE__ */ (0, import_jsx_runtime26.jsx)("i", { className: "bi bi-exclamation-triangle text-2xl" }),
            /* @__PURE__ */ (0, import_jsx_runtime26.jsx)("span", { className: "font-bold uppercase tracking-widest text-sm", children: error })
          ] }),
          loading ? /* @__PURE__ */ (0, import_jsx_runtime26.jsxs)("div", { className: "flex flex-col items-center justify-center py-24 gap-6", children: [
            /* @__PURE__ */ (0, import_jsx_runtime26.jsx)("div", { className: "w-16 h-16 border-4 border-neutral-800 border-t-primary-500 rounded-full animate-spin" }),
            /* @__PURE__ */ (0, import_jsx_runtime26.jsx)("span", { className: "text-xs font-black text-neutral-500 uppercase tracking-[0.3em] pulse", children: "Indexing Modrinth..." })
          ] }) : /* @__PURE__ */ (0, import_jsx_runtime26.jsx)("div", { className: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6", children: results.length > 0 ? results.map((project) => /* @__PURE__ */ (0, import_jsx_runtime26.jsx)(AddonCard, { project, onInstall: (p) => window.location.href = `/server/${server.containerId}/minecraft/addons/project/${p.project_id}` }, project.project_id)) : /* @__PURE__ */ (0, import_jsx_runtime26.jsxs)("div", { className: "col-span-full py-24 text-center", children: [
            /* @__PURE__ */ (0, import_jsx_runtime26.jsx)("i", { className: "bi bi-search text-6xl text-neutral-800 mb-6 block" }),
            /* @__PURE__ */ (0, import_jsx_runtime26.jsx)("div", { className: "text-lg font-bold text-neutral-600 uppercase tracking-widest", children: "No addons found" }),
            /* @__PURE__ */ (0, import_jsx_runtime26.jsx)("p", { className: "text-sm text-neutral-700 mt-2", children: "Try adjusting your search terms or filters." })
          ] }) })
        ]
      }
    ) });
  }
  if (root14) {
    root14.render(
      /* @__PURE__ */ (0, import_jsx_runtime26.jsx)(ThemeContext_default, { pageData: data14, children: /* @__PURE__ */ (0, import_jsx_runtime26.jsx)(BrowserRouter, { children: /* @__PURE__ */ (0, import_jsx_runtime26.jsx)(ServerMinecraftAddonsPage, { pageData: data14 }) }) })
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === "function") {
      window.__CPANEL_REACT_BOOTED__();
    }
  }

  // views/react/server-minecraft-installer.jsx
  var import_react27 = __toESM(require_react());
  var import_client15 = __toESM(require_client());
  var import_jsx_runtime27 = __toESM(require_jsx_runtime());
  var data15 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry15 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "server-minecraft-installer";
  var root15 = standaloneEntry15 ? (0, import_client15.createRoot)(document.getElementById("reactRoot")) : null;
  var PLATFORMS = [
    { id: "vanilla", name: "Vanilla", icon: "bi-box-seam", description: "The official Minecraft server jar from Mojang.", color: "bg-green-600/10 text-green-500" },
    { id: "fabric", name: "Fabric", icon: "bi-cpu", description: "Lightweight, modular modding toolset for modern versions.", color: "bg-orange-600/10 text-orange-500" },
    { id: "forge", name: "Forge", icon: "bi-hammer", description: "The original modding API for extensive content mods.", color: "bg-blue-600/10 text-blue-500" },
    { id: "quilt", name: "Quilt", icon: "bi-patch-check", description: "Community-driven mod loader built for modularity.", color: "bg-purple-600/10 text-purple-500" },
    { id: "waterfall", name: "Waterfall", icon: "bi-water", description: "High-performance BungeeCord fork for proxy networks.", color: "bg-sky-600/10 text-sky-500" },
    { id: "bungeecord", name: "BungeeCord", icon: "bi-intersect", description: "The standard proxy for connecting multiple servers.", color: "bg-yellow-600/10 text-yellow-500" }
  ];
  function ServerMinecraftInstallerPage({ pageData = data15 }) {
    const server = pageData.server || {};
    const catalog = pageData.installerCatalog || {};
    const [selectedPlatform, setSelectedPlatform] = import_react27.default.useState(null);
    const [selectedVersion, setSelectedVersion] = import_react27.default.useState("");
    const [selectedBuild, setSelectedBuild] = import_react27.default.useState("");
    const [installing, setInstalling] = import_react27.default.useState(false);
    const [error, setError] = import_react27.default.useState(pageData.error || null);
    const [success, setSuccess] = import_react27.default.useState(pageData.success || null);
    const availableVersions = import_react27.default.useMemo(() => {
      if (!selectedPlatform) return [];
      const platformKey = selectedPlatform.toLowerCase();
      if (platformKey === "waterfall" && catalog.waterfall) {
        return Object.keys(catalog.waterfall).sort((a, b) => b.localeCompare(a, void 0, { numeric: true }));
      }
      return [];
    }, [selectedPlatform, catalog]);
    const handlePlatformSelect = (platform) => {
      setSelectedPlatform(platform.id);
      setSelectedVersion("");
      setSelectedBuild("");
      setError(null);
    };
    const handleInstall = () => {
      if (!selectedPlatform || !selectedVersion) return;
      const form = document.createElement("form");
      form.method = "POST";
      form.action = `/server/${server.containerId}/minecraft/installer`;
      const platInput = document.createElement("input");
      platInput.name = "platform";
      platInput.value = selectedPlatform;
      form.appendChild(platInput);
      const verInput = document.createElement("input");
      verInput.name = "version";
      verInput.value = selectedVersion;
      form.appendChild(verInput);
      if (selectedBuild) {
        const buildInput = document.createElement("input");
        buildInput.name = "build";
        buildInput.value = selectedBuild;
        form.appendChild(buildInput);
      }
      const csrfInput = document.createElement("input");
      csrfInput.type = "hidden";
      csrfInput.name = "_csrf";
      csrfInput.value = document.querySelector('meta[name="csrf-token"]')?.getAttribute("content") || "";
      form.appendChild(csrfInput);
      document.body.appendChild(form);
      setInstalling(true);
      form.submit();
    };
    return /* @__PURE__ */ (0, import_jsx_runtime27.jsx)(ReactAppShell, { pageData, subtitle: "Version Installer", children: /* @__PURE__ */ (0, import_jsx_runtime27.jsxs)(
      PageContentBlock,
      {
        title: "Version Installer",
        description: "Easily switch between different Minecraft platforms and versions.",
        eyebrow: "Provisioning",
        children: [
          error && /* @__PURE__ */ (0, import_jsx_runtime27.jsxs)("div", { className: "mb-8 bg-rose-600/10 border border-rose-600/20 text-rose-500 p-6 rounded-3xl flex items-center gap-4 animate-in slide-in-from-top-4", children: [
            /* @__PURE__ */ (0, import_jsx_runtime27.jsx)("i", { className: "bi bi-exclamation-octagon text-2xl" }),
            /* @__PURE__ */ (0, import_jsx_runtime27.jsx)("span", { className: "font-bold uppercase tracking-widest text-sm", children: error })
          ] }),
          success && /* @__PURE__ */ (0, import_jsx_runtime27.jsxs)("div", { className: "mb-8 bg-emerald-600/10 border border-emerald-600/20 text-emerald-500 p-6 rounded-3xl flex items-center gap-4 animate-in slide-in-from-top-4", children: [
            /* @__PURE__ */ (0, import_jsx_runtime27.jsx)("i", { className: "bi bi-check-circle text-2xl" }),
            /* @__PURE__ */ (0, import_jsx_runtime27.jsx)("span", { className: "font-bold uppercase tracking-widest text-sm", children: success })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime27.jsxs)("div", { className: "mb-10", children: [
            /* @__PURE__ */ (0, import_jsx_runtime27.jsxs)("h3", { className: "text-sm font-black text-white uppercase tracking-[0.2em] mb-6 flex items-center gap-3", children: [
              /* @__PURE__ */ (0, import_jsx_runtime27.jsx)("span", { className: "w-6 h-6 rounded-lg bg-neutral-800 flex items-center justify-center text-[10px]", children: "1" }),
              "Select Platform"
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime27.jsx)("div", { className: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4", children: PLATFORMS.map((platform) => /* @__PURE__ */ (0, import_jsx_runtime27.jsxs)(
              "button",
              {
                onClick: () => handlePlatformSelect(platform),
                className: `group flex items-start gap-4 p-5 rounded-2xl border transition-all text-left ${selectedPlatform === platform.id ? "bg-primary-600/10 border-primary-500 shadow-xl shadow-primary-900/10" : "bg-neutral-800/40 border-neutral-800 hover:border-neutral-700"}`,
                children: [
                  /* @__PURE__ */ (0, import_jsx_runtime27.jsx)("div", { className: `shrink-0 w-12 h-12 rounded-xl flex items-center justify-center text-xl shadow-lg ${selectedPlatform === platform.id ? "bg-primary-600 text-white" : platform.color}`, children: /* @__PURE__ */ (0, import_jsx_runtime27.jsx)("i", { className: `bi ${platform.icon}` }) }),
                  /* @__PURE__ */ (0, import_jsx_runtime27.jsxs)("div", { children: [
                    /* @__PURE__ */ (0, import_jsx_runtime27.jsx)("h4", { className: "font-black text-white uppercase tracking-widest text-xs mb-1 group-hover:text-primary-400 transition-colors", children: platform.name }),
                    /* @__PURE__ */ (0, import_jsx_runtime27.jsx)("p", { className: "text-[10px] text-neutral-500 font-bold uppercase tracking-widest leading-relaxed", children: platform.description })
                  ] })
                ]
              },
              platform.id
            )) })
          ] }),
          selectedPlatform && /* @__PURE__ */ (0, import_jsx_runtime27.jsxs)("div", { className: "animate-in fade-in slide-in-from-top-4 duration-500", children: [
            /* @__PURE__ */ (0, import_jsx_runtime27.jsxs)("h3", { className: "text-sm font-black text-white uppercase tracking-[0.2em] mb-6 flex items-center gap-3", children: [
              /* @__PURE__ */ (0, import_jsx_runtime27.jsx)("span", { className: "w-6 h-6 rounded-lg bg-neutral-800 flex items-center justify-center text-[10px]", children: "2" }),
              "Configure Installation"
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime27.jsxs)("div", { className: "bg-neutral-800/40 border border-neutral-800 rounded-3xl p-8 max-w-2xl", children: [
              /* @__PURE__ */ (0, import_jsx_runtime27.jsxs)("div", { className: "grid grid-cols-1 sm:grid-cols-2 gap-6 mb-8", children: [
                /* @__PURE__ */ (0, import_jsx_runtime27.jsxs)("div", { children: [
                  /* @__PURE__ */ (0, import_jsx_runtime27.jsx)("label", { className: "block text-[10px] font-black text-neutral-500 uppercase tracking-[0.2em] mb-3", children: "Target Version" }),
                  /* @__PURE__ */ (0, import_jsx_runtime27.jsx)(
                    "input",
                    {
                      type: "text",
                      placeholder: "e.g. 1.20.1",
                      value: selectedVersion,
                      onChange: (e) => setSelectedVersion(e.target.value),
                      className: "w-full bg-neutral-900 border border-neutral-700 rounded-xl px-4 py-3 text-sm text-white focus:border-primary-500 transition-colors outline-none font-mono"
                    }
                  ),
                  selectedPlatform === "waterfall" && availableVersions.length > 0 && /* @__PURE__ */ (0, import_jsx_runtime27.jsx)("div", { className: "mt-2 flex flex-wrap gap-2", children: availableVersions.slice(0, 5).map((v) => /* @__PURE__ */ (0, import_jsx_runtime27.jsx)("button", { onClick: () => setSelectedVersion(v), className: "text-[9px] font-bold text-neutral-600 hover:text-white transition-colors", children: v }, v)) })
                ] }),
                ["forge", "fabric", "quilt", "waterfall"].includes(selectedPlatform) && /* @__PURE__ */ (0, import_jsx_runtime27.jsxs)("div", { children: [
                  /* @__PURE__ */ (0, import_jsx_runtime27.jsx)("label", { className: "block text-[10px] font-black text-neutral-500 uppercase tracking-[0.2em] mb-3", children: "Build / Loader" }),
                  /* @__PURE__ */ (0, import_jsx_runtime27.jsx)(
                    "input",
                    {
                      type: "text",
                      placeholder: "Leave blank for latest",
                      value: selectedBuild,
                      onChange: (e) => setSelectedBuild(e.target.value),
                      className: "w-full bg-neutral-900 border border-neutral-700 rounded-xl px-4 py-3 text-sm text-white focus:border-primary-500 transition-colors outline-none font-mono"
                    }
                  )
                ] })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime27.jsx)("div", { className: "bg-rose-600/5 border border-rose-600/20 p-5 rounded-2xl mb-8", children: /* @__PURE__ */ (0, import_jsx_runtime27.jsxs)("div", { className: "flex items-start gap-4", children: [
                /* @__PURE__ */ (0, import_jsx_runtime27.jsx)("i", { className: "bi bi-shield-exclamation text-rose-500 text-xl" }),
                /* @__PURE__ */ (0, import_jsx_runtime27.jsxs)("div", { children: [
                  /* @__PURE__ */ (0, import_jsx_runtime27.jsx)("h5", { className: "text-[10px] font-black text-rose-500 uppercase tracking-[0.2em] mb-1", children: "Destructive Action" }),
                  /* @__PURE__ */ (0, import_jsx_runtime27.jsx)("p", { className: "text-[10px] text-neutral-500 font-bold uppercase tracking-widest leading-relaxed", children: "This will stop your server and overwrite the primary executable. Current world files will be preserved." })
                ] })
              ] }) }),
              /* @__PURE__ */ (0, import_jsx_runtime27.jsx)(
                "button",
                {
                  onClick: handleInstall,
                  disabled: !selectedVersion || installing,
                  className: `w-full py-4 rounded-xl text-xs font-black uppercase tracking-[0.3em] transition-all shadow-xl active:scale-95 flex items-center justify-center gap-3 ${!selectedVersion || installing ? "bg-neutral-800 text-neutral-600 cursor-not-allowed" : "bg-primary-600 hover:bg-primary-500 text-white shadow-primary-900/20"}`,
                  children: installing ? /* @__PURE__ */ (0, import_jsx_runtime27.jsxs)(import_jsx_runtime27.Fragment, { children: [
                    /* @__PURE__ */ (0, import_jsx_runtime27.jsx)("div", { className: "w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" }),
                    "Processing..."
                  ] }) : /* @__PURE__ */ (0, import_jsx_runtime27.jsxs)(import_jsx_runtime27.Fragment, { children: [
                    /* @__PURE__ */ (0, import_jsx_runtime27.jsx)("i", { className: "bi bi-download" }),
                    "Install ",
                    PLATFORMS.find((p) => p.id === selectedPlatform)?.name,
                    " ",
                    selectedVersion
                  ] })
                }
              )
            ] })
          ] })
        ]
      }
    ) });
  }
  if (root15) {
    root15.render(
      /* @__PURE__ */ (0, import_jsx_runtime27.jsx)(ThemeContext_default, { pageData: data15, children: /* @__PURE__ */ (0, import_jsx_runtime27.jsx)(BrowserRouter, { children: /* @__PURE__ */ (0, import_jsx_runtime27.jsx)(ServerMinecraftInstallerPage, { pageData: data15 }) }) })
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === "function") {
      window.__CPANEL_REACT_BOOTED__();
    }
  }

  // views/react/server-minecraft-admin.jsx
  var import_react28 = __toESM(require_react());
  var import_client16 = __toESM(require_client());
  var import_jsx_runtime28 = __toESM(require_jsx_runtime());
  var data16 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry16 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "server-minecraft-admin";
  var root16 = standaloneEntry16 ? (0, import_client16.createRoot)(document.getElementById("reactRoot")) : null;
  function ServerMinecraftAdminPage({ pageData = data16 }) {
    const server = pageData.server || {};
    const {
      minecraftAdminPermissions = {},
      minecraftAdminRecentEvents = []
    } = pageData;
    const [searchQuery, setSearchQuery] = (0, import_react28.useState)("");
    const [selectedPlayer, setSelectedPlayer] = (0, import_react28.useState)(null);
    const players = [
      { name: "Notch", uuid: "069a79f4-44e9-4726-a5be-fca90e38aaf5", isOnline: true },
      { name: "Jeb_", uuid: "853c80ef-3c37-49fd-aa49-938b674adae6", isOnline: false }
    ];
    const filteredPlayers = players.filter((p) => p.name.toLowerCase().includes(searchQuery.toLowerCase()));
    return /* @__PURE__ */ (0, import_jsx_runtime28.jsx)(ReactAppShell, { pageData, subtitle: "Admin & Control", children: /* @__PURE__ */ (0, import_jsx_runtime28.jsx)(
      PageContentBlock,
      {
        title: "Admin & Control",
        description: "Live player directory, administrative actions, and instance metrics.",
        eyebrow: "Moderation",
        children: /* @__PURE__ */ (0, import_jsx_runtime28.jsxs)("div", { className: "grid grid-cols-1 xl:grid-cols-12 gap-8", children: [
          /* @__PURE__ */ (0, import_jsx_runtime28.jsxs)("div", { className: "xl:col-span-4 flex flex-col h-[800px] bg-neutral-900/60 backdrop-blur-xl border border-neutral-800 rounded-[2rem] shadow-2xl overflow-hidden", children: [
            /* @__PURE__ */ (0, import_jsx_runtime28.jsxs)("div", { className: "p-6 border-b border-neutral-800", children: [
              /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("h3", { className: "text-sm font-black text-white uppercase tracking-[0.2em] mb-4", children: "Player Directory" }),
              /* @__PURE__ */ (0, import_jsx_runtime28.jsxs)("div", { className: "relative", children: [
                /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("i", { className: "bi bi-search absolute left-4 top-1/2 -translate-y-1/2 text-neutral-500" }),
                /* @__PURE__ */ (0, import_jsx_runtime28.jsx)(
                  "input",
                  {
                    type: "text",
                    placeholder: "Search by username...",
                    value: searchQuery,
                    onChange: (e) => setSearchQuery(e.target.value),
                    className: "w-full bg-neutral-800 border border-neutral-700 rounded-xl py-3 pl-10 pr-4 text-sm text-neutral-200 focus:border-primary-500 outline-none transition-colors"
                  }
                )
              ] })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("div", { className: "flex-1 overflow-y-auto p-4 space-y-2", children: filteredPlayers.map((p) => /* @__PURE__ */ (0, import_jsx_runtime28.jsxs)(
              "button",
              {
                onClick: () => setSelectedPlayer(p),
                className: `w-full flex items-center gap-4 p-3 rounded-xl transition-all border text-left ${selectedPlayer?.name === p.name ? "bg-primary-600/10 border-primary-500/50" : "bg-transparent border-transparent hover:bg-neutral-800 hover:border-neutral-700"}`,
                children: [
                  /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("img", { src: `https://mc-heads.net/avatar/${p.uuid}/100.png`, alt: p.name, className: "w-10 h-10 rounded-lg shadow-sm" }),
                  /* @__PURE__ */ (0, import_jsx_runtime28.jsxs)("div", { className: "flex-1 min-w-0", children: [
                    /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("div", { className: "font-bold text-sm text-white truncate", children: p.name }),
                    /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("div", { className: "text-[10px] text-neutral-500 font-bold uppercase tracking-widest truncate", children: p.uuid })
                  ] }),
                  /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("div", { className: `w-2 h-2 rounded-full ${p.isOnline ? "bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]" : "bg-neutral-600"}` })
                ]
              },
              p.name
            )) })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("div", { className: "xl:col-span-8 flex flex-col h-[800px]", children: !selectedPlayer ? /* @__PURE__ */ (0, import_jsx_runtime28.jsxs)("div", { className: "flex-1 flex flex-col items-center justify-center border-2 border-dashed border-neutral-800 rounded-[2rem] text-center p-8", children: [
            /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("i", { className: "bi bi-person-badge text-6xl text-neutral-800 mb-6" }),
            /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("h3", { className: "text-lg font-black text-white uppercase tracking-widest mb-2", children: "Select a Player" }),
            /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("p", { className: "text-sm text-neutral-500 font-bold max-w-sm leading-relaxed", children: "Choose a player from the directory to inspect their inventory, execute commands, or manage moderation tools." })
          ] }) : /* @__PURE__ */ (0, import_jsx_runtime28.jsxs)("div", { className: "flex-1 bg-neutral-900/60 backdrop-blur-xl border border-neutral-800 rounded-[2rem] shadow-2xl p-8 overflow-y-auto", children: [
            /* @__PURE__ */ (0, import_jsx_runtime28.jsxs)("div", { className: "flex items-start gap-6 border-b border-neutral-800 pb-8 mb-8", children: [
              /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("img", { src: `https://mc-heads.net/avatar/${selectedPlayer.uuid}/200.png`, alt: selectedPlayer.name, className: "w-24 h-24 rounded-2xl shadow-xl ring-1 ring-white/10" }),
              /* @__PURE__ */ (0, import_jsx_runtime28.jsxs)("div", { className: "flex-1", children: [
                /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("h2", { className: "text-2xl font-black text-white tracking-tight mb-1", children: selectedPlayer.name }),
                /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("p", { className: "text-xs text-neutral-400 font-mono mb-4 bg-neutral-800 inline-block px-3 py-1 rounded-md", children: selectedPlayer.uuid }),
                /* @__PURE__ */ (0, import_jsx_runtime28.jsxs)("div", { className: "flex flex-wrap gap-2", children: [
                  minecraftAdminPermissions.kick && /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("button", { className: "px-5 py-2 bg-neutral-800 hover:bg-rose-600/20 hover:text-rose-400 text-neutral-300 rounded-lg text-xs font-black uppercase tracking-widest transition-all", children: "Kick" }),
                  minecraftAdminPermissions.ban && /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("button", { className: "px-5 py-2 bg-rose-600/10 text-rose-500 hover:bg-rose-600 hover:text-white rounded-lg text-xs font-black uppercase tracking-widest transition-all border border-rose-600/20", children: "Ban" }),
                  minecraftAdminPermissions.op && /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("button", { className: "px-5 py-2 bg-primary-600/10 text-primary-500 hover:bg-primary-600 hover:text-white rounded-lg text-xs font-black uppercase tracking-widest transition-all border border-primary-600/20", children: "Make Operator" })
                ] })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("div", { className: `px-4 py-1.5 rounded-full text-[10px] font-black uppercase tracking-widest border ${selectedPlayer.isOnline ? "bg-green-500/10 text-green-400 border-green-500/20" : "bg-neutral-800 text-neutral-400 border-neutral-700"}`, children: selectedPlayer.isOnline ? "Online Now" : "Offline" })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime28.jsxs)("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-6", children: [
              /* @__PURE__ */ (0, import_jsx_runtime28.jsxs)("div", { className: "bg-neutral-800/40 rounded-2xl p-6 border border-neutral-800", children: [
                /* @__PURE__ */ (0, import_jsx_runtime28.jsxs)("h4", { className: "text-xs font-black text-neutral-500 uppercase tracking-[0.2em] mb-4 flex items-center gap-2", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("i", { className: "bi bi-heart-pulse" }),
                  " Vitals"
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime28.jsxs)("div", { className: "space-y-4", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime28.jsxs)("div", { children: [
                    /* @__PURE__ */ (0, import_jsx_runtime28.jsxs)("div", { className: "flex justify-between text-xs font-bold mb-1", children: [
                      /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("span", { className: "text-rose-400", children: "Health" }),
                      /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("span", { className: "text-white", children: "20/20" })
                    ] }),
                    /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("div", { className: "h-2 rounded-full bg-neutral-900 border border-neutral-800 overflow-hidden", children: /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("div", { className: "h-full bg-rose-500 w-full" }) })
                  ] }),
                  /* @__PURE__ */ (0, import_jsx_runtime28.jsxs)("div", { children: [
                    /* @__PURE__ */ (0, import_jsx_runtime28.jsxs)("div", { className: "flex justify-between text-xs font-bold mb-1", children: [
                      /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("span", { className: "text-amber-400", children: "Food" }),
                      /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("span", { className: "text-white", children: "20/20" })
                    ] }),
                    /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("div", { className: "h-2 rounded-full bg-neutral-900 border border-neutral-800 overflow-hidden", children: /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("div", { className: "h-full bg-amber-500 w-full" }) })
                  ] }),
                  /* @__PURE__ */ (0, import_jsx_runtime28.jsxs)("div", { children: [
                    /* @__PURE__ */ (0, import_jsx_runtime28.jsxs)("div", { className: "flex justify-between text-xs font-bold mb-1", children: [
                      /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("span", { className: "text-green-400", children: "Experience Level" }),
                      /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("span", { className: "text-white", children: "12" })
                    ] }),
                    /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("div", { className: "h-2 rounded-full bg-neutral-900 border border-neutral-800 overflow-hidden", children: /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("div", { className: "h-full bg-green-500 w-[45%]" }) })
                  ] })
                ] })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime28.jsxs)("div", { className: "bg-neutral-800/40 rounded-2xl p-6 border border-neutral-800", children: [
                /* @__PURE__ */ (0, import_jsx_runtime28.jsxs)("h4", { className: "text-xs font-black text-neutral-500 uppercase tracking-[0.2em] mb-4 flex items-center gap-2", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("i", { className: "bi bi-geo-alt" }),
                  " Location"
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime28.jsxs)("div", { className: "grid grid-cols-2 gap-4", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime28.jsxs)("div", { children: [
                    /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("div", { className: "text-[10px] uppercase font-black text-neutral-500 mb-1", children: "World" }),
                    /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("div", { className: "text-sm font-bold text-white bg-neutral-900 px-3 py-2 rounded-lg border border-neutral-800", children: "world" })
                  ] }),
                  /* @__PURE__ */ (0, import_jsx_runtime28.jsxs)("div", { children: [
                    /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("div", { className: "text-[10px] uppercase font-black text-neutral-500 mb-1", children: "Coordinates" }),
                    /* @__PURE__ */ (0, import_jsx_runtime28.jsx)("div", { className: "text-sm font-bold text-white bg-neutral-900 px-3 py-2 rounded-lg border border-neutral-800 font-mono", children: "142, 64, -89" })
                  ] })
                ] })
              ] })
            ] })
          ] }) })
        ] })
      }
    ) });
  }
  if (root16) {
    root16.render(
      /* @__PURE__ */ (0, import_jsx_runtime28.jsx)(ThemeContext_default, { pageData: data16, children: /* @__PURE__ */ (0, import_jsx_runtime28.jsx)(BrowserRouter, { children: /* @__PURE__ */ (0, import_jsx_runtime28.jsx)(ServerMinecraftAdminPage, { pageData: data16 }) }) })
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === "function") {
      window.__CPANEL_REACT_BOOTED__();
    }
  }

  // views/react/server-minecraft-configs.jsx
  var import_react29 = __toESM(require_react());
  var import_client17 = __toESM(require_client());
  var import_jsx_runtime29 = __toESM(require_jsx_runtime());
  var data17 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry17 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "server-minecraft-configs";
  var root17 = standaloneEntry17 ? (0, import_client17.createRoot)(document.getElementById("reactRoot")) : null;
  function ServerMinecraftConfigsPage({ pageData = data17 }) {
    const server = pageData.server || {};
    const {
      minecraftStatusAddress = "",
      minecraftBedrockMode = false,
      minecraftProxyMode = null,
      connectorOnline = false,
      minecraftMotd = "",
      minecraftResourcePack = {},
      minecraftMotdPresets = [],
      minecraftPropertiesError = ""
    } = pageData;
    const [proxyInstalling, setProxyInstalling] = (0, import_react29.useState)(false);
    const handleSaveMotd = (e) => {
      e.preventDefault();
      const form = e.target;
      form.submit();
    };
    const handleSaveProxy = (e) => {
      e.preventDefault();
      setProxyInstalling(true);
      e.target.submit();
    };
    return /* @__PURE__ */ (0, import_jsx_runtime29.jsx)(ReactAppShell, { pageData, subtitle: "Minecraft Control", children: /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)(
      PageContentBlock,
      {
        title: "Minecraft Control",
        description: "Core server properties, MOTD presets, proxy setup, and resource packs.",
        eyebrow: "Configuration",
        children: [
          minecraftPropertiesError && /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)("div", { className: "mb-8 bg-rose-600/10 border border-rose-600/20 text-rose-500 p-6 rounded-3xl flex items-center gap-4", children: [
            /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("i", { className: "bi bi-exclamation-octagon text-2xl" }),
            /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)("div", { children: [
              /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("h4", { className: "font-bold text-sm uppercase tracking-widest", children: "Configuration Read Error" }),
              /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("p", { className: "text-xs text-rose-400 mt-1", children: minecraftPropertiesError })
            ] })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)("div", { className: "grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8", children: [
            /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)("div", { className: "bg-neutral-800/40 border border-neutral-800 rounded-[2rem] p-8 shadow-2xl", children: [
              /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)("div", { className: "flex items-center gap-4 mb-8", children: [
                /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("div", { className: "w-12 h-12 rounded-2xl bg-primary-600/10 flex items-center justify-center text-primary-500 text-xl shadow-inner", children: /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("i", { className: "bi bi-fonts" }) }),
                /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)("div", { children: [
                  /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("h3", { className: "text-sm font-black text-white uppercase tracking-[0.2em]", children: "Server MOTD" }),
                  /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("p", { className: "text-[10px] font-bold text-neutral-500 uppercase tracking-widest mt-1", children: "Message of the day" })
                ] })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)("form", { method: "POST", action: `/server/${server.containerId}/minecraft/configs/motd`, onSubmit: handleSaveMotd, children: [
                /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("input", { type: "hidden", name: "_csrf", value: document.querySelector('meta[name="csrf-token"]')?.getAttribute("content") || "" }),
                /* @__PURE__ */ (0, import_jsx_runtime29.jsx)(
                  "textarea",
                  {
                    name: "motd",
                    defaultValue: minecraftMotd,
                    rows: "3",
                    className: "w-full bg-neutral-900 border border-neutral-700/50 rounded-2xl px-5 py-4 text-sm text-white focus:border-primary-500 transition-colors outline-none font-mono resize-none mb-6 shadow-inner",
                    placeholder: "A Minecraft Server..."
                  }
                ),
                /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)("div", { className: "flex justify-between items-center", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("button", { type: "button", className: "text-[10px] font-black text-primary-500 hover:text-primary-400 uppercase tracking-[0.2em] transition-colors", children: /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("i", { className: "bi bi-palette flex items-center gap-2", children: "Presets" }) }),
                  /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)("button", { type: "submit", disabled: !connectorOnline, className: `px-8 py-3 rounded-xl text-xs font-black uppercase tracking-[0.2em] transition-all shadow-xl active:scale-95 flex items-center gap-3 ${connectorOnline ? "bg-primary-600 hover:bg-primary-500 text-white shadow-primary-900/20" : "bg-neutral-800 text-neutral-600 cursor-not-allowed"}`, children: [
                    /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("i", { className: "bi bi-save" }),
                    " Save Changes"
                  ] })
                ] })
              ] })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)("div", { className: "bg-neutral-800/40 border border-neutral-800 rounded-[2rem] p-8 shadow-2xl relative overflow-hidden", children: [
              /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("div", { className: "absolute top-0 right-0 p-8 opacity-5", children: /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("i", { className: "bi bi-diagram-3 text-9xl" }) }),
              /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)("div", { className: "relative", children: [
                /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)("div", { className: "flex items-center gap-4 mb-8", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("div", { className: "w-12 h-12 rounded-2xl bg-purple-600/10 flex items-center justify-center text-purple-500 text-xl shadow-inner", children: /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("i", { className: "bi bi-diagram-3" }) }),
                  /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)("div", { children: [
                    /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("h3", { className: "text-sm font-black text-white uppercase tracking-[0.2em]", children: "Proxy Setup" }),
                    /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("p", { className: "text-[10px] font-bold text-neutral-500 uppercase tracking-widest mt-1", children: "BungeeCord / Velocity" })
                  ] })
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)("p", { className: "text-sm text-neutral-400 font-medium mb-6 leading-relaxed", children: [
                  "Currently operating in ",
                  /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("strong", { className: minecraftProxyMode && minecraftProxyMode !== "disabled" ? "text-purple-400" : "text-primary-400", children: minecraftProxyMode || "disabled" }),
                  " mode."
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)("form", { method: "POST", action: `/server/${server.containerId}/minecraft/configs/proxy-mode`, onSubmit: handleSaveProxy, children: [
                  /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("input", { type: "hidden", name: "_csrf", value: document.querySelector('meta[name="csrf-token"]')?.getAttribute("content") || "" }),
                  /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("div", { className: "grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6", children: ["disabled", "bungeecord", "velocity"].map((mode) => /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)("label", { className: `relative flex items-center justify-center px-4 py-3 rounded-xl border cursor-pointer transition-all ${minecraftProxyMode === mode ? "bg-purple-600/10 border-purple-500 text-purple-400" : "bg-neutral-900 border-neutral-800 text-neutral-500 hover:border-neutral-700"}`, children: [
                    /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("input", { type: "radio", name: "proxyMode", value: mode, defaultChecked: minecraftProxyMode === mode, className: "sr-only" }),
                    /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("span", { className: "text-[10px] font-black uppercase tracking-widest", children: mode })
                  ] }, mode)) }),
                  /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("button", { type: "submit", disabled: proxyInstalling || !connectorOnline, className: `w-full py-4 rounded-xl text-xs font-black uppercase tracking-[0.2em] transition-all flex justify-center items-center gap-3 ${proxyInstalling || !connectorOnline ? "bg-neutral-800 text-neutral-600" : "bg-neutral-100/10 hover:bg-neutral-100/20 text-white"}`, children: proxyInstalling ? /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)(import_jsx_runtime29.Fragment, { children: [
                    /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("div", { className: "w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" }),
                    " Reconfiguring..."
                  ] }) : /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)(import_jsx_runtime29.Fragment, { children: [
                    /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("i", { className: "bi bi-arrow-repeat" }),
                    " Apply Strategy"
                  ] }) })
                ] })
              ] })
            ] })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)("div", { className: "bg-neutral-800/40 border border-neutral-800 rounded-[2rem] p-8 shadow-2xl mb-8", children: [
            /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)("div", { className: "flex items-center gap-4 mb-8", children: [
              /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("div", { className: "w-12 h-12 rounded-2xl bg-amber-600/10 flex items-center justify-center text-amber-500 text-xl shadow-inner", children: /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("i", { className: "bi bi-box-seam" }) }),
              /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)("div", { children: [
                /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("h3", { className: "text-sm font-black text-white uppercase tracking-[0.2em]", children: "Global Resource Pack" }),
                /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("p", { className: "text-[10px] font-bold text-neutral-500 uppercase tracking-widest mt-1", children: "Automatic Client Downloads" })
              ] })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)("form", { method: "POST", action: `/server/${server.containerId}/minecraft/configs/resource-pack`, className: "grid grid-cols-1 md:grid-cols-2 gap-8", children: [
              /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("input", { type: "hidden", name: "_csrf", value: document.querySelector('meta[name="csrf-token"]')?.getAttribute("content") || "" }),
              /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)("div", { children: [
                /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("label", { className: "block text-[10px] font-black text-neutral-500 uppercase tracking-[0.2em] mb-3", children: "Direct Download URL" }),
                /* @__PURE__ */ (0, import_jsx_runtime29.jsx)(
                  "input",
                  {
                    type: "url",
                    name: "url",
                    defaultValue: minecraftResourcePack.url || "",
                    placeholder: "https://example.com/pack.zip",
                    className: "w-full bg-neutral-900 border border-neutral-700/50 rounded-xl px-4 py-3 text-sm text-white focus:border-amber-500 transition-colors outline-none font-mono shadow-inner"
                  }
                )
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)("div", { children: [
                /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("label", { className: "block text-[10px] font-black text-neutral-500 uppercase tracking-[0.2em] mb-3", children: "SHA-1 Hash" }),
                /* @__PURE__ */ (0, import_jsx_runtime29.jsx)(
                  "input",
                  {
                    type: "text",
                    name: "sha1",
                    defaultValue: minecraftResourcePack.sha1 || "",
                    placeholder: "Must be valid SHA-1",
                    className: "w-full bg-neutral-900 border border-neutral-700/50 rounded-xl px-4 py-3 text-sm text-white focus:border-amber-500 transition-colors outline-none font-mono shadow-inner mb-4"
                  }
                ),
                /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)("label", { className: "flex items-center gap-3 cursor-pointer group", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("input", { type: "checkbox", name: "required", defaultChecked: minecraftResourcePack.required, className: "w-5 h-5 rounded bg-neutral-900 border border-neutral-700 text-amber-500 focus:ring-amber-500 focus:ring-offset-neutral-900 transition-colors cursor-pointer" }),
                  /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("span", { className: "text-xs font-bold text-neutral-400 group-hover:text-white uppercase tracking-wider transition-colors", children: "Enforce Pack on Join" })
                ] })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("div", { className: "md:col-span-2 flex justify-end", children: /* @__PURE__ */ (0, import_jsx_runtime29.jsxs)("button", { type: "submit", disabled: !connectorOnline, className: `px-10 py-4 rounded-xl text-xs font-black uppercase tracking-[0.2em] transition-all shadow-xl flex items-center gap-3 ${connectorOnline ? "bg-amber-600 hover:bg-amber-500 text-white shadow-amber-900/20" : "bg-neutral-800 text-neutral-600 cursor-not-allowed"}`, children: [
                /* @__PURE__ */ (0, import_jsx_runtime29.jsx)("i", { className: "bi bi-cloud-arrow-up" }),
                " Update Config"
              ] }) })
            ] })
          ] })
        ]
      }
    ) });
  }
  if (root17) {
    root17.render(
      /* @__PURE__ */ (0, import_jsx_runtime29.jsx)(ThemeContext_default, { pageData: data17, children: /* @__PURE__ */ (0, import_jsx_runtime29.jsx)(BrowserRouter, { children: /* @__PURE__ */ (0, import_jsx_runtime29.jsx)(ServerMinecraftConfigsPage, { pageData: data17 }) }) })
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === "function") {
      window.__CPANEL_REACT_BOOTED__();
    }
  }

  // views/react/server-overview.jsx
  var import_react30 = __toESM(require_react());
  var import_client18 = __toESM(require_client());
  var import_jsx_runtime30 = __toESM(require_jsx_runtime());
  var data18 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry18 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "server-overview";
  var root18 = standaloneEntry18 ? (0, import_client18.createRoot)(document.getElementById("reactRoot")) : null;
  function StatCard({ label, value, progress, subValue, colorClass }) {
    return /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "bg-neutral-900 border border-neutral-800 rounded-xl p-5 shadow-sm", children: [
      /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "flex justify-between items-center mb-4", children: [
        /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("span", { className: "text-xs font-bold text-neutral-400 uppercase tracking-widest", children: label }),
        /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("span", { className: "text-lg font-bold text-white", children: value })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("div", { className: "h-2 bg-neutral-800 rounded-full overflow-hidden mb-3", children: /* @__PURE__ */ (0, import_jsx_runtime30.jsx)(
        "div",
        {
          className: `h-full transition-all duration-500 rounded-full ${colorClass}`,
          style: { width: `${Math.min(progress, 100)}%` }
        }
      ) }),
      /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("div", { className: "text-[10px] text-neutral-500 font-medium", children: subValue })
    ] });
  }
  function ServerOverviewPage({ pageData = data18 }) {
    const server = pageData.server || {};
    const [stats, setStats] = (0, import_react30.useState)({ cpu: 0, memory: 0, disk: 0, status: server.status || "unknown" });
    const wsRef = (0, import_react30.useRef)(null);
    const memoryLimit = Number(server.memory) || 1;
    const diskLimit = Number(server.disk) || 1;
    (0, import_react30.useEffect)(() => {
      const wsToken = pageData.wsToken;
      if (!wsToken) return;
      const protocol = window.location.protocol.replace("http", "ws");
      const url = `${protocol}//${window.location.host}/ws/server/${server.containerId}?token=${encodeURIComponent(wsToken)}`;
      let reconnectTimer = null;
      let reconnectInterval = 1e3;
      const connect = () => {
        const ws = new WebSocket(url);
        wsRef.current = ws;
        ws.onopen = () => {
          reconnectInterval = 1e3;
        };
        ws.onmessage = (event) => {
          try {
            const payload = JSON.parse(event.data);
            if (payload.type === "server_stats") {
              setStats((prev) => ({
                ...prev,
                cpu: Number(payload.cpu) || 0,
                memory: Number(payload.memory) || 0,
                disk: Number(payload.disk) || 0
              }));
            } else if (payload.type === "server_status_update") {
              setStats((prev) => ({ ...prev, status: payload.status }));
            }
          } catch (e) {
          }
        };
        ws.onclose = () => {
          reconnectTimer = setTimeout(() => {
            reconnectInterval = Math.min(reconnectInterval * 1.5, 5e3);
            connect();
          }, reconnectInterval);
        };
      };
      connect();
      return () => {
        if (wsRef.current) wsRef.current.close();
        if (reconnectTimer) clearTimeout(reconnectTimer);
      };
    }, [server.containerId, pageData.wsToken]);
    const memPercent = stats.memory / memoryLimit * 100;
    const diskPercent = stats.disk / diskLimit * 100;
    const getStatusColor = (status) => {
      switch (status) {
        case "running":
          return "text-green-500 bg-green-500/10 border-green-500/20";
        case "starting":
          return "text-yellow-500 bg-yellow-500/10 border-yellow-500/20";
        case "stopping":
          return "text-red-500 bg-red-500/10 border-red-500/20";
        default:
          return "text-neutral-500 bg-neutral-800 border-neutral-700";
      }
    };
    const handleCopy = (text) => {
      navigator.clipboard.writeText(text);
    };
    return /* @__PURE__ */ (0, import_jsx_runtime30.jsx)(ReactAppShell, { pageData, subtitle: "Overview", children: /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)(PageContentBlock, { title: server.name, description: server.description || "No description provided.", children: [
      /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "grid grid-cols-1 md:grid-cols-3 gap-6 mb-8", children: [
        /* @__PURE__ */ (0, import_jsx_runtime30.jsx)(
          StatCard,
          {
            label: "Processor",
            value: `${stats.cpu.toFixed(1)}%`,
            progress: stats.cpu,
            subValue: "Live CPU Usage",
            colorClass: stats.cpu < 60 ? "bg-green-500" : stats.cpu < 85 ? "bg-yellow-500" : "bg-red-500"
          }
        ),
        /* @__PURE__ */ (0, import_jsx_runtime30.jsx)(
          StatCard,
          {
            label: "Memory",
            value: `${Math.round(stats.memory)} MB`,
            progress: memPercent,
            subValue: `Limit: ${memoryLimit} MB`,
            colorClass: memPercent < 60 ? "bg-green-500" : memPercent < 85 ? "bg-yellow-500" : "bg-red-500"
          }
        ),
        /* @__PURE__ */ (0, import_jsx_runtime30.jsx)(
          StatCard,
          {
            label: "Disk",
            value: `${Math.round(stats.disk)} MB`,
            progress: diskPercent,
            subValue: `Quota: ${diskLimit} MB`,
            colorClass: diskPercent < 60 ? "bg-green-500" : diskPercent < 85 ? "bg-yellow-500" : "bg-red-500"
          }
        )
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "grid grid-cols-1 lg:grid-cols-12 gap-8", children: [
        /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "lg:col-span-8 space-y-8", children: [
          /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "bg-neutral-900 border border-neutral-700 rounded-xl overflow-hidden shadow-sm", children: [
            /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "bg-neutral-800/50 px-5 py-4 border-b border-neutral-700 flex justify-between items-center", children: [
              /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("h3", { className: "font-bold text-white flex items-center gap-2", children: [
                /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("i", { className: "bi bi-link-45deg" }),
                " Connection Detail"
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("div", { className: `px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-widest border ${getStatusColor(stats.status)}`, children: stats.status })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "p-6", children: [
              /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-6", children: [
                /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { children: [
                  /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("label", { className: "block text-[10px] font-bold text-neutral-500 uppercase tracking-widest mb-2", children: "Primary IP / Port" }),
                  /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "flex items-center gap-2", children: [
                    /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("code", { className: "bg-neutral-800 px-3 py-2 rounded text-primary-400 font-mono text-sm flex-1", children: [
                      server.allocation?.ip || "0.0.0.0",
                      ":",
                      server.allocation?.port || "0"
                    ] }),
                    /* @__PURE__ */ (0, import_jsx_runtime30.jsx)(
                      "button",
                      {
                        onClick: () => handleCopy(`${server.allocation?.ip}:${server.allocation?.port}`),
                        className: "p-2 bg-neutral-800 hover:bg-neutral-700 rounded text-neutral-400 transition",
                        title: "Copy",
                        children: /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("i", { className: "bi bi-clipboard" })
                      }
                    )
                  ] })
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { children: [
                  /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("label", { className: "block text-[10px] font-bold text-neutral-500 uppercase tracking-widest mb-2", children: "Container Identifier" }),
                  /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("code", { className: "block bg-neutral-800 px-3 py-2 rounded text-neutral-300 font-mono text-sm", children: server.containerId })
                ] })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "mt-6 pt-6 border-t border-neutral-800", children: [
                /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("label", { className: "block text-[10px] font-bold text-neutral-500 uppercase tracking-widest mb-2", children: "Startup Command" }),
                /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("pre", { className: "w-full bg-neutral-950 border border-neutral-800 rounded p-4 text-xs font-mono text-neutral-400 overflow-x-auto", children: pageData.resolvedStartup || "No startup command defined." })
              ] })
            ] })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "bg-neutral-900 border border-neutral-700 rounded-xl overflow-hidden shadow-sm", children: [
            /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("div", { className: "bg-neutral-800/50 px-5 py-4 border-b border-neutral-700", children: /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("h3", { className: "font-bold text-white flex items-center gap-2", children: [
              /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("i", { className: "bi bi-pencil-square" }),
              " General Settings"
            ] }) }),
            /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("div", { className: "p-6", children: /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("form", { method: "POST", action: `/server/${server.containerId}/overview/meta`, className: "space-y-6", children: [
              /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-6", children: [
                /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { children: [
                  /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("label", { className: "block text-[10px] font-bold text-neutral-500 uppercase tracking-widest mb-1.5", children: "Server Name" }),
                  /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("input", { type: "text", name: "name", defaultValue: server.name, className: "w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500" })
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { children: [
                  /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("label", { className: "block text-[10px] font-bold text-neutral-500 uppercase tracking-widest mb-1.5", children: "Folder" }),
                  /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("input", { type: "text", name: "folder", defaultValue: server.folder, className: "w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500" })
                ] })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { children: [
                /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("label", { className: "block text-[10px] font-bold text-neutral-500 uppercase tracking-widest mb-1.5", children: "Description" }),
                /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("textarea", { name: "description", defaultValue: server.description, rows: "2", className: "w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500" })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { children: [
                /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("label", { className: "block text-[10px] font-bold text-neutral-500 uppercase tracking-widest mb-1.5", children: "Tags (comma separated)" }),
                /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("input", { type: "text", name: "tags", defaultValue: (server.tags || []).join(", "), className: "w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500" })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("div", { className: "flex justify-end pt-2", children: /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("button", { className: "bg-primary-600 hover:bg-primary-500 text-white font-bold py-2 px-6 rounded-lg transition shadow-md text-sm", children: "Update Information" }) })
            ] }) })
          ] })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "lg:col-span-4 space-y-6", children: [
          /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "bg-neutral-900 border border-neutral-700 rounded-xl overflow-hidden shadow-sm", children: [
            /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("div", { className: "bg-neutral-800/50 px-4 py-3 border-b border-neutral-700", children: /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("h4", { className: "text-xs font-bold text-neutral-100 uppercase tracking-wider", children: "Network Info" }) }),
            /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "p-4 space-y-4", children: [
              /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "flex justify-between items-center text-sm", children: [
                /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("span", { className: "text-neutral-500", children: "Node" }),
                /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("span", { className: "text-neutral-200 font-semibold", children: server.allocation?.connector?.name || "Local" })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "flex justify-between items-center text-sm", children: [
                /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("span", { className: "text-neutral-500", children: "Location" }),
                /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("span", { className: "text-neutral-200 font-semibold", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("i", { className: `bi bi-geo-alt-fill text-primary-500 me-2` }),
                  server.allocation?.connector?.location?.name || "Central"
                ] })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("div", { className: "flex justify-between items-center text-sm pt-4 border-t border-neutral-800", children: /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "flex items-center gap-2", children: [
                /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("span", { className: `px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-widest ${typeof pageData.healthScore === "object" ? pageData.healthScore.badgeClass || "bg-neutral-800 text-neutral-400" : pageData.healthScore >= 80 ? "bg-green-500/10 text-green-500 border-green-500/20" : pageData.healthScore >= 50 ? "bg-yellow-500/10 text-yellow-500 border-yellow-500/20" : "bg-red-500/10 text-red-500 border-red-500/20"}`, children: typeof pageData.healthScore === "object" ? pageData.healthScore.grade : pageData.healthScore >= 80 ? "Healthy" : "Warning" }),
                /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("span", { className: `font-bold ${typeof pageData.healthScore === "object" ? pageData.healthScore.score >= 80 ? "text-green-500" : pageData.healthScore.score >= 50 ? "text-yellow-500" : "text-red-500" : pageData.healthScore >= 80 ? "text-green-500" : pageData.healthScore >= 50 ? "text-yellow-500" : "text-red-500"}`, children: [
                  typeof pageData.healthScore === "object" ? pageData.healthScore.score : pageData.healthScore || 0,
                  "%"
                ] })
              ] }) }),
              pageData.serverCost && /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "flex justify-between items-center text-sm", children: [
                /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("span", { className: "text-neutral-500", children: "Monthly Est." }),
                /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("span", { className: "text-primary-400 font-bold", children: [
                  "$",
                  pageData.serverCost
                ] })
              ] })
            ] })
          ] }),
          pageData.minecraftProfileCard?.enabled && /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "bg-neutral-900 border border-neutral-700 rounded-xl overflow-hidden shadow-sm", children: [
            /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "bg-emerald-600/10 px-4 py-3 border-b border-emerald-900/20 text-emerald-400 font-bold text-xs uppercase tracking-wider flex items-center gap-2", children: [
              /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("i", { className: "bi bi-controller" }),
              " Minecraft Status"
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "p-4", children: [
              /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "flex items-center gap-4 mb-4", children: [
                /* @__PURE__ */ (0, import_jsx_runtime30.jsx)(
                  "img",
                  {
                    src: `https://mc-api.net/v3/server/favicon/${pageData.minecraftProfileCard.statusAddress}`,
                    className: "w-10 h-10 rounded shadow border border-neutral-800 bg-black",
                    onError: (e) => e.target.src = "/assets/rocky.png"
                  }
                ),
                /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "flex-1 min-w-0", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("div", { className: "text-sm font-bold text-white truncate", children: pageData.minecraftProfileCard.status?.motd || "MC Server" }),
                  /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("div", { className: "text-[10px] text-emerald-400", children: pageData.minecraftProfileCard.status?.version || "Unknown version" })
                ] })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "flex justify-between items-center text-sm", children: [
                /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("span", { className: "text-neutral-500", children: "Players Online" }),
                /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("span", { className: "bg-emerald-900/30 text-emerald-400 px-2 py-0.5 rounded text-xs font-bold", children: [
                  pageData.minecraftProfileCard.status?.playersOnline || 0,
                  " / ",
                  pageData.minecraftProfileCard.status?.playersMax || 0
                ] })
              ] })
            ] })
          ] }),
          pageData.user?.isAdmin && server.owner && /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "bg-neutral-900 border border-neutral-700 rounded-xl overflow-hidden shadow-sm mb-6", children: [
            /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("div", { className: "bg-primary-900/10 px-5 py-4 border-b border-primary-900/20", children: /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("h3", { className: "font-black text-primary-500 text-[10px] uppercase tracking-[0.2em] flex items-center gap-2", children: [
              /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("i", { className: "bi bi-person-badge" }),
              " Owner Information"
            ] }) }),
            /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "p-5 flex items-center gap-4", children: [
              /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("div", { className: "w-12 h-12 rounded-full bg-neutral-800 flex items-center justify-center text-xl font-bold text-neutral-400 border border-neutral-700", children: server.owner.username?.charAt(0).toUpperCase() || "U" }),
              /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "flex-1", children: [
                /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("div", { className: "text-sm font-bold text-white", children: server.owner.username }),
                /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "text-[10px] text-neutral-500 font-mono", children: [
                  "UID: ",
                  server.ownerId
                ] })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("a", { href: `/admin/users/view/${server.ownerId}`, className: "px-3 py-1.5 bg-neutral-800 hover:bg-neutral-700 text-neutral-300 text-[10px] font-bold uppercase tracking-widest rounded border border-neutral-700 transition", children: "View Profile" })
            ] })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "p-5 border border-dashed border-neutral-800 rounded-xl", children: [
            /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("h5", { className: "text-xs font-bold text-neutral-400 uppercase tracking-widest mb-3", children: "Quick Navigation" }),
            /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("div", { className: "grid grid-cols-2 gap-2", children: [
              /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("a", { href: `/server/${server.containerId}/files`, className: "p-3 bg-neutral-900 hover:bg-neutral-800 border border-neutral-800 rounded-lg text-center transition group", children: [
                /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("i", { className: "bi bi-folder2-open block text-lg text-neutral-500 group-hover:text-primary-400 mb-1" }),
                /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("span", { className: "text-[10px] font-bold text-neutral-400 uppercase", children: "Files" })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime30.jsxs)("a", { href: `/server/${server.containerId}/backups`, className: "p-3 bg-neutral-900 hover:bg-neutral-800 border border-neutral-800 rounded-lg text-center transition group", children: [
                /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("i", { className: "bi bi-safe block text-lg text-neutral-500 group-hover:text-primary-400 mb-1" }),
                /* @__PURE__ */ (0, import_jsx_runtime30.jsx)("span", { className: "text-[10px] font-bold text-neutral-400 uppercase", children: "Backups" })
              ] })
            ] })
          ] })
        ] })
      ] })
    ] }) });
  }
  if (root18) {
    root18.render(
      /* @__PURE__ */ (0, import_jsx_runtime30.jsx)(ThemeContext_default, { pageData: data18, children: /* @__PURE__ */ (0, import_jsx_runtime30.jsx)(ServerOverviewPage, { pageData: data18 }) })
    );
  }

  // views/react/server-activity.jsx
  var import_react31 = __toESM(require_react());
  var import_client19 = __toESM(require_client());
  var import_jsx_runtime31 = __toESM(require_jsx_runtime());
  var data19 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry19 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "server-activity";
  var root19 = standaloneEntry19 ? (0, import_client19.createRoot)(document.getElementById("reactRoot")) : null;
  function getActivityTone(action) {
    const val = String(action || "").trim();
    if (val.includes("crash") || val.includes("error") || val.includes("denied")) return "danger";
    if (val.includes("start") || val.includes("success") || val.includes("transition")) return "success";
    if (val.includes("mismatch") || val.includes("recovery")) return "warning";
    return "neutral";
  }
  function getActivitySummary(log) {
    const action = String(log?.action || "").trim();
    const metadata = log?.metadata || {};
    if (action === "server:state.transition" || action === "server:state.mismatch") {
      const prev = metadata.previousStatus || "unknown";
      const next = metadata.nextStatus || "unknown";
      const src = metadata.source || "system";
      const reason = metadata.reason ? ` \xB7 ${metadata.reason}` : "";
      return `${prev.toUpperCase()} \u2192 ${next.toUpperCase()} (via ${src})${reason}`;
    }
    if (action === "server:recovery.policy") return `${metadata.playbook || "policy"} \u2192 ${metadata.action || "unknown"}`;
    if (action === "server:recovery.auto") return `${metadata.action || "start"} (recovery after crash)`;
    if (action === "server:power.action") return `${metadata.powerAction || "unknown"} requested`;
    if (action === "server:debug.crash") {
      const exit = metadata.exitCode !== void 0 ? `exit ${metadata.exitCode}` : "no exit code";
      return metadata.oomKilled ? `${exit} \xB7 OOM KILLED` : exit;
    }
    return [log?.targetType, log?.targetId].filter(Boolean).join(" / ") || "-";
  }
  function ToneBadge({ tone, children }) {
    const colors = {
      success: "bg-green-500/10 text-green-500 border-green-500/20",
      danger: "bg-red-500/10 text-red-500 border-red-500/20",
      warning: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
      neutral: "bg-neutral-800 text-neutral-400 border-neutral-700"
    };
    return /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("span", { className: `px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${colors[tone] || colors.neutral}`, children });
  }
  function ServerActivityPage({ pageData = data19 }) {
    const server = pageData.server || {};
    const logs = pageData.logs || [];
    const changeLogs = pageData.changeLogs || [];
    const [isClearing, setIsClearing] = import_react31.default.useState(false);
    const handleClearLogs = async () => {
      if (!window.confirm("Are you sure you want to PERMANENTLY clear all activity and change logs for this server? This action cannot be undone.")) {
        return;
      }
      setIsClearing(true);
      try {
        const response = await fetch(`/server/${server.containerId}/activity/clear`, {
          method: "POST",
          headers: { "Accept": "application/json" }
        });
        const payload = await response.json();
        if (payload.success) {
          window.location.reload();
        } else {
          alert(payload.error || "Failed to clear logs.");
          setIsClearing(false);
        }
      } catch (err) {
        alert("An error occurred while clearing logs.");
        setIsClearing(false);
      }
    };
    const canClear = pageData.user?.isAdmin || (Array.isArray(pageData.permissions) ? pageData.permissions.includes("server.activity.clear") : pageData.permissions && pageData.permissions["server.activity.clear"]);
    return /* @__PURE__ */ (0, import_jsx_runtime31.jsx)(ReactAppShell, { pageData, subtitle: "Activity", children: /* @__PURE__ */ (0, import_jsx_runtime31.jsxs)(PageContentBlock, { title: "Server Activity", description: "Tracking all events and state changes for your server.", children: [
      canClear && /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("div", { className: "flex justify-end mb-6", children: /* @__PURE__ */ (0, import_jsx_runtime31.jsxs)(
        "button",
        {
          onClick: handleClearLogs,
          disabled: isClearing,
          className: "bg-red-900/30 hover:bg-red-600 border border-red-500/50 text-red-200 hover:text-white font-black text-[10px] uppercase tracking-[0.2em] py-2.5 px-5 rounded-xl transition-all flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-red-900/20",
          children: [
            /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("i", { className: `bi ${isClearing ? "bi-hourglass-split" : "bi-trash3-fill"}` }),
            isClearing ? "Clearing History..." : "Clear Activity History"
          ]
        }
      ) }),
      /* @__PURE__ */ (0, import_jsx_runtime31.jsxs)("div", { className: "bg-neutral-900 border border-neutral-800 rounded-xl overflow-hidden mb-8 shadow-sm", children: [
        /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("div", { className: "bg-neutral-800/50 px-5 py-4 border-b border-neutral-800", children: /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("h3", { className: "text-xs font-black text-neutral-400 uppercase tracking-[0.2em]", children: "What Changed" }) }),
        /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("div", { className: "overflow-x-auto", children: /* @__PURE__ */ (0, import_jsx_runtime31.jsxs)("table", { className: "w-full text-left border-collapse", children: [
          /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("thead", { children: /* @__PURE__ */ (0, import_jsx_runtime31.jsxs)("tr", { className: "text-[10px] font-bold text-neutral-500 uppercase tracking-widest border-b border-neutral-800", children: [
            /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("th", { className: "px-6 py-4", children: "When" }),
            /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("th", { className: "px-6 py-4", children: "Actor" }),
            /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("th", { className: "px-6 py-4", children: "Category" }),
            /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("th", { className: "px-6 py-4", children: "Summary" }),
            /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("th", { className: "px-6 py-4", children: "Diff" })
          ] }) }),
          /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("tbody", { className: "text-sm", children: changeLogs.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("tr", { children: /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("td", { colSpan: "5", className: "px-6 py-10 text-center text-neutral-500 italic", children: "No configuration changes recorded yet." }) }) : changeLogs.map((entry, idx) => /* @__PURE__ */ (0, import_jsx_runtime31.jsxs)("tr", { className: "border-b border-neutral-800/50 hover:bg-white/[0.02] transition-colors", children: [
            /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("td", { className: "px-6 py-4 text-neutral-400 whitespace-nowrap", children: new Date(entry.createdAt).toLocaleString() }),
            /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("td", { className: "px-6 py-4", children: /* @__PURE__ */ (0, import_jsx_runtime31.jsxs)("div", { className: "flex items-center gap-2", children: [
              /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("div", { className: "w-6 h-6 rounded-full bg-neutral-800 flex items-center justify-center text-[10px] font-bold text-primary-400", children: entry.actor?.username?.charAt(0).toUpperCase() || "S" }),
              /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("span", { className: "text-neutral-200", children: entry.actor?.username || "system" })
            ] }) }),
            /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("td", { className: "px-6 py-4", children: /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("span", { className: "bg-neutral-800 text-neutral-400 px-2 py-0.5 rounded text-[10px] font-mono border border-neutral-700", children: entry.category || "-" }) }),
            /* @__PURE__ */ (0, import_jsx_runtime31.jsxs)("td", { className: "px-6 py-4", children: [
              /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("div", { className: "font-bold text-neutral-200", children: entry.summary || entry.changeKey || "-" }),
              entry.changeKey && /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("div", { className: "text-[10px] text-neutral-500 font-mono mt-0.5", children: entry.changeKey })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("td", { className: "px-6 py-4 max-w-xs", children: /* @__PURE__ */ (0, import_jsx_runtime31.jsxs)("div", { className: "text-[10px] space-y-1", children: [
              /* @__PURE__ */ (0, import_jsx_runtime31.jsxs)("div", { className: "flex gap-2", children: [
                /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("span", { className: "text-red-500/50 font-bold uppercase w-10", children: "Before:" }),
                /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("code", { className: "text-neutral-500 truncate block", children: JSON.stringify(entry.beforeValue) })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime31.jsxs)("div", { className: "flex gap-2", children: [
                /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("span", { className: "text-green-500/50 font-bold uppercase w-10", children: "After:" }),
                /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("code", { className: "text-neutral-300 truncate block", children: JSON.stringify(entry.afterValue) })
              ] })
            ] }) })
          ] }, idx)) })
        ] }) })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime31.jsxs)("div", { className: "bg-neutral-900 border border-neutral-800 rounded-xl overflow-hidden shadow-sm", children: [
        /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("div", { className: "bg-neutral-800/50 px-5 py-4 border-b border-neutral-800", children: /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("h3", { className: "text-xs font-black text-neutral-400 uppercase tracking-[0.2em]", children: "Activity Log" }) }),
        /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("div", { className: "overflow-x-auto", children: /* @__PURE__ */ (0, import_jsx_runtime31.jsxs)("table", { className: "w-full text-left border-collapse", children: [
          /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("thead", { children: /* @__PURE__ */ (0, import_jsx_runtime31.jsxs)("tr", { className: "text-[10px] font-bold text-neutral-500 uppercase tracking-widest border-b border-neutral-800", children: [
            /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("th", { className: "px-6 py-4", children: "When" }),
            /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("th", { className: "px-6 py-4", children: "Actor" }),
            /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("th", { className: "px-6 py-4 text-center", children: "Action" }),
            /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("th", { className: "px-6 py-4", children: "Summary" }),
            /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("th", { className: "px-6 py-4 text-right", children: "IP Address" })
          ] }) }),
          /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("tbody", { className: "text-sm", children: logs.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("tr", { children: /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("td", { colSpan: "5", className: "px-6 py-10 text-center text-neutral-500 italic", children: "No activity logs found." }) }) : logs.map((log, idx) => /* @__PURE__ */ (0, import_jsx_runtime31.jsxs)("tr", { className: "border-b border-neutral-800/50 hover:bg-white/[0.02] transition-colors", children: [
            /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("td", { className: "px-6 py-4 text-neutral-400 whitespace-nowrap", children: new Date(log.createdAt).toLocaleString() }),
            /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("td", { className: "px-6 py-4", children: /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("span", { className: "text-neutral-200 font-medium", children: log.actor?.username || "system" }) }),
            /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("td", { className: "px-6 py-4 text-center", children: /* @__PURE__ */ (0, import_jsx_runtime31.jsx)(ToneBadge, { tone: getActivityTone(log.action), children: (log.action || "").split(":").pop().replace(/\./g, " ") }) }),
            /* @__PURE__ */ (0, import_jsx_runtime31.jsxs)("td", { className: "px-6 py-4", children: [
              /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("div", { className: "text-neutral-300", children: getActivitySummary(log) }),
              log.metadata?.reason && /* @__PURE__ */ (0, import_jsx_runtime31.jsxs)("div", { className: "text-[10px] text-neutral-500 italic mt-1 flex items-center gap-1", children: [
                /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("i", { className: "bi bi-info-circle" }),
                " ",
                log.metadata.reason
              ] })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime31.jsx)("td", { className: "px-6 py-4 text-right text-neutral-500 font-mono text-xs", children: log.ip || "\u2013" })
          ] }, idx)) })
        ] }) })
      ] })
    ] }) });
  }
  if (root19) {
    root19.render(
      /* @__PURE__ */ (0, import_jsx_runtime31.jsx)(ThemeContext_default, { pageData: data19, children: /* @__PURE__ */ (0, import_jsx_runtime31.jsx)(ServerActivityPage, { pageData: data19 }) })
    );
  }

  // views/react/server-timeline.jsx
  var import_react32 = __toESM(require_react());
  var import_client20 = __toESM(require_client());
  var import_jsx_runtime32 = __toESM(require_jsx_runtime());
  var data20 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry20 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "server-timeline";
  var root20 = standaloneEntry20 ? (0, import_client20.createRoot)(document.getElementById("reactRoot")) : null;
  var MAX_POINTS = 180;
  function ServerTimelinePage({ pageData = data20 }) {
    const server = pageData.server || {};
    const canvasRef = (0, import_react32.useRef)(null);
    const [history, setHistory] = (0, import_react32.useState)([]);
    const [stats, setStats] = (0, import_react32.useState)({ cpu: 0, memory: 0, disk: 0, lastUpdate: null });
    const memoryLimit = Math.max(1, Number(server.memory) || 1);
    const diskLimit = Math.max(1, Number(server.disk) || 1);
    (0, import_react32.useEffect)(() => {
      if (pageData.samples && Array.isArray(pageData.samples)) {
        const initial = pageData.samples.map((row) => ({
          ts: row.collectedAt ? new Date(row.collectedAt).getTime() : Date.now(),
          cpu: Math.max(0, parseFloat(row.cpuPercent) || 0),
          mem: Math.max(0, parseFloat(row.memoryMb) || 0),
          disk: Math.max(0, parseFloat(row.diskMb) || 0)
        })).slice(-MAX_POINTS);
        setHistory(initial);
        if (initial.length > 0) {
          const last = initial[initial.length - 1];
          setStats({ cpu: last.cpu, memory: last.mem, disk: last.disk, lastUpdate: new Date(last.ts) });
        }
      }
    }, [pageData.samples]);
    (0, import_react32.useEffect)(() => {
      const wsToken = pageData.wsToken;
      if (!wsToken) return;
      const protocol = window.location.protocol.replace("http", "ws");
      const url = `${protocol}//${window.location.host}/ws/server/${server.containerId}?token=${encodeURIComponent(wsToken)}`;
      let ws = null;
      const connect = () => {
        ws = new WebSocket(url);
        ws.onmessage = (event) => {
          try {
            const data32 = JSON.parse(event.data);
            if (data32 && data32.type === "server_stats") {
              const newPoint = {
                ts: Date.now(),
                cpu: Math.max(0, parseFloat(data32.cpu) || 0),
                mem: Math.max(0, parseFloat(data32.memory) || 0),
                disk: Math.max(0, parseFloat(data32.disk) || 0)
              };
              setHistory((prev) => {
                const updated = [...prev, newPoint];
                return updated.slice(-MAX_POINTS);
              });
              setStats({ cpu: newPoint.cpu, memory: newPoint.mem, disk: newPoint.disk, lastUpdate: /* @__PURE__ */ new Date() });
            }
          } catch (e) {
          }
        };
        ws.onclose = () => setTimeout(connect, 2e3);
      };
      connect();
      return () => ws && ws.close();
    }, [server.containerId, pageData.wsToken]);
    (0, import_react32.useEffect)(() => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const draw = () => {
        const ctx = canvas.getContext("2d");
        const dpr = window.devicePixelRatio || 1;
        const rect = canvas.getBoundingClientRect();
        const width = rect.width;
        const height = rect.height;
        canvas.width = width * dpr;
        canvas.height = height * dpr;
        ctx.scale(dpr, dpr);
        ctx.clearRect(0, 0, width, height);
        ctx.fillStyle = "#0a0a0c";
        ctx.fillRect(0, 0, width, height);
        ctx.strokeStyle = "rgba(255,255,255,0.05)";
        ctx.lineWidth = 1;
        for (let i = 0; i <= 4; i++) {
          const y = 10 + (height - 20) * (i / 4);
          ctx.beginPath();
          ctx.moveTo(0, y);
          ctx.lineTo(width, y);
          ctx.stroke();
        }
        if (history.length < 2) return;
        const clamp2 = (v) => Math.max(0, Math.min(100, v));
        const getX = (i) => width / (MAX_POINTS - 1) * (i + (MAX_POINTS - history.length));
        const getY = (percent) => 10 + (height - 20) * (1 - clamp2(percent) / 100);
        const drawLine = (getData, color, fillGradient) => {
          ctx.beginPath();
          history.forEach((pt, i) => {
            const x = getX(i);
            const y = getY(getData(pt));
            if (i === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
          });
          ctx.strokeStyle = color;
          ctx.lineWidth = 2;
          ctx.lineJoin = "round";
          ctx.stroke();
          if (fillGradient) {
            ctx.lineTo(getX(history.length - 1), height);
            ctx.lineTo(getX(0), height);
            ctx.closePath();
            const grad = ctx.createLinearGradient(0, 0, 0, height);
            grad.addColorStop(0, fillGradient);
            grad.addColorStop(1, "transparent");
            ctx.fillStyle = grad;
            ctx.fill();
          }
        };
        drawLine((p) => p.disk / diskLimit * 100, "#f59e0b", "rgba(245, 158, 11, 0.05)");
        drawLine((p) => p.mem / memoryLimit * 100, "#3b82f6", "rgba(59, 130, 246, 0.05)");
        drawLine((p) => p.cpu, "#22c55e", "rgba(34, 197, 94, 0.1)");
      };
      draw();
      window.addEventListener("resize", draw);
      return () => window.removeEventListener("resize", draw);
    }, [history, memoryLimit, diskLimit]);
    return /* @__PURE__ */ (0, import_jsx_runtime32.jsx)(ReactAppShell, { pageData, subtitle: "Resource Timeline", children: /* @__PURE__ */ (0, import_jsx_runtime32.jsx)(PageContentBlock, { title: "Resource Timeline", description: "Real-time performance monitoring across CPU, Memory and Disk.", children: /* @__PURE__ */ (0, import_jsx_runtime32.jsxs)("div", { className: "bg-neutral-900 border border-neutral-800 rounded-2xl p-6 shadow-xl overflow-hidden", children: [
      /* @__PURE__ */ (0, import_jsx_runtime32.jsxs)("div", { className: "flex flex-wrap items-center justify-between gap-4 mb-6", children: [
        /* @__PURE__ */ (0, import_jsx_runtime32.jsxs)("div", { className: "flex gap-6", children: [
          /* @__PURE__ */ (0, import_jsx_runtime32.jsxs)("div", { className: "flex items-center gap-2", children: [
            /* @__PURE__ */ (0, import_jsx_runtime32.jsx)("div", { className: "w-3 h-3 rounded-full bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.5)]" }),
            /* @__PURE__ */ (0, import_jsx_runtime32.jsx)("span", { className: "text-xs font-bold text-neutral-300 uppercase tracking-widest", children: "CPU Used" })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime32.jsxs)("div", { className: "flex items-center gap-2", children: [
            /* @__PURE__ */ (0, import_jsx_runtime32.jsx)("div", { className: "w-3 h-3 rounded-full bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.5)]" }),
            /* @__PURE__ */ (0, import_jsx_runtime32.jsx)("span", { className: "text-xs font-bold text-neutral-300 uppercase tracking-widest", children: "Memory Used" })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime32.jsxs)("div", { className: "flex items-center gap-2", children: [
            /* @__PURE__ */ (0, import_jsx_runtime32.jsx)("div", { className: "w-3 h-3 rounded-full bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.5)]" }),
            /* @__PURE__ */ (0, import_jsx_runtime32.jsx)("span", { className: "text-xs font-bold text-neutral-300 uppercase tracking-widest", children: "Disk Used" })
          ] })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime32.jsxs)("div", { className: "text-[10px] font-mono text-neutral-500", children: [
          "Last Update: ",
          stats.lastUpdate ? stats.lastUpdate.toLocaleTimeString() : "Waiting..."
        ] })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime32.jsxs)("div", { className: "relative group", children: [
        /* @__PURE__ */ (0, import_jsx_runtime32.jsx)(
          "canvas",
          {
            ref: canvasRef,
            className: "w-full h-[360px] cursor-crosshair rounded-lg",
            style: { imageRendering: "auto" }
          }
        ),
        /* @__PURE__ */ (0, import_jsx_runtime32.jsxs)("div", { className: "absolute top-4 right-4 pointer-events-none space-y-2", children: [
          /* @__PURE__ */ (0, import_jsx_runtime32.jsxs)("div", { className: "bg-neutral-950/80 backdrop-blur-md border border-neutral-700/50 rounded-lg px-3 py-2 text-right", children: [
            /* @__PURE__ */ (0, import_jsx_runtime32.jsx)("div", { className: "text-[10px] text-neutral-500 font-bold uppercase tracking-tighter", children: "Current CPU" }),
            /* @__PURE__ */ (0, import_jsx_runtime32.jsxs)("div", { className: "text-lg font-black text-white", children: [
              stats.cpu.toFixed(1),
              "%"
            ] })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime32.jsxs)("div", { className: "bg-neutral-950/80 backdrop-blur-md border border-neutral-700/50 rounded-lg px-3 py-2 text-right", children: [
            /* @__PURE__ */ (0, import_jsx_runtime32.jsx)("div", { className: "text-[10px] text-neutral-500 font-bold uppercase tracking-tighter", children: "Current Memory" }),
            /* @__PURE__ */ (0, import_jsx_runtime32.jsxs)("div", { className: "text-lg font-black text-white", children: [
              Math.round(stats.memory),
              " MB"
            ] })
          ] })
        ] })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime32.jsxs)("div", { className: "grid grid-cols-1 md:grid-cols-3 gap-4 mt-8 pt-8 border-t border-neutral-800", children: [
        /* @__PURE__ */ (0, import_jsx_runtime32.jsxs)("div", { className: "space-y-1", children: [
          /* @__PURE__ */ (0, import_jsx_runtime32.jsx)("div", { className: "text-[10px] font-bold text-neutral-500 uppercase tracking-widest", children: "CPU Limit" }),
          /* @__PURE__ */ (0, import_jsx_runtime32.jsx)("div", { className: "text-neutral-200 font-mono", children: "Unrestricted" })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime32.jsxs)("div", { className: "space-y-1", children: [
          /* @__PURE__ */ (0, import_jsx_runtime32.jsx)("div", { className: "text-[10px] font-bold text-neutral-500 uppercase tracking-widest", children: "Memory Limit" }),
          /* @__PURE__ */ (0, import_jsx_runtime32.jsxs)("div", { className: "text-neutral-200 font-mono", children: [
            memoryLimit,
            " MB"
          ] })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime32.jsxs)("div", { className: "space-y-1", children: [
          /* @__PURE__ */ (0, import_jsx_runtime32.jsx)("div", { className: "text-[10px] font-bold text-neutral-500 uppercase tracking-widest", children: "Disk Quota" }),
          /* @__PURE__ */ (0, import_jsx_runtime32.jsxs)("div", { className: "text-neutral-200 font-mono", children: [
            diskLimit,
            " MB"
          ] })
        ] })
      ] })
    ] }) }) });
  }
  if (root20) {
    root20.render(
      /* @__PURE__ */ (0, import_jsx_runtime32.jsx)(ThemeContext_default, { pageData: data20, children: /* @__PURE__ */ (0, import_jsx_runtime32.jsx)(ServerTimelinePage, { pageData: data20 }) })
    );
  }

  // views/react/server-not-found.jsx
  var import_react33 = __toESM(require_react());
  var import_client21 = __toESM(require_client());
  var import_jsx_runtime33 = __toESM(require_jsx_runtime());
  var data21 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry21 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "server-not-found";
  var root21 = standaloneEntry21 ? (0, import_client21.createRoot)(document.getElementById("reactRoot")) : null;
  function ServerNotFoundPage({ pageData = data21 }) {
    const brandName = pageData.settings?.brandName || "CPanel";
    return /* @__PURE__ */ (0, import_jsx_runtime33.jsx)("div", { className: "min-h-screen bg-neutral-950 flex items-center justify-center p-6 font-sans text-neutral-200", children: /* @__PURE__ */ (0, import_jsx_runtime33.jsxs)("div", { className: "max-w-md w-full bg-neutral-900 border border-neutral-800 rounded-2xl p-10 text-center shadow-2xl relative overflow-hidden", children: [
      /* @__PURE__ */ (0, import_jsx_runtime33.jsx)("div", { className: "absolute -top-24 -right-24 w-48 h-48 bg-primary-600/10 rounded-full blur-3xl" }),
      /* @__PURE__ */ (0, import_jsx_runtime33.jsxs)("div", { className: "relative z-10", children: [
        /* @__PURE__ */ (0, import_jsx_runtime33.jsx)("div", { className: "mb-8", children: /* @__PURE__ */ (0, import_jsx_runtime33.jsx)(
          "img",
          {
            src: "/assets/sad-rocky.png",
            alt: "Not Found",
            className: "w-40 h-40 mx-auto rounded-2xl shadow-lg border border-neutral-800"
          }
        ) }),
        /* @__PURE__ */ (0, import_jsx_runtime33.jsx)("div", { className: "text-primary-500 text-xs font-black uppercase tracking-[0.2em] mb-3", children: brandName }),
        /* @__PURE__ */ (0, import_jsx_runtime33.jsx)("h1", { className: "text-3xl font-extrabold text-white mb-4", children: "Server Not Found" }),
        /* @__PURE__ */ (0, import_jsx_runtime33.jsx)("p", { className: "text-neutral-400 leading-relaxed mb-8", children: "The server you are looking for does not exist or has been deleted from our system." }),
        /* @__PURE__ */ (0, import_jsx_runtime33.jsxs)(
          "a",
          {
            href: "/",
            className: "inline-flex items-center justify-center px-8 py-3 bg-neutral-800 hover:bg-neutral-700 text-white font-bold rounded-xl transition-all hover:-translate-y-1 shadow-md border border-neutral-700",
            children: [
              /* @__PURE__ */ (0, import_jsx_runtime33.jsx)("i", { className: "bi bi-arrow-left me-2" }),
              "Back to Dashboard"
            ]
          }
        )
      ] })
    ] }) });
  }
  if (root21) {
    root21.render(
      /* @__PURE__ */ (0, import_jsx_runtime33.jsx)(ThemeContext_default, { pageData: data21, children: /* @__PURE__ */ (0, import_jsx_runtime33.jsx)(ServerNotFoundPage, { pageData: data21 }) })
    );
  }

  // views/react/server-no-permissions.jsx
  var import_react34 = __toESM(require_react());
  var import_client22 = __toESM(require_client());
  var import_jsx_runtime34 = __toESM(require_jsx_runtime());
  var data22 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry22 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "server-no-permissions";
  var root22 = standaloneEntry22 ? (0, import_client22.createRoot)(document.getElementById("reactRoot")) : null;
  function ServerNoPermissionsPage({ pageData = data22 }) {
    const brandName = pageData.settings?.brandName || "CPanel";
    return /* @__PURE__ */ (0, import_jsx_runtime34.jsx)("div", { className: "min-h-screen bg-neutral-950 flex items-center justify-center p-6 font-sans text-neutral-200", children: /* @__PURE__ */ (0, import_jsx_runtime34.jsxs)("div", { className: "max-w-md w-full bg-neutral-900 border border-neutral-800 rounded-2xl p-10 text-center shadow-2xl relative overflow-hidden", children: [
      /* @__PURE__ */ (0, import_jsx_runtime34.jsx)("div", { className: "absolute -top-24 -right-24 w-48 h-48 bg-red-600/10 rounded-full blur-3xl" }),
      /* @__PURE__ */ (0, import_jsx_runtime34.jsxs)("div", { className: "relative z-10", children: [
        /* @__PURE__ */ (0, import_jsx_runtime34.jsx)("div", { className: "mb-8", children: /* @__PURE__ */ (0, import_jsx_runtime34.jsx)(
          "img",
          {
            src: "/assets/rocky-security.png",
            alt: "No Permission",
            className: "w-40 h-40 mx-auto rounded-2xl shadow-lg border border-neutral-800"
          }
        ) }),
        /* @__PURE__ */ (0, import_jsx_runtime34.jsx)("div", { className: "text-red-500 text-xs font-black uppercase tracking-[0.2em] mb-3", children: brandName }),
        /* @__PURE__ */ (0, import_jsx_runtime34.jsx)("h1", { className: "text-3xl font-extrabold text-white mb-4", children: "No Permission" }),
        /* @__PURE__ */ (0, import_jsx_runtime34.jsx)("p", { className: "text-neutral-400 leading-relaxed mb-1 italic text-sm", children: "Access Denied" }),
        /* @__PURE__ */ (0, import_jsx_runtime34.jsx)("p", { className: "text-neutral-500 text-sm mb-8", children: "You don't have permission to access this server. If you think this is a mistake, contact your administrator." }),
        /* @__PURE__ */ (0, import_jsx_runtime34.jsxs)(
          "a",
          {
            href: "/",
            className: "inline-flex items-center justify-center px-8 py-3 bg-neutral-800 hover:bg-neutral-700 text-white font-bold rounded-xl transition-all hover:-translate-y-1 shadow-md border border-neutral-700",
            children: [
              /* @__PURE__ */ (0, import_jsx_runtime34.jsx)("i", { className: "bi bi-arrow-left me-2" }),
              "Back to Dashboard"
            ]
          }
        )
      ] })
    ] }) });
  }
  if (root22) {
    root22.render(
      /* @__PURE__ */ (0, import_jsx_runtime34.jsx)(ThemeContext_default, { pageData: data22, children: /* @__PURE__ */ (0, import_jsx_runtime34.jsx)(ServerNoPermissionsPage, { pageData: data22 }) })
    );
  }

  // views/react/server-suspended.jsx
  var import_react35 = __toESM(require_react());
  var import_client23 = __toESM(require_client());
  var import_jsx_runtime35 = __toESM(require_jsx_runtime());
  var data23 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry23 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "server-suspended";
  var root23 = standaloneEntry23 ? (0, import_client23.createRoot)(document.getElementById("reactRoot")) : null;
  function ServerSuspendedPage({ pageData = data23 }) {
    const brandName = pageData.settings?.brandName || "CPanel";
    const server = pageData.server || {};
    const suspendReason = server.suspendReason || null;
    return /* @__PURE__ */ (0, import_jsx_runtime35.jsx)("div", { className: "min-h-screen bg-neutral-950 flex items-center justify-center p-6 font-sans text-neutral-200", children: /* @__PURE__ */ (0, import_jsx_runtime35.jsxs)("div", { className: "max-w-lg w-full bg-neutral-900 border border-yellow-900/20 rounded-2xl p-10 text-center shadow-2xl relative overflow-hidden", children: [
      /* @__PURE__ */ (0, import_jsx_runtime35.jsx)("div", { className: "absolute -top-24 -right-24 w-48 h-48 bg-yellow-600/10 rounded-full blur-3xl" }),
      /* @__PURE__ */ (0, import_jsx_runtime35.jsxs)("div", { className: "relative z-10", children: [
        /* @__PURE__ */ (0, import_jsx_runtime35.jsx)("div", { className: "mb-6", children: /* @__PURE__ */ (0, import_jsx_runtime35.jsx)(
          "img",
          {
            src: "/assets/sad-rocky.png",
            alt: "Suspended",
            className: "w-40 h-40 mx-auto rounded-2xl shadow-lg border border-neutral-800"
          }
        ) }),
        /* @__PURE__ */ (0, import_jsx_runtime35.jsx)("div", { className: "text-yellow-500 text-xs font-black uppercase tracking-[0.2em] mb-3", children: brandName }),
        /* @__PURE__ */ (0, import_jsx_runtime35.jsx)("h1", { className: "text-3xl font-extrabold text-white mb-2", children: "Server Suspended" }),
        /* @__PURE__ */ (0, import_jsx_runtime35.jsxs)("div", { className: "inline-block px-3 py-1 bg-neutral-800 border border-neutral-700 rounded text-xs font-mono text-neutral-400 mb-6", children: [
          /* @__PURE__ */ (0, import_jsx_runtime35.jsx)("i", { className: "bi bi-server me-2" }),
          server.name || "Unknown Server"
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime35.jsx)("p", { className: "text-neutral-400 text-sm mb-6 leading-relaxed", children: "This server has been suspended by an administrator and is temporarily unavailable. All runtime resources have been halted." }),
        /* @__PURE__ */ (0, import_jsx_runtime35.jsxs)("div", { className: "bg-yellow-500/5 border border-yellow-500/10 rounded-xl p-5 mb-8 text-left", children: [
          /* @__PURE__ */ (0, import_jsx_runtime35.jsxs)("div", { className: "text-[10px] font-bold text-yellow-500 uppercase tracking-widest mb-2 flex items-center", children: [
            /* @__PURE__ */ (0, import_jsx_runtime35.jsx)("i", { className: "bi bi-chat-left-text me-2" }),
            " Reason"
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime35.jsx)("div", { className: "text-sm text-neutral-300", children: suspendReason ? suspendReason : /* @__PURE__ */ (0, import_jsx_runtime35.jsx)("span", { className: "text-neutral-500 italic", children: "No specific reason was provided by the administrator." }) })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime35.jsx)("p", { className: "text-neutral-500 text-xs mb-8", children: "Please contact support or an administrator for more information regarding this suspension." }),
        /* @__PURE__ */ (0, import_jsx_runtime35.jsxs)(
          "a",
          {
            href: "/",
            className: "inline-flex items-center justify-center px-8 py-3 bg-neutral-800 hover:bg-neutral-700 text-white font-bold rounded-xl transition-all hover:-translate-y-1 shadow-md border border-neutral-700",
            children: [
              /* @__PURE__ */ (0, import_jsx_runtime35.jsx)("i", { className: "bi bi-arrow-left me-2" }),
              "Back to Dashboard"
            ]
          }
        )
      ] })
    ] }) });
  }
  if (root23) {
    root23.render(
      /* @__PURE__ */ (0, import_jsx_runtime35.jsx)(ThemeContext_default, { pageData: data23, children: /* @__PURE__ */ (0, import_jsx_runtime35.jsx)(ServerSuspendedPage, { pageData: data23 }) })
    );
  }

  // views/react/account.jsx
  var import_react36 = __toESM(require_react());
  var import_client24 = __toESM(require_client());
  var import_jsx_runtime36 = __toESM(require_jsx_runtime());
  var data24 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry24 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "account";
  var root24 = standaloneEntry24 ? (0, import_client24.createRoot)(document.getElementById("reactRoot")) : null;
  function LinkedProviderCard({ provider }) {
    return /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "bg-neutral-900 border border-neutral-700/50 rounded-lg p-4 flex flex-col sm:flex-row sm:items-center justify-between mb-2", children: [
      /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "flex items-center gap-3", children: [
        /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("i", { className: `bi ${provider.icon} text-2xl`, style: { color: provider.color } }),
        /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { children: [
          /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("strong", { className: "block text-sm font-bold text-neutral-200", children: provider.name }),
          /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("span", { className: "text-xs text-neutral-400", children: provider.isLinked ? "Linked to this account" : "Available to connect" })
        ] })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("div", { className: "mt-4 sm:mt-0 shrink-0", children: provider.isLinked ? /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("form", { method: "POST", action: provider.unlinkAction, children: /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("button", { type: "submit", className: "bg-red-600/20 hover:bg-red-600/30 text-red-400 hover:text-red-300 border border-red-600/30 text-xs font-semibold py-1.5 px-4 rounded transition-colors w-full sm:w-auto", children: "Unlink" }) }) : /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("a", { href: provider.linkAction, className: "inline-block bg-neutral-700 hover:bg-neutral-600 text-neutral-200 text-xs font-semibold py-1.5 px-4 rounded transition-colors text-center w-full sm:w-auto", children: "Connect" }) })
    ] });
  }
  function AccountPage({ pageData = data24 }) {
    const user = pageData.user || {};
    const linkedProviders = Array.isArray(pageData.linkedProviders) ? pageData.linkedProviders : [];
    const avatar = resolveUserAvatar(user, resolveBrandImage(pageData));
    const [setupState, setSetupState] = import_react36.default.useState({ loading: false, qrCodeUrl: "", secret: "", code: "", error: "" });
    const [disableState, setDisableState] = import_react36.default.useState({ password: "", loading: false, error: "" });
    const start2FASetup = async () => {
      setSetupState((current) => ({ ...current, loading: true, error: "" }));
      try {
        const response = await fetch("/account/2fa/setup");
        const payload = await response.json();
        if (!response.ok || payload.error) {
          throw new Error(payload.error || "Failed to initialize 2FA.");
        }
        setSetupState({
          loading: false,
          qrCodeUrl: payload.qrCodeUrl || "",
          secret: payload.secret || "",
          code: "",
          error: ""
        });
      } catch (error) {
        setSetupState((current) => ({
          ...current,
          loading: false,
          error: error && error.message ? error.message : "Failed to initialize 2FA."
        }));
      }
    };
    const enable2FA = async () => {
      if (!setupState.code || setupState.code.trim().length !== 6) {
        setSetupState((current) => ({ ...current, error: "Enter the 6-digit code from your authenticator app." }));
        return;
      }
      setSetupState((current) => ({ ...current, loading: true, error: "" }));
      try {
        const response = await fetch("/account/2fa/enable", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ code: setupState.code.trim() })
        });
        const payload = await response.json();
        if (!response.ok || !payload.success) {
          throw new Error(payload.error || "Failed to enable 2FA.");
        }
        window.location.replace("/account?success=" + encodeURIComponent("2FA enabled successfully."));
      } catch (error) {
        setSetupState((current) => ({
          ...current,
          loading: false,
          error: error && error.message ? error.message : "Failed to enable 2FA."
        }));
      }
    };
    const disable2FA = async () => {
      if (!disableState.password) {
        setDisableState((current) => ({ ...current, error: "Current password is required." }));
        return;
      }
      setDisableState((current) => ({ ...current, loading: true, error: "" }));
      try {
        const response = await fetch("/account/2fa/disable", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password: disableState.password })
        });
        const payload = await response.json();
        if (!response.ok || !payload.success) {
          throw new Error(payload.error || "Failed to disable 2FA.");
        }
        window.location.replace("/account?success=" + encodeURIComponent("2FA disabled successfully."));
      } catch (error) {
        setDisableState((current) => ({
          ...current,
          loading: false,
          error: error && error.message ? error.message : "Failed to disable 2FA."
        }));
      }
    };
    const [browserNotifyEnabled, setBrowserNotifyEnabled] = import_react36.default.useState(pageData.browserSubscriptionCount > 0);
    const [notifyLoading, setNotifyLoading] = import_react36.default.useState(false);
    const toggleBrowserNotifications = async (enable) => {
      if (enable) {
        if (!("Notification" in window)) {
          alert("This browser does not support desktop notifications.");
          return;
        }
        let permission = Notification.permission;
        if (permission === "default") {
          permission = await Notification.requestPermission();
        }
        if (permission !== "granted") {
          alert("Notification permission was not granted. Please enable it in your browser settings.");
          return;
        }
        setNotifyLoading(true);
        try {
          const response = await fetch("/api/account/browser-notifications/subscribe", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              permission,
              endpoint: `browser:${navigator.userAgent}:${window.location.host}`,
              keys: {}
            })
          });
          if (!response.ok) throw new Error("Failed to subscribe.");
          setBrowserNotifyEnabled(true);
        } catch (error) {
          alert(error.message || "Action failed.");
        } finally {
          setNotifyLoading(false);
        }
      } else {
        setNotifyLoading(true);
        try {
          const response = await fetch("/api/account/browser-notifications/unsubscribe", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({})
          });
          if (!response.ok) throw new Error("Failed to unsubscribe.");
          setBrowserNotifyEnabled(false);
        } catch (error) {
          alert(error.message || "Action failed.");
        } finally {
          setNotifyLoading(false);
        }
      }
    };
    const inputClass = "w-full bg-neutral-900 border border-neutral-700/50 rounded p-2.5 text-sm text-neutral-200 focus:ring-2 focus:ring-primary-500 focus:border-transparent outline-none transition-shadow";
    const labelClass = "block text-xs font-bold text-neutral-400 uppercase tracking-wide mb-1.5";
    return /* @__PURE__ */ (0, import_jsx_runtime36.jsx)(ReactAppShell, { pageData, subtitle: "Account surface", children: /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)(PageContentBlock, { title: "Your Account", children: [
      pageData.success && /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "bg-green-600/20 border border-green-600/50 text-green-100 p-4 rounded-lg mb-6 shadow-sm flex items-center gap-3", children: [
        /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("i", { className: "bi bi-check-circle-fill text-green-500" }),
        pageData.success
      ] }),
      pageData.error && /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "bg-red-600/20 border border-red-600/50 text-red-100 p-4 rounded-lg mb-6 shadow-sm flex items-center gap-3", children: [
        /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("i", { className: "bi bi-exclamation-triangle-fill text-red-500" }),
        pageData.error
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "grid grid-cols-1 lg:grid-cols-12 gap-6 items-start", children: [
        /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "lg:col-span-4 flex flex-col gap-6", children: [
          /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-lg p-6", children: [
            /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "flex flex-col items-center text-center", children: [
              /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("img", { src: avatar, alt: user.username || "User", className: "w-24 h-24 rounded-full border-4 border-neutral-700 shadow-md mb-4" }),
              /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("h1", { className: "text-xl font-bold text-white leading-tight", children: [user.firstName, user.lastName].filter(Boolean).join(" ") || user.username || "Account" }),
              /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "text-sm text-neutral-400 mt-1 font-mono", children: [
                "@",
                user.username || "unknown"
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("div", { className: "text-sm text-neutral-500 mt-0.5", children: user.email || "No email set" }),
              /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "flex flex-wrap items-center justify-center gap-2 mt-4", children: [
                /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("span", { className: `px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wide ${user.twoFactorEnabled ? "bg-green-600/20 text-green-400 border border-green-600/30" : "bg-neutral-700 text-neutral-400"}`, children: user.twoFactorEnabled ? "2FA Active" : "2FA Inactive" }),
                /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("span", { className: "px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wide bg-primary-600/20 text-primary-400 border border-primary-600/30", children: [
                  "Theme: ",
                  pageData.activeTheme || "default"
                ] })
              ] })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "mt-8 flex flex-col gap-2", children: [
              /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)(Link, { to: ReactRoutes.deviceLogin, className: "w-full bg-neutral-700/50 hover:bg-neutral-700 text-neutral-300 text-sm font-semibold py-2 px-4 rounded transition-colors text-center border border-transparent hover:border-neutral-600 flex justify-center items-center gap-2", children: [
                /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("i", { className: "bi bi-clock-history" }),
                " Device History"
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("a", { href: ReactRoutes.themes, className: "w-full bg-neutral-700/50 hover:bg-neutral-700 text-neutral-300 text-sm font-semibold py-2 px-4 rounded transition-colors text-center border border-transparent hover:border-neutral-600 flex justify-center items-center gap-2", children: [
                /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("i", { className: "bi bi-palette2" }),
                " Themes"
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)(Link, { to: ReactRoutes.experimentalFeatures, className: "w-full bg-neutral-700/50 hover:bg-neutral-700 text-neutral-300 text-sm font-semibold py-2 px-4 rounded transition-colors text-center border border-transparent hover:border-neutral-600 flex justify-center items-center gap-2", children: [
                /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("i", { className: "bi bi-stars" }),
                " Experimental"
              ] })
            ] })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-lg p-6", children: [
            /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("h2", { className: "text-lg font-bold text-neutral-100 mb-4", children: "Linked Accounts" }),
            /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("div", { children: linkedProviders.length > 0 ? linkedProviders.map((provider) => /* @__PURE__ */ (0, import_jsx_runtime36.jsx)(LinkedProviderCard, { provider }, provider.id)) : /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("div", { className: "text-sm text-neutral-400 text-center py-4", children: "No external providers are configured for this account yet." }) })
          ] })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "lg:col-span-8 flex flex-col gap-6", children: [
          /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-lg p-6", children: [
            /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("h2", { className: "text-lg font-bold text-neutral-100 mb-6", children: "Account Details" }),
            /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("form", { method: "POST", action: "/account/update", className: "flex flex-col gap-5", children: [
              /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-5", children: [
                /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("label", { children: [
                  /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("span", { className: labelClass, children: "First Name" }),
                  /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("input", { type: "text", name: "firstName", defaultValue: user.firstName || "", required: true, className: inputClass })
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("label", { children: [
                  /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("span", { className: labelClass, children: "Last Name" }),
                  /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("input", { type: "text", name: "lastName", defaultValue: user.lastName || "", required: true, className: inputClass })
                ] })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("label", { children: [
                /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("span", { className: labelClass, children: "Email" }),
                /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("input", { type: "email", name: "email", defaultValue: user.email || "", required: true, className: inputClass })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-5", children: [
                /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("label", { children: [
                  /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("span", { className: labelClass, children: "Avatar Provider" }),
                  /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("select", { name: "avatarProvider", defaultValue: user.avatarProvider || "gravatar", className: `${inputClass} pr-8 appearance-none`, children: [
                    /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("option", { value: "gravatar", children: "Gravatar" }),
                    /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("option", { value: "url", children: "Custom URL" })
                  ] })
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("label", { children: [
                  /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("span", { className: labelClass, children: "Avatar URL" }),
                  /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("input", { type: "url", name: "avatarUrl", defaultValue: user.avatarUrl || "", placeholder: "https://example.com/avatar.png", className: inputClass })
                ] })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("label", { children: [
                /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("span", { className: labelClass, children: "Username" }),
                /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("input", { type: "text", value: user.username || "", readOnly: true, className: `${inputClass} bg-neutral-800/50 cursor-not-allowed text-neutral-500 ring-0 focus:ring-0` }),
                /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("span", { className: "block text-xs text-neutral-500 mt-1", children: "Usernames cannot be changed." })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("div", { className: "mt-2 flex justify-end", children: /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("button", { type: "submit", className: "bg-primary-600 hover:bg-primary-500 text-white font-semibold py-2 px-6 rounded transition-colors text-sm shadow-sm", children: "Save Account" }) })
            ] })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-lg p-6", children: [
            /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("h2", { className: "text-lg font-bold text-neutral-100 mb-6", children: "Update Password" }),
            /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("form", { method: "POST", action: "/account/password", className: "flex flex-col gap-5", children: [
              /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("label", { children: [
                /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("span", { className: labelClass, children: "Current Password" }),
                /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("input", { type: "password", name: "currentPassword", required: true, className: inputClass })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-5", children: [
                /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("label", { children: [
                  /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("span", { className: labelClass, children: "New Password" }),
                  /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("input", { type: "password", name: "newPassword", required: true, className: inputClass })
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("label", { children: [
                  /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("span", { className: labelClass, children: "Confirm New Password" }),
                  /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("input", { type: "password", name: "confirmPassword", required: true, className: inputClass })
                ] })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("div", { className: "mt-2 flex justify-end", children: /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("button", { type: "submit", className: "bg-primary-600 hover:bg-primary-500 text-white font-semibold py-2 px-6 rounded transition-colors text-sm shadow-sm", children: "Update Password" }) })
            ] })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-lg p-6", children: [
            /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("h2", { className: "text-lg font-bold text-neutral-100 mb-4", children: "Two-Factor Authentication" }),
            user.twoFactorEnabled ? /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { children: [
              /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("p", { className: "text-sm text-neutral-400 mb-5", children: "Two-factor authentication is currently enabled on your account. If you would like to disable it, you must securely confirm your password below." }),
              /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "flex flex-col sm:flex-row gap-4 items-end", children: [
                /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("label", { className: "flex-1 w-full", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("span", { className: labelClass, children: "Current Password" }),
                  /* @__PURE__ */ (0, import_jsx_runtime36.jsx)(
                    "input",
                    {
                      type: "password",
                      value: disableState.password,
                      onChange: (e) => setDisableState({ ...disableState, password: e.target.value }),
                      className: inputClass
                    }
                  )
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime36.jsx)(
                  "button",
                  {
                    type: "button",
                    className: "w-full sm:w-auto bg-red-600 hover:bg-red-500 text-white font-semibold flex-shrink-0 h-10 px-6 rounded transition-colors text-sm shadow-sm disabled:opacity-50",
                    onClick: disable2FA,
                    disabled: disableState.loading,
                    children: disableState.loading ? "Disabling..." : "Disable 2FA"
                  }
                )
              ] }),
              disableState.error && /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("p", { className: "text-red-400 text-sm mt-2 font-bold", children: disableState.error })
            ] }) : /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { children: [
              /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("p", { className: "text-sm text-neutral-400 mb-5", children: "Enable two-factor authentication to add an extra layer of security to your account. You will be required to input a code generated by your authenticator app each time you log in." }),
              !setupState.qrCodeUrl ? /* @__PURE__ */ (0, import_jsx_runtime36.jsx)(
                "button",
                {
                  type: "button",
                  className: "bg-primary-600 hover:bg-primary-500 text-white font-semibold py-2 px-6 rounded transition-colors text-sm shadow-sm disabled:opacity-50",
                  onClick: start2FASetup,
                  disabled: setupState.loading,
                  children: setupState.loading ? "Connecting..." : "Begin Setup"
                }
              ) : /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "bg-neutral-900 border border-neutral-700/50 rounded-lg p-6 flex flex-col md:flex-row items-center md:items-start gap-8", children: [
                /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("div", { className: "bg-white p-2 rounded shrink-0 shadow-lg", children: /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("img", { src: setupState.qrCodeUrl, alt: "2FA QR code", className: "w-32 h-32 md:w-40 md:h-40", style: { imageRendering: "pixelated" } }) }),
                /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "flex-1 w-full", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("label", { className: "block mb-4", children: [
                    /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("span", { className: labelClass, children: "Manual Setup Key" }),
                    /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("input", { type: "text", value: setupState.secret, readOnly: true, className: `${inputClass} font-mono`, onClick: (e) => e.target.select() }),
                    /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("span", { className: "block text-xs text-neutral-500 mt-1", children: "If you cannot scan the QR code, manually input this secret into your app." })
                  ] }),
                  /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("label", { className: "block mb-5", children: [
                    /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("span", { className: labelClass, children: "Authentication Code" }),
                    /* @__PURE__ */ (0, import_jsx_runtime36.jsx)(
                      "input",
                      {
                        type: "text",
                        value: setupState.code,
                        maxLength: 6,
                        onChange: (event) => setSetupState({ ...setupState, code: event.target.value.replace(/[^0-9]/g, "") }),
                        placeholder: "000000",
                        className: `${inputClass} font-mono tracking-widest text-lg py-3`
                      }
                    )
                  ] }),
                  setupState.error && /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("p", { className: "text-red-400 text-sm mb-4 font-bold", children: setupState.error }),
                  /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "flex gap-3", children: [
                    /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("button", { type: "button", className: "bg-neutral-700 hover:bg-neutral-600 text-white font-semibold py-2 px-6 rounded transition-colors text-sm", onClick: () => setSetupState({ loading: false, qrCodeUrl: "", secret: "", code: "", error: "" }), children: "Cancel" }),
                    /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("button", { type: "button", className: "bg-primary-600 hover:bg-primary-500 text-white font-semibold py-2 px-6 rounded transition-colors text-sm shadow-sm disabled:opacity-50", onClick: enable2FA, disabled: setupState.loading || setupState.code.length !== 6, children: setupState.loading ? "Verifying..." : "Verify & Enable" })
                  ] })
                ] })
              ] }),
              !setupState.qrCodeUrl && setupState.error && /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("p", { className: "text-red-400 text-sm mt-4 font-bold", children: setupState.error })
            ] })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-lg p-6", children: [
            /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "flex items-center justify-between mb-6", children: [
              /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("h2", { className: "text-lg font-bold text-neutral-100", children: "Notifications Settings" }),
              /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)(Link, { to: ReactRoutes.notifications, className: "text-xs font-bold text-primary-400 hover:text-primary-300 uppercase tracking-wider", children: [
                "History ",
                /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("i", { className: "bi bi-arrow-right ml-1" })
              ] })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-8", children: [
              /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { children: [
                /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("p", { className: "text-sm text-neutral-400 mb-4", children: "Live notifications deliver system alerts, server status changes, and account activity directly to your browser." }),
                /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "flex flex-col gap-2", children: [
                  browserNotifyEnabled ? /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)(
                    "button",
                    {
                      onClick: () => toggleBrowserNotifications(false),
                      disabled: notifyLoading,
                      className: "w-full bg-red-600/10 hover:bg-red-600/20 text-red-500 border border-red-600/20 font-semibold py-2 px-4 rounded transition-colors text-sm flex items-center justify-center gap-2",
                      children: [
                        notifyLoading ? /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("span", { className: "w-4 h-4 border-2 border-red-500/30 border-t-red-500 rounded-full animate-spin" }) : /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("i", { className: "bi bi-bell-slash" }),
                        "Disable Browser Delivery"
                      ]
                    }
                  ) : /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)(
                    "button",
                    {
                      onClick: () => toggleBrowserNotifications(true),
                      disabled: notifyLoading,
                      className: "w-full bg-primary-600/10 hover:bg-primary-600/20 text-primary-500 border border-primary-600/20 font-semibold py-2 px-4 rounded transition-colors text-sm flex items-center justify-center gap-2",
                      children: [
                        notifyLoading ? /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("span", { className: "w-4 h-4 border-2 border-primary-500/30 border-t-primary-500 rounded-full animate-spin" }) : /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("i", { className: "bi bi-bell" }),
                        "Enable Browser Delivery"
                      ]
                    }
                  ),
                  /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "text-[11px] text-neutral-500 text-center uppercase tracking-widest font-black", children: [
                    "Status: ",
                    /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("span", { className: browserNotifyEnabled ? "text-green-500" : "text-neutral-600", children: browserNotifyEnabled ? "Active" : "Inactive" })
                  ] })
                ] })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "bg-neutral-900/50 rounded-lg p-4 border border-neutral-700/30", children: [
                /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("span", { className: "block text-[10px] font-black text-neutral-500 uppercase tracking-[0.2em] mb-3", children: "Recent Activity" }),
                Array.isArray(pageData.recentNotifications) && pageData.recentNotifications.length > 0 ? /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("div", { className: "flex flex-col gap-3", children: pageData.recentNotifications.slice(0, 3).map((n) => /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "flex flex-col gap-1 border-b border-neutral-700/50 pb-2 last:border-0 last:pb-0", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime36.jsxs)("div", { className: "flex items-center justify-between", children: [
                    /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("strong", { className: "text-xs text-neutral-200 truncate pr-4", children: n.title }),
                    /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("span", { className: "text-[10px] text-neutral-500 shrink-0 font-mono", children: new Date(n.createdAt).toLocaleDateString() })
                  ] }),
                  /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("p", { className: "text-[11px] text-neutral-400 line-clamp-1", children: n.message })
                ] }, n.id)) }) : /* @__PURE__ */ (0, import_jsx_runtime36.jsx)("div", { className: "text-xs text-neutral-600 py-4 text-center italic", children: "No recent notifications." })
              ] })
            ] })
          ] })
        ] })
      ] })
    ] }) });
  }
  if (root24) {
    root24.render(
      /* @__PURE__ */ (0, import_jsx_runtime36.jsx)(ThemeContext_default, { pageData: data24, children: /* @__PURE__ */ (0, import_jsx_runtime36.jsx)(AccountPage, { pageData: data24 }) })
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === "function") {
      window.__CPANEL_REACT_BOOTED__();
    }
  }

  // views/react/device-login.jsx
  var import_react37 = __toESM(require_react());
  var import_client25 = __toESM(require_client());
  var import_jsx_runtime37 = __toESM(require_jsx_runtime());
  var data25 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry25 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "device-login";
  var root25 = standaloneEntry25 ? (0, import_client25.createRoot)(document.getElementById("reactRoot")) : null;
  function formatDate3(value) {
    try {
      return new Date(value).toLocaleString();
    } catch {
      return String(value || "");
    }
  }
  function DeviceLoginPage({ pageData = data25 }) {
    const user = pageData.user || {};
    const events = Array.isArray(pageData.events) ? pageData.events : [];
    return /* @__PURE__ */ (0, import_jsx_runtime37.jsx)(ReactAppShell, { pageData, subtitle: "Device login history", children: /* @__PURE__ */ (0, import_jsx_runtime37.jsxs)(PageContentBlock, { title: "Activity History", children: [
      /* @__PURE__ */ (0, import_jsx_runtime37.jsx)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-lg p-6 mb-6", children: /* @__PURE__ */ (0, import_jsx_runtime37.jsxs)("div", { className: "flex justify-between items-center", children: [
        /* @__PURE__ */ (0, import_jsx_runtime37.jsxs)("div", { children: [
          /* @__PURE__ */ (0, import_jsx_runtime37.jsx)("h2", { className: "text-lg font-bold text-neutral-100", children: "Recent login activity" }),
          /* @__PURE__ */ (0, import_jsx_runtime37.jsx)("p", { className: "text-sm text-neutral-400 mt-1", children: "Latest account access records across device and login flow." })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime37.jsx)(Link, { to: ReactRoutes.account, className: "bg-neutral-700 hover:bg-neutral-600 text-neutral-200 text-sm font-semibold py-2 px-4 rounded transition-colors hidden sm:block", children: "Back to Account" })
      ] }) }),
      /* @__PURE__ */ (0, import_jsx_runtime37.jsx)("div", { className: "flex flex-col gap-2", children: events.length > 0 ? events.map((entry) => /* @__PURE__ */ (0, import_jsx_runtime37.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-lg p-4 flex flex-col md:flex-row md:items-center justify-between", children: [
        /* @__PURE__ */ (0, import_jsx_runtime37.jsxs)("div", { className: "flex items-center gap-4", children: [
          /* @__PURE__ */ (0, import_jsx_runtime37.jsx)("div", { className: "bg-neutral-700 text-neutral-300 p-3 rounded-full flex items-center justify-center", children: /* @__PURE__ */ (0, import_jsx_runtime37.jsx)("i", { className: "bi bi-phone text-xl leading-none" }) }),
          /* @__PURE__ */ (0, import_jsx_runtime37.jsxs)("div", { children: [
            /* @__PURE__ */ (0, import_jsx_runtime37.jsx)("div", { className: "font-bold text-neutral-100", children: entry.username || user.username || "Unknown" }),
            /* @__PURE__ */ (0, import_jsx_runtime37.jsx)("div", { className: "text-sm text-neutral-400 mt-0.5", children: `${entry.operatingSystem || "Unknown OS"} \u2022 ${entry.loginType || "Standard"} \u2022 ${entry.ipAddress || "unknown"}` })
          ] })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime37.jsxs)("div", { className: "mt-4 md:mt-0 flex flex-col md:items-end", children: [
          /* @__PURE__ */ (0, import_jsx_runtime37.jsx)("div", { className: "font-semibold text-neutral-200", children: entry.location || "Unknown" }),
          /* @__PURE__ */ (0, import_jsx_runtime37.jsx)("div", { className: "text-sm text-neutral-500 font-mono mt-0.5", children: formatDate3(entry.createdAt) })
        ] })
      ] }, entry.id || `${entry.ipAddress}-${entry.createdAt}`)) : /* @__PURE__ */ (0, import_jsx_runtime37.jsx)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-lg p-8 text-center", children: /* @__PURE__ */ (0, import_jsx_runtime37.jsx)("p", { className: "text-neutral-400", children: "No login history yet." }) }) })
    ] }) });
  }
  if (root25) {
    root25.render(
      /* @__PURE__ */ (0, import_jsx_runtime37.jsx)(ThemeContext_default, { pageData: data25, children: /* @__PURE__ */ (0, import_jsx_runtime37.jsx)(DeviceLoginPage, { pageData: data25 }) })
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === "function") {
      window.__CPANEL_REACT_BOOTED__();
    }
  }

  // views/react/themes.jsx
  var import_react38 = __toESM(require_react());
  var import_client26 = __toESM(require_client());
  var import_jsx_runtime38 = __toESM(require_jsx_runtime());
  var data26 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry26 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "themes";
  var root26 = standaloneEntry26 ? (0, import_client26.createRoot)(document.getElementById("reactRoot")) : null;
  function ThemesPage({ pageData = data26 }) {
    const themeCatalog = Array.isArray(pageData.themeCatalog) ? pageData.themeCatalog : [];
    const { activeTheme, previewTheme, customTheme, applyTheme, toggleCustomTheme, restoreTheme } = useTheme();
    const handleApply = (themeId) => {
      const form = document.createElement("form");
      form.method = "POST";
      form.action = "/themes/apply";
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = "theme";
      input.value = themeId;
      form.appendChild(input);
      document.body.appendChild(form);
      form.submit();
    };
    const handleToggleCustom = (enabled) => {
      const form = document.createElement("form");
      form.method = "POST";
      form.action = "/themes/custom-mode";
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = "enabled";
      input.value = String(enabled);
      form.appendChild(input);
      document.body.appendChild(form);
      form.submit();
    };
    const handlePreview = (theme) => {
      if (previewTheme === theme.id) {
        restoreTheme();
      } else {
        applyTheme(theme.id, true);
      }
    };
    return /* @__PURE__ */ (0, import_jsx_runtime38.jsx)(ReactAppShell, { pageData, subtitle: "Themes & Styling", children: /* @__PURE__ */ (0, import_jsx_runtime38.jsxs)(
      PageContentBlock,
      {
        title: "Themes",
        description: "Pick a preset theme or manage your private custom theme override.",
        actions: /* @__PURE__ */ (0, import_jsx_runtime38.jsxs)("div", { className: "flex gap-2", children: [
          /* @__PURE__ */ (0, import_jsx_runtime38.jsxs)("a", { href: "/themes/builder", className: "bg-neutral-800 hover:bg-neutral-700 text-neutral-300 text-xs font-bold py-1.5 px-3 rounded border border-neutral-700 transition-colors flex items-center gap-2", children: [
            /* @__PURE__ */ (0, import_jsx_runtime38.jsx)("i", { className: "bi bi-sliders" }),
            " Builder"
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime38.jsxs)(Link, { to: ReactRoutes.account, className: "bg-neutral-800 hover:bg-neutral-700 text-neutral-300 text-xs font-bold py-1.5 px-3 rounded border border-neutral-700 transition-colors flex items-center gap-2", children: [
            /* @__PURE__ */ (0, import_jsx_runtime38.jsx)("i", { className: "bi bi-arrow-left" }),
            " Account"
          ] })
        ] }),
        children: [
          /* @__PURE__ */ (0, import_jsx_runtime38.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-xl p-6 mb-8 shadow-sm", children: [
            /* @__PURE__ */ (0, import_jsx_runtime38.jsxs)("div", { className: "flex flex-wrap justify-between items-center gap-6", children: [
              /* @__PURE__ */ (0, import_jsx_runtime38.jsxs)("div", { className: "flex gap-8", children: [
                /* @__PURE__ */ (0, import_jsx_runtime38.jsxs)("div", { children: [
                  /* @__PURE__ */ (0, import_jsx_runtime38.jsx)("span", { className: "block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-1", children: "Base Theme" }),
                  /* @__PURE__ */ (0, import_jsx_runtime38.jsx)("div", { className: "text-xl font-bold text-white capitalize", children: activeTheme })
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime38.jsxs)("div", { children: [
                  /* @__PURE__ */ (0, import_jsx_runtime38.jsx)("span", { className: "block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-1", children: "Custom Override" }),
                  /* @__PURE__ */ (0, import_jsx_runtime38.jsxs)("div", { className: "flex items-center gap-2", children: [
                    /* @__PURE__ */ (0, import_jsx_runtime38.jsx)("div", { className: `w-2 h-2 rounded-full ${customTheme.enabled ? "bg-green-500 animate-pulse" : "bg-neutral-600"}` }),
                    /* @__PURE__ */ (0, import_jsx_runtime38.jsx)("span", { className: `text-sm font-bold ${customTheme.enabled ? "text-green-400" : "text-neutral-500"}`, children: customTheme.enabled ? "ENABLED" : "DISABLED" })
                  ] })
                ] })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime38.jsx)("div", { className: "flex items-center gap-3", children: /* @__PURE__ */ (0, import_jsx_runtime38.jsx)(
                "button",
                {
                  onClick: () => handleToggleCustom(!customTheme.enabled),
                  className: `px-4 py-2 rounded text-xs font-bold transition-all border ${customTheme.enabled ? "bg-red-500/10 border-red-500/20 text-red-400 hover:bg-red-500/20" : "bg-green-500/10 border-green-500/20 text-green-400 hover:bg-green-500/20"}`,
                  children: customTheme.enabled ? "Disable Override" : "Enable Override"
                }
              ) })
            ] }),
            previewTheme && /* @__PURE__ */ (0, import_jsx_runtime38.jsxs)("div", { className: "mt-6 pt-6 border-t border-neutral-700/50 flex items-center justify-between", children: [
              /* @__PURE__ */ (0, import_jsx_runtime38.jsxs)("div", { className: "flex items-center gap-3", children: [
                /* @__PURE__ */ (0, import_jsx_runtime38.jsx)("i", { className: "bi bi-eye-fill text-yellow-500" }),
                /* @__PURE__ */ (0, import_jsx_runtime38.jsx)("span", { className: "text-sm text-neutral-300", children: "Currently previewing a theme. Styles are temporary." })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime38.jsx)(
                "button",
                {
                  onClick: restoreTheme,
                  className: "text-xs font-bold text-yellow-500 hover:text-yellow-400 uppercase tracking-wider underline underline-offset-4",
                  children: "Reset View"
                }
              )
            ] })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime38.jsx)("div", { className: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6", children: themeCatalog.map((theme) => {
            const isCurrent = String(activeTheme).toLowerCase() === String(theme.id).toLowerCase();
            const isPreviewing = previewTheme === theme.id;
            const preview = theme.preview || {};
            const swatches = Array.isArray(preview.swatches) ? preview.swatches : ["#3b82f6", "#2e3036", "#ffffff"];
            return /* @__PURE__ */ (0, import_jsx_runtime38.jsxs)("div", { className: `group bg-neutral-800 border rounded-2xl overflow-hidden transition-all duration-300 hover:translate-y-[-4px] hover:shadow-xl ${isCurrent ? "border-primary-500 ring-1 ring-primary-500/20" : "border-neutral-700"}`, children: [
              /* @__PURE__ */ (0, import_jsx_runtime38.jsxs)("div", { className: "h-40 relative p-6 flex flex-col justify-end overflow-hidden", style: {
                background: preview.background || "linear-gradient(145deg, #1a1a20 0%, #0b0b0d 100%)",
                backgroundSize: "cover",
                backgroundPosition: "center"
              }, children: [
                /* @__PURE__ */ (0, import_jsx_runtime38.jsx)("div", { className: "absolute top-0 right-0 p-4 opacity-20 group-hover:scale-110 transition-transform", children: /* @__PURE__ */ (0, import_jsx_runtime38.jsx)("i", { className: "bi bi-palette2 text-8xl text-white" }) }),
                /* @__PURE__ */ (0, import_jsx_runtime38.jsxs)("div", { className: "relative z-10 flex flex-col gap-1", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime38.jsx)("span", { className: "text-[10px] font-black text-white/50 uppercase tracking-widest", children: preview.eyebrow || "PRESET" }),
                  /* @__PURE__ */ (0, import_jsx_runtime38.jsx)("h3", { className: "text-lg font-bold text-white leading-tight", children: theme.label })
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime38.jsx)("div", { className: "absolute right-6 bottom-6 flex flex-col gap-2", children: swatches.map((color, idx) => /* @__PURE__ */ (0, import_jsx_runtime38.jsx)("div", { className: "w-8 h-8 rounded-lg border border-white/20 shadow-lg", style: { backgroundColor: color } }, idx)) })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime38.jsxs)("div", { className: "p-5 flex flex-col gap-4", children: [
                /* @__PURE__ */ (0, import_jsx_runtime38.jsxs)("div", { className: "flex items-start justify-between", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime38.jsx)("p", { className: "text-sm text-neutral-400 line-clamp-2 pr-4", children: preview.summary || "Custom theme profile for CPanel Rocky surface." }),
                  isCurrent && /* @__PURE__ */ (0, import_jsx_runtime38.jsx)("span", { className: "shrink-0 bg-primary-500/10 text-primary-400 border border-primary-500/20 text-[10px] font-black px-2 py-0.5 rounded", children: "ACTIVE" })
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime38.jsxs)("div", { className: "flex items-center gap-2 mt-auto", children: [
                  /* @__PURE__ */ (0, import_jsx_runtime38.jsxs)(
                    "button",
                    {
                      onClick: () => handlePreview(theme),
                      className: `flex-1 text-xs font-bold py-2 rounded border transition-all ${isPreviewing ? "bg-yellow-500/20 border-yellow-500/40 text-yellow-400" : "bg-neutral-900 border-neutral-700 text-neutral-400 hover:text-white hover:border-neutral-600"}`,
                      children: [
                        /* @__PURE__ */ (0, import_jsx_runtime38.jsx)("i", { className: `bi ${isPreviewing ? "bi-eye-slash" : "bi-eye"} mr-2` }),
                        isPreviewing ? "Stop Preview" : "Preview"
                      ]
                    }
                  ),
                  /* @__PURE__ */ (0, import_jsx_runtime38.jsxs)(
                    "button",
                    {
                      onClick: () => handleApply(theme.id),
                      disabled: isCurrent,
                      className: "flex-1 bg-primary-600 hover:bg-primary-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-bold py-2 rounded shadow-sm transition-all",
                      children: [
                        /* @__PURE__ */ (0, import_jsx_runtime38.jsx)("i", { className: "bi bi-check2 mr-2" }),
                        "Apply"
                      ]
                    }
                  )
                ] })
              ] })
            ] }, theme.id);
          }) })
        ]
      }
    ) });
  }
  if (root26) {
    root26.render(
      /* @__PURE__ */ (0, import_jsx_runtime38.jsx)(BrowserRouter, { children: /* @__PURE__ */ (0, import_jsx_runtime38.jsx)(ThemeProvider2, { pageData: data26, children: /* @__PURE__ */ (0, import_jsx_runtime38.jsx)(ThemesPage, { pageData: data26 }) }) })
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === "function") {
      window.__CPANEL_REACT_BOOTED__();
    }
  }

  // views/react/rewards.jsx
  var import_react39 = __toESM(require_react());
  var import_client27 = __toESM(require_client());
  var import_jsx_runtime39 = __toESM(require_jsx_runtime());
  var data27 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry27 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "rewards";
  var root27 = standaloneEntry27 ? (0, import_client27.createRoot)(document.getElementById("reactRoot")) : null;
  var compactFormatter = new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 });
  function formatRemaining(period, seconds) {
    if (seconds <= 0) return "Ready";
    let s = seconds;
    const d = Math.floor(s / 86400);
    s -= d * 86400;
    const h = Math.floor(s / 3600);
    s -= h * 3600;
    const m = Math.floor(s / 60);
    s -= m * 60;
    if (period === "minute") return `${m}m ${s}s`;
    if (period === "hour") return `${h}h ${m}m ${s}s`;
    if (period === "day") return `${d}d ${h}h ${m}m`;
    if (period === "week") return `${d}d ${h}h`;
    if (period === "month") return `${d}d ${h}h`;
    if (period === "year") {
      const months = Math.floor(d / 30);
      const days = d % 30;
      return `${months}mo ${days}d`;
    }
    return `${d}d ${h}h ${m}m`;
  }
  function RewardsPage({ pageData = data27 }) {
    const [coins, setCoins] = import_react39.default.useState(Number(pageData.user?.coins || 0));
    const [dailyStreak, setDailyStreak] = import_react39.default.useState(Number(pageData.dailyStreak || 0));
    const [streakResetSeconds, setStreakResetSeconds] = import_react39.default.useState(Number(pageData.streakResetSeconds || 0));
    const [claimRemaining, setClaimRemaining] = import_react39.default.useState(pageData.claimRemainingByPeriod || {});
    const [claiming, setClaiming] = import_react39.default.useState(null);
    const [status, setStatus] = import_react39.default.useState("Ready");
    import_react39.default.useEffect(() => {
      const interval = setInterval(() => {
        setStreakResetSeconds((prev) => prev > 0 ? prev - 1 : 0);
        setClaimRemaining((prev) => {
          const next = { ...prev };
          let changed = false;
          Object.keys(next).forEach((k) => {
            if (next[k] > 0) {
              next[k] -= 1;
              changed = true;
            }
          });
          return changed ? next : prev;
        });
      }, 1e3);
      return () => clearInterval(interval);
    }, []);
    const handleClaim = async (period) => {
      setClaiming(period);
      try {
        const response = await fetch("/rewards/claim", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ period })
        });
        const payload = await response.json();
        if (!response.ok || !payload.success) {
          if (payload.remainingSeconds !== void 0) {
            setClaimRemaining((prev) => ({ ...prev, [period]: Math.max(0, payload.remainingSeconds) }));
          }
          throw new Error(payload.error || "Claim failed.");
        }
        if (payload.coins !== void 0) setCoins(payload.coins);
        if (payload.dailyStreak !== void 0) setDailyStreak(payload.dailyStreak);
        if (payload.remainingSeconds !== void 0) {
          setClaimRemaining((prev) => ({ ...prev, [period]: Math.max(0, payload.remainingSeconds) }));
        }
        setStreakResetSeconds(86400);
        setStatus(`Claimed +${compactFormatter.format(payload.awardedCoins || 0)} ${payload.economyUnit || pageData.economyUnit}`);
        setTimeout(() => setStatus("Ready"), 5e3);
      } catch (error) {
        setStatus(error.message);
      } finally {
        setClaiming(null);
      }
    };
    const cards = [
      { key: "minute", label: "Minutes" },
      { key: "hour", label: "Hours" },
      { key: "day", label: "Days" },
      { key: "week", label: "Weekly" },
      { key: "month", label: "Monthly" },
      { key: "year", label: "Yearly" }
    ];
    return /* @__PURE__ */ (0, import_jsx_runtime39.jsx)(ReactAppShell, { pageData, subtitle: "Rewards Center", children: /* @__PURE__ */ (0, import_jsx_runtime39.jsxs)(
      PageContentBlock,
      {
        title: "Rewards",
        description: "Claim rewards at various intervals and keep your daily streak active.",
        actions: /* @__PURE__ */ (0, import_jsx_runtime39.jsxs)("div", { className: "flex gap-2", children: [
          /* @__PURE__ */ (0, import_jsx_runtime39.jsxs)(Link, { to: ReactRoutes.afk, className: "bg-neutral-800 hover:bg-neutral-700 text-neutral-300 text-xs font-bold py-1.5 px-3 rounded border border-neutral-700 transition-colors flex items-center gap-2", children: [
            /* @__PURE__ */ (0, import_jsx_runtime39.jsx)("i", { className: "bi bi-hourglass-split" }),
            " AFK Timer"
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime39.jsxs)(Link, { to: ReactRoutes.dashboard, className: "bg-neutral-800 hover:bg-neutral-700 text-neutral-300 text-xs font-bold py-1.5 px-3 rounded border border-neutral-700 transition-colors flex items-center gap-2", children: [
            /* @__PURE__ */ (0, import_jsx_runtime39.jsx)("i", { className: "bi bi-house-door" }),
            " Home"
          ] })
        ] }),
        children: [
          /* @__PURE__ */ (0, import_jsx_runtime39.jsxs)("div", { className: "grid grid-cols-1 md:grid-cols-3 gap-6 mb-8", children: [
            /* @__PURE__ */ (0, import_jsx_runtime39.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-xl p-5 shadow-sm", children: [
              /* @__PURE__ */ (0, import_jsx_runtime39.jsx)("span", { className: "block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-1", children: "Total Balance" }),
              /* @__PURE__ */ (0, import_jsx_runtime39.jsxs)("div", { className: "text-2xl font-black text-white flex items-baseline gap-2", children: [
                compactFormatter.format(coins),
                /* @__PURE__ */ (0, import_jsx_runtime39.jsx)("span", { className: "text-xs font-bold text-neutral-500", children: pageData.economyUnit })
              ] })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime39.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-xl p-5 shadow-sm", children: [
              /* @__PURE__ */ (0, import_jsx_runtime39.jsx)("span", { className: "block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-1", children: "Daily Streak" }),
              /* @__PURE__ */ (0, import_jsx_runtime39.jsxs)("div", { className: "text-2xl font-black text-blue-400", children: [
                dailyStreak,
                " Days"
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime39.jsxs)("div", { className: "text-[10px] text-neutral-500 mt-1 uppercase tracking-tight", children: [
                "Bonus: +",
                pageData.claimDailyStreakBonusCoins || 0,
                " / day"
              ] })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime39.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-xl p-5 shadow-sm", children: [
              /* @__PURE__ */ (0, import_jsx_runtime39.jsx)("span", { className: "block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-1", children: "Streak Reset" }),
              /* @__PURE__ */ (0, import_jsx_runtime39.jsx)("div", { className: "text-2xl font-black text-neutral-200", children: dailyStreak > 0 ? streakResetSeconds > 0 ? formatRemaining("day", streakResetSeconds) : "Expired" : "No streak" })
            ] })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime39.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-lg px-4 py-3 mb-8 flex justify-between items-center", children: [
            /* @__PURE__ */ (0, import_jsx_runtime39.jsx)("h2", { className: "text-xs font-black text-neutral-400 uppercase tracking-widest", children: "Global Claim Status" }),
            /* @__PURE__ */ (0, import_jsx_runtime39.jsx)("span", { className: `text-xs font-bold ${status.includes("Claimed") ? "text-green-400" : "text-neutral-500"}`, children: status })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime39.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-xl p-6 mb-8", children: [
            /* @__PURE__ */ (0, import_jsx_runtime39.jsx)("h2", { className: "text-sm font-black text-neutral-200 uppercase tracking-[0.1em] mb-4", children: "Streak Calendar" }),
            /* @__PURE__ */ (0, import_jsx_runtime39.jsx)("div", { className: "grid grid-cols-7 gap-3", children: Array.from({ length: 7 }).map((_, i) => /* @__PURE__ */ (0, import_jsx_runtime39.jsxs)("div", { className: `h-16 rounded-lg border-2 flex flex-col items-center justify-center gap-1 transition-all ${dailyStreak > i ? "bg-blue-600/10 border-blue-600/50 text-blue-400 font-bold" : "bg-neutral-900 border-neutral-700 text-neutral-600 opacity-50"}`, children: [
              /* @__PURE__ */ (0, import_jsx_runtime39.jsx)("span", { className: dailyStreak > i ? "text-lg" : "text-sm", children: /* @__PURE__ */ (0, import_jsx_runtime39.jsx)("i", { className: dailyStreak > i ? "bi bi-check-circle-fill" : "bi bi-circle" }) }),
              /* @__PURE__ */ (0, import_jsx_runtime39.jsxs)("span", { className: "text-[9px] uppercase font-black", children: [
                "Day ",
                i + 1
              ] })
            ] }, i)) })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime39.jsx)("div", { className: "grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6", children: cards.map((card) => {
            const remaining = claimRemaining[card.key] || 0;
            const isReady = remaining <= 0;
            const isClaiming = claiming === card.key;
            const rewardValue = pageData.rewardsMap ? pageData.rewardsMap[card.key] : 0;
            return /* @__PURE__ */ (0, import_jsx_runtime39.jsxs)("div", { className: `relative bg-neutral-800 border rounded-xl p-6 flex flex-col gap-4 transition-all ${isReady ? "border-primary-500/50 shadow-md ring-1 ring-primary-500/10" : "border-neutral-700 opacity-80 shadow-sm"}`, children: [
              /* @__PURE__ */ (0, import_jsx_runtime39.jsxs)("div", { className: "flex justify-between items-start", children: [
                /* @__PURE__ */ (0, import_jsx_runtime39.jsx)("h3", { className: "text-sm font-black text-neutral-100 uppercase tracking-widest", children: card.label }),
                isReady && /* @__PURE__ */ (0, import_jsx_runtime39.jsx)("span", { className: "bg-green-500/20 text-green-400 text-[10px] font-black px-2 py-0.5 rounded animate-pulse", children: "READY" })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime39.jsxs)("div", { className: "py-2", children: [
                /* @__PURE__ */ (0, import_jsx_runtime39.jsxs)("div", { className: "text-2xl font-black text-white", children: [
                  "+",
                  compactFormatter.format(rewardValue),
                  " ",
                  /* @__PURE__ */ (0, import_jsx_runtime39.jsx)("span", { className: "text-xs text-neutral-500 uppercase", children: pageData.economyUnit })
                ] }),
                /* @__PURE__ */ (0, import_jsx_runtime39.jsxs)("div", { className: "text-xs text-neutral-400 mt-1", children: [
                  "Remaining: ",
                  /* @__PURE__ */ (0, import_jsx_runtime39.jsx)("span", { className: "font-mono text-neutral-200", children: formatRemaining(card.key, remaining) })
                ] })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime39.jsx)(
                "button",
                {
                  onClick: () => handleClaim(card.key),
                  disabled: !isReady || isClaiming || rewardValue <= 0,
                  className: `w-full py-2.5 rounded text-sm font-bold shadow-sm transition-all flex items-center justify-center gap-2 ${isReady ? "bg-primary-600 hover:bg-primary-500 text-white" : "bg-neutral-700 text-neutral-500 cursor-not-allowed"}`,
                  children: isClaiming ? /* @__PURE__ */ (0, import_jsx_runtime39.jsx)("span", { className: "w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" }) : /* @__PURE__ */ (0, import_jsx_runtime39.jsxs)(import_jsx_runtime39.Fragment, { children: [
                    /* @__PURE__ */ (0, import_jsx_runtime39.jsx)("i", { className: "bi bi-box-arrow-in-down" }),
                    " Claim"
                  ] })
                }
              )
            ] }, card.key);
          }) })
        ]
      }
    ) });
  }
  if (root27) {
    root27.render(
      /* @__PURE__ */ (0, import_jsx_runtime39.jsx)(ThemeContext_default, { pageData: data27, children: /* @__PURE__ */ (0, import_jsx_runtime39.jsx)(BrowserRouter, { children: /* @__PURE__ */ (0, import_jsx_runtime39.jsx)(RewardsPage, { pageData: data27 }) }) })
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === "function") {
      window.__CPANEL_REACT_BOOTED__();
    }
  }

  // views/react/afk.jsx
  var import_react40 = __toESM(require_react());
  var import_client28 = __toESM(require_client());
  var import_jsx_runtime40 = __toESM(require_jsx_runtime());
  var data28 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry28 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "afk";
  var root28 = standaloneEntry28 ? (0, import_client28.createRoot)(document.getElementById("reactRoot")) : null;
  var compactFormatter2 = new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 });
  function AFKPage({ pageData = data28 }) {
    const [coins, setCoins] = import_react40.default.useState(Number(pageData.user?.coins || 0));
    const [afkRemainingSeconds, setAfkRemainingSeconds] = import_react40.default.useState(Number(pageData.afkRemainingSeconds || 0));
    const [status, setStatus] = import_react40.default.useState("Initializing...");
    const pingAfk = async () => {
      if (!pageData.afkTimerEnabled) return;
      try {
        const response = await fetch("/afk/ping", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: "{}"
        });
        const payload = await response.json();
        if (!response.ok || !payload.success) {
          throw new Error(payload.error || "AFK ping failed");
        }
        if (payload.remainingSeconds !== void 0) {
          setAfkRemainingSeconds(Math.max(0, payload.remainingSeconds));
        }
        if (payload.coins !== void 0) {
          setCoins(payload.coins);
        }
        if (payload.awarded && Number(payload.awardedCoins) > 0) {
          setStatus(`+${payload.awardedCoins} ${payload.economyUnit || pageData.economyUnit} awarded`);
          setTimeout(() => setStatus("AFK heartbeat synced"), 5e3);
        } else {
          setStatus("AFK heartbeat synced");
        }
      } catch (error) {
        setStatus(error.message || "AFK ping error");
      }
    };
    import_react40.default.useEffect(() => {
      pingAfk();
      const tickInterval = setInterval(() => {
        setAfkRemainingSeconds((prev) => prev > 0 ? prev - 1 : 0);
      }, 1e3);
      const pingInterval = setInterval(() => {
        pingAfk();
      }, 1e4);
      return () => {
        clearInterval(tickInterval);
        clearInterval(pingInterval);
      };
    }, []);
    return /* @__PURE__ */ (0, import_jsx_runtime40.jsx)(ReactAppShell, { pageData, subtitle: "AFK Rewards", children: /* @__PURE__ */ (0, import_jsx_runtime40.jsxs)(
      PageContentBlock,
      {
        title: "AFK Timer",
        description: "Stay on this page to automatically earn coins at the configured interval.",
        actions: /* @__PURE__ */ (0, import_jsx_runtime40.jsxs)("div", { className: "flex gap-2", children: [
          /* @__PURE__ */ (0, import_jsx_runtime40.jsxs)(Link, { to: ReactRoutes.rewards, className: "bg-neutral-800 hover:bg-neutral-700 text-neutral-300 text-xs font-bold py-1.5 px-3 rounded border border-neutral-700 transition-colors flex items-center gap-2", children: [
            /* @__PURE__ */ (0, import_jsx_runtime40.jsx)("i", { className: "bi bi-coin" }),
            " Rewards"
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime40.jsxs)(Link, { to: ReactRoutes.dashboard, className: "bg-neutral-800 hover:bg-neutral-700 text-neutral-300 text-xs font-bold py-1.5 px-3 rounded border border-neutral-700 transition-colors flex items-center gap-2", children: [
            /* @__PURE__ */ (0, import_jsx_runtime40.jsx)("i", { className: "bi bi-house-door" }),
            " Home"
          ] })
        ] }),
        children: [
          /* @__PURE__ */ (0, import_jsx_runtime40.jsxs)("div", { className: "grid grid-cols-1 md:grid-cols-3 gap-6 mb-8", children: [
            /* @__PURE__ */ (0, import_jsx_runtime40.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-xl p-6 shadow-sm", children: [
              /* @__PURE__ */ (0, import_jsx_runtime40.jsx)("span", { className: "block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-1", children: "Your Wallet" }),
              /* @__PURE__ */ (0, import_jsx_runtime40.jsxs)("div", { className: "text-3xl font-black text-white flex items-baseline gap-2", children: [
                compactFormatter2.format(coins),
                /* @__PURE__ */ (0, import_jsx_runtime40.jsx)("span", { className: "text-xs font-bold text-neutral-500 uppercase", children: pageData.economyUnit })
              ] })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime40.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-xl p-6 shadow-sm ring-2 ring-primary-500/20", children: [
              /* @__PURE__ */ (0, import_jsx_runtime40.jsx)("span", { className: "block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-1", children: "Next Reward In" }),
              /* @__PURE__ */ (0, import_jsx_runtime40.jsxs)("div", { className: "text-3xl font-black text-primary-400 font-mono tracking-tighter", children: [
                afkRemainingSeconds,
                "s"
              ] })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime40.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-xl p-6 shadow-sm", children: [
              /* @__PURE__ */ (0, import_jsx_runtime40.jsx)("span", { className: "block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-1", children: "Reward Value" }),
              /* @__PURE__ */ (0, import_jsx_runtime40.jsxs)("div", { className: "text-3xl font-black text-neutral-200", children: [
                "+",
                compactFormatter2.format(pageData.afkTimerCoins || 0)
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime40.jsxs)("div", { className: "text-[10px] text-neutral-500 mt-1 uppercase tracking-tight", children: [
                "Interval: ",
                pageData.afkTimerCooldownSeconds || 60,
                "s"
              ] })
            ] })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime40.jsxs)("div", { className: "bg-neutral-800 border border-neutral-700 rounded-2xl p-10 flex flex-col items-center justify-center text-center gap-6 relative overflow-hidden", children: [
            /* @__PURE__ */ (0, import_jsx_runtime40.jsx)("div", { className: "absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-primary-500 to-transparent opacity-20 animate-pulse" }),
            /* @__PURE__ */ (0, import_jsx_runtime40.jsx)("div", { className: "absolute -bottom-24 -right-24 w-64 h-64 bg-primary-500/5 rounded-full blur-3xl" }),
            /* @__PURE__ */ (0, import_jsx_runtime40.jsx)("div", { className: "absolute -top-24 -left-24 w-64 h-64 bg-primary-500/5 rounded-full blur-3xl" }),
            /* @__PURE__ */ (0, import_jsx_runtime40.jsxs)("div", { className: "relative", children: [
              /* @__PURE__ */ (0, import_jsx_runtime40.jsx)("div", { className: "w-24 h-24 rounded-full bg-primary-500/10 border border-primary-500/20 flex items-center justify-center mb-2", children: /* @__PURE__ */ (0, import_jsx_runtime40.jsx)("i", { className: "bi bi-hourglass-split text-4xl text-primary-400 animate-spin-slow" }) }),
              /* @__PURE__ */ (0, import_jsx_runtime40.jsx)("div", { className: "absolute -top-1 -right-1", children: /* @__PURE__ */ (0, import_jsx_runtime40.jsx)("div", { className: "w-4 h-4 bg-green-500 rounded-full border-4 border-neutral-800 animate-pulse" }) })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime40.jsxs)("div", { children: [
              /* @__PURE__ */ (0, import_jsx_runtime40.jsx)("h2", { className: "text-xl font-bold text-white mb-2", children: "AFK Monitoring Active" }),
              /* @__PURE__ */ (0, import_jsx_runtime40.jsx)("p", { className: "text-sm text-neutral-400 max-w-md mx-auto", children: "As long as this tab remains open and active, your session is being monitored. The heartbeat system confirms your presence every 10 seconds." })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime40.jsx)("div", { className: "bg-neutral-900 px-6 py-2 rounded-full border border-neutral-700 shadow-inner", children: /* @__PURE__ */ (0, import_jsx_runtime40.jsx)("span", { className: `text-xs font-black uppercase tracking-widest ${status.includes("awarded") ? "text-green-400" : "text-neutral-500"}`, children: status }) }),
            !pageData.afkTimerEnabled && /* @__PURE__ */ (0, import_jsx_runtime40.jsxs)("div", { className: "mt-4 bg-red-600/10 border border-red-600/20 text-red-400 px-4 py-2 rounded-lg text-xs font-bold", children: [
              /* @__PURE__ */ (0, import_jsx_runtime40.jsx)("i", { className: "bi bi-exclamation-triangle-fill mr-2" }),
              "AFK Timer is currently disabled by administrator."
            ] })
          ] })
        ]
      }
    ) });
  }
  if (root28) {
    root28.render(
      /* @__PURE__ */ (0, import_jsx_runtime40.jsx)(ThemeContext_default, { pageData: data28, children: /* @__PURE__ */ (0, import_jsx_runtime40.jsx)(BrowserRouter, { children: /* @__PURE__ */ (0, import_jsx_runtime40.jsx)(AFKPage, { pageData: data28 }) }) })
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === "function") {
      window.__CPANEL_REACT_BOOTED__();
    }
  }

  // views/react/notifications.jsx
  var import_react41 = __toESM(require_react());
  var import_client29 = __toESM(require_client());
  var import_jsx_runtime41 = __toESM(require_jsx_runtime());
  var data29 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry29 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "notifications";
  var root29 = standaloneEntry29 ? (0, import_client29.createRoot)(document.getElementById("reactRoot")) : null;
  function getSeverityTheme(severity) {
    const s = String(severity || "info").toLowerCase();
    if (s === "danger" || s === "error" || s === "critical") {
      return { icon: "bi-exclamation-octagon-fill", color: "text-red-500", bg: "bg-red-500/10", border: "border-red-500/20" };
    }
    if (s === "warning") {
      return { icon: "bi-exclamation-triangle-fill", color: "text-yellow-500", bg: "bg-yellow-500/10", border: "border-yellow-500/20" };
    }
    if (s === "success") {
      return { icon: "bi-check-circle-fill", color: "text-green-500", bg: "bg-green-500/10", border: "border-green-500/20" };
    }
    return { icon: "bi-info-circle-fill", color: "text-blue-500", bg: "bg-blue-500/10", border: "border-blue-500/20" };
  }
  function NotificationsPage({ pageData = data29 }) {
    const [notifications, setNotifications] = import_react41.default.useState(Array.isArray(pageData.notifications) ? pageData.notifications : []);
    const [unreadCount, setUnreadCount] = import_react41.default.useState(Number(pageData.unreadCount || 0));
    const [processing, setProcessing] = import_react41.default.useState(false);
    const markRead = async (id) => {
      try {
        const response = await fetch(`/api/account/notifications/${id}/read`, { method: "POST" });
        const result = await response.json();
        if (response.ok) {
          setNotifications((prev) => prev.map((n) => n.id === id ? { ...n, isRead: true } : n));
          setUnreadCount(result.unreadCount);
        }
      } catch (error) {
        console.error("Failed to mark notification as read:", error);
      }
    };
    const markAllRead = async () => {
      if (processing) return;
      setProcessing(true);
      try {
        const response = await fetch("/api/account/notifications/read-all", { method: "POST" });
        const result = await response.json();
        if (response.ok) {
          setNotifications((prev) => prev.map((n) => ({ ...n, isRead: true })));
          setUnreadCount(0);
        }
      } catch (error) {
        console.error("Failed to mark all as read:", error);
      } finally {
        setProcessing(false);
      }
    };
    return /* @__PURE__ */ (0, import_jsx_runtime41.jsx)(ReactAppShell, { pageData: { ...pageData, user: { ...pageData.user, notificationUnreadCount: unreadCount } }, subtitle: "User Notifications", children: /* @__PURE__ */ (0, import_jsx_runtime41.jsxs)(
      PageContentBlock,
      {
        title: "Notifications",
        description: "Stay informed about your servers, security events, and platform updates.",
        children: [
          /* @__PURE__ */ (0, import_jsx_runtime41.jsxs)("div", { className: "flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-8", children: [
            /* @__PURE__ */ (0, import_jsx_runtime41.jsxs)("div", { children: [
              /* @__PURE__ */ (0, import_jsx_runtime41.jsxs)("div", { className: "flex items-center gap-3", children: [
                /* @__PURE__ */ (0, import_jsx_runtime41.jsx)("h2", { className: "text-2xl font-black text-white uppercase tracking-tight", children: "Activity Feed" }),
                unreadCount > 0 && /* @__PURE__ */ (0, import_jsx_runtime41.jsxs)("span", { className: "bg-primary-600 text-white text-[10px] font-black px-2 py-0.5 rounded-full uppercase tracking-widest animate-pulse", children: [
                  unreadCount,
                  " Unread"
                ] })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime41.jsx)("p", { className: "text-xs text-neutral-500 font-bold uppercase tracking-widest mt-1", children: "Viewing your 100 most recent alerts" })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime41.jsxs)("div", { className: "flex gap-2 w-full sm:w-auto", children: [
              /* @__PURE__ */ (0, import_jsx_runtime41.jsx)(
                "button",
                {
                  onClick: markAllRead,
                  disabled: unreadCount === 0 || processing,
                  className: `flex-1 sm:flex-none px-6 py-2.5 rounded-xl text-[10px] font-black uppercase tracking-[0.2em] transition-all border ${unreadCount > 0 ? "bg-neutral-800 border-neutral-700 text-white hover:bg-neutral-700 active:scale-95" : "bg-neutral-900 border-neutral-800 text-neutral-700 cursor-not-allowed"}`,
                  children: processing ? "Processing..." : "Mark All Read"
                }
              ),
              /* @__PURE__ */ (0, import_jsx_runtime41.jsx)(
                "a",
                {
                  href: "/account",
                  className: "px-4 py-2.5 bg-neutral-800 border border-neutral-700 rounded-xl text-neutral-400 hover:text-white transition-colors flex items-center justify-center",
                  title: "Notification Settings",
                  children: /* @__PURE__ */ (0, import_jsx_runtime41.jsx)("i", { className: "bi bi-gear-fill" })
                }
              )
            ] })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime41.jsx)("div", { className: "space-y-3", children: notifications.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime41.jsxs)("div", { className: "py-24 flex flex-col items-center justify-center bg-neutral-800/20 border border-neutral-800/50 border-dashed rounded-[2.5rem]", children: [
            /* @__PURE__ */ (0, import_jsx_runtime41.jsx)("div", { className: "w-20 h-20 bg-neutral-800 rounded-3xl flex items-center justify-center mb-6 shadow-2xl", children: /* @__PURE__ */ (0, import_jsx_runtime41.jsx)("i", { className: "bi bi-bell-slash text-3xl text-neutral-600" }) }),
            /* @__PURE__ */ (0, import_jsx_runtime41.jsx)("h3", { className: "text-lg font-bold text-neutral-400 uppercase tracking-widest", children: "Peace and Quiet" }),
            /* @__PURE__ */ (0, import_jsx_runtime41.jsx)("p", { className: "text-xs text-neutral-600 font-bold uppercase tracking-[0.15em] mt-2 text-center max-w-xs", children: "No new notifications at the moment. We'll alert you if anything requires your attention." })
          ] }) : notifications.map((notif, idx) => {
            const theme = getSeverityTheme(notif.severity);
            return /* @__PURE__ */ (0, import_jsx_runtime41.jsxs)(
              "div",
              {
                className: `group relative overflow-hidden bg-neutral-800/40 border transition-all duration-300 rounded-2xl p-5 sm:p-6 ${notif.isRead ? "border-neutral-800/50 opacity-60" : `${theme.border} hover:border-neutral-600 shadow-xl`}`,
                children: [
                  !notif.isRead && /* @__PURE__ */ (0, import_jsx_runtime41.jsx)("div", { className: `absolute top-0 left-0 w-1 h-full ${theme.color.replace("text", "bg")}` }),
                  /* @__PURE__ */ (0, import_jsx_runtime41.jsxs)("div", { className: "flex gap-5 items-start", children: [
                    /* @__PURE__ */ (0, import_jsx_runtime41.jsx)("div", { className: `shrink-0 w-12 h-12 rounded-xl flex items-center justify-center text-xl ${theme.bg} ${theme.color} border ${theme.border} transition-transform group-hover:scale-110`, children: /* @__PURE__ */ (0, import_jsx_runtime41.jsx)("i", { className: `bi ${theme.icon}` }) }),
                    /* @__PURE__ */ (0, import_jsx_runtime41.jsxs)("div", { className: "flex-1 min-w-0", children: [
                      /* @__PURE__ */ (0, import_jsx_runtime41.jsxs)("div", { className: "flex flex-wrap items-center gap-3 mb-2", children: [
                        /* @__PURE__ */ (0, import_jsx_runtime41.jsx)("h4", { className: `text-sm font-black uppercase tracking-widest truncate ${notif.isRead ? "text-neutral-400" : "text-white"}`, children: notif.title }),
                        /* @__PURE__ */ (0, import_jsx_runtime41.jsx)("span", { className: "text-[10px] font-bold text-neutral-600 uppercase tracking-widest", children: new Date(notif.createdAt).toLocaleString() })
                      ] }),
                      /* @__PURE__ */ (0, import_jsx_runtime41.jsx)("div", { className: `text-xs leading-relaxed font-medium mb-4 whitespace-pre-wrap ${notif.isRead ? "text-neutral-500" : "text-neutral-300"}`, children: notif.message }),
                      /* @__PURE__ */ (0, import_jsx_runtime41.jsxs)("div", { className: "flex flex-wrap items-center gap-4", children: [
                        notif.linkUrl && /* @__PURE__ */ (0, import_jsx_runtime41.jsx)(
                          "a",
                          {
                            href: notif.linkUrl,
                            className: "px-4 py-1.5 bg-primary-600/10 hover:bg-primary-600/20 text-primary-400 text-[10px] font-black uppercase tracking-widest rounded-lg transition-colors border border-primary-500/20",
                            children: "View Details"
                          }
                        ),
                        !notif.isRead && /* @__PURE__ */ (0, import_jsx_runtime41.jsx)(
                          "button",
                          {
                            onClick: () => markRead(notif.id),
                            className: "text-[10px] font-black text-neutral-500 hover:text-white uppercase tracking-[0.2em] transition-colors",
                            children: "Mark as Read"
                          }
                        )
                      ] })
                    ] })
                  ] })
                ]
              },
              notif.id || idx
            );
          }) })
        ]
      }
    ) });
  }
  if (root29) {
    root29.render(
      /* @__PURE__ */ (0, import_jsx_runtime41.jsx)(ThemeContext_default, { pageData: data29, children: /* @__PURE__ */ (0, import_jsx_runtime41.jsx)(BrowserRouter, { children: /* @__PURE__ */ (0, import_jsx_runtime41.jsx)(NotificationsPage, { pageData: data29 }) }) })
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === "function") {
      window.__CPANEL_REACT_BOOTED__();
    }
  }

  // views/react/experimental-features.jsx
  var import_react42 = __toESM(require_react());
  var import_client30 = __toESM(require_client());
  var import_jsx_runtime42 = __toESM(require_jsx_runtime());
  var data30 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry30 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "experimental-features";
  var root30 = standaloneEntry30 ? (0, import_client30.createRoot)(document.getElementById("reactRoot")) : null;
  function MetricItem({ title, value, note, active }) {
    return /* @__PURE__ */ (0, import_jsx_runtime42.jsxs)("div", { className: "bg-neutral-900/50 border border-neutral-700/50 rounded-lg p-4", children: [
      /* @__PURE__ */ (0, import_jsx_runtime42.jsxs)("div", { className: "flex justify-between items-center mb-1", children: [
        /* @__PURE__ */ (0, import_jsx_runtime42.jsx)("span", { className: "text-xs font-bold text-neutral-500 uppercase tracking-wide", children: title }),
        /* @__PURE__ */ (0, import_jsx_runtime42.jsx)("strong", { className: `text-sm ${active ? "text-primary-400" : "text-neutral-300"}`, children: value })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime42.jsx)("div", { className: "text-xs text-neutral-500", children: note })
    ] });
  }
  function ExperimentalFeaturesPage({ pageData = data30 }) {
    const user = pageData.user || {};
    const aiAvailable = Boolean(pageData.aiAdminEnabled && pageData.aiProviderReady);
    return /* @__PURE__ */ (0, import_jsx_runtime42.jsx)(ReactAppShell, { pageData, subtitle: "Outdated features", children: /* @__PURE__ */ (0, import_jsx_runtime42.jsxs)(PageContentBlock, { title: "Outdated Features", children: [
      /* @__PURE__ */ (0, import_jsx_runtime42.jsxs)("div", { className: "bg-red-600/20 border border-red-600/50 text-red-100 p-4 rounded-lg mb-6 shadow-sm flex items-center gap-3", children: [
        /* @__PURE__ */ (0, import_jsx_runtime42.jsx)("i", { className: "bi bi-info-circle text-xl" }),
        /* @__PURE__ */ (0, import_jsx_runtime42.jsxs)("div", { children: [
          /* @__PURE__ */ (0, import_jsx_runtime42.jsx)("strong", { className: "block", children: "Notice" }),
          /* @__PURE__ */ (0, import_jsx_runtime42.jsx)("p", { className: "text-sm", children: "Sorry but features that were added here will still be working but wont be updated anymore" })
        ] })
      ] }),
      pageData.success && /* @__PURE__ */ (0, import_jsx_runtime42.jsx)("div", { className: "bg-green-600/20 border border-green-600/50 text-green-100 p-4 rounded-lg mb-6 shadow-sm", children: pageData.success }),
      pageData.error && /* @__PURE__ */ (0, import_jsx_runtime42.jsx)("div", { className: "bg-red-600/20 border border-red-600/50 text-red-100 p-4 rounded-lg mb-6 shadow-sm", children: pageData.error }),
      /* @__PURE__ */ (0, import_jsx_runtime42.jsxs)("div", { className: "grid grid-cols-1 lg:grid-cols-2 gap-6", children: [
        /* @__PURE__ */ (0, import_jsx_runtime42.jsxs)("section", { className: "bg-neutral-800 border border-neutral-700 rounded-lg p-6 flex flex-col hover:border-neutral-500 transition-colors", children: [
          /* @__PURE__ */ (0, import_jsx_runtime42.jsxs)("div", { className: "flex justify-between items-start mb-4", children: [
            /* @__PURE__ */ (0, import_jsx_runtime42.jsxs)("div", { children: [
              /* @__PURE__ */ (0, import_jsx_runtime42.jsx)("h2", { className: "text-lg font-bold text-neutral-100", children: "React View Mode" }),
              /* @__PURE__ */ (0, import_jsx_runtime42.jsx)("p", { className: "text-sm text-neutral-400 mt-1", children: "Switch between the stable EJS renderer and the React beta renderer for migrated pages." })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime42.jsx)("span", { className: `px-2 py-1 rounded text-xs font-semibold uppercase tracking-wide shrink-0 ml-4 ${pageData.currentViewMode === "react" ? "bg-primary-600 text-white" : "bg-neutral-700 text-neutral-400"}`, children: pageData.currentViewMode === "react" ? "React Active" : "EJS Active" })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime42.jsx)("div", { className: "mt-auto pt-4", children: /* @__PURE__ */ (0, import_jsx_runtime42.jsx)(Link, { to: ReactRoutes.changeView, className: "inline-block bg-primary-600 hover:bg-primary-500 text-white font-semibold py-2 px-6 rounded transition-colors text-sm shadow-sm", children: "Open Change View" }) })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime42.jsxs)("section", { className: "bg-neutral-800 border border-neutral-700 rounded-lg p-6 flex flex-col hover:border-neutral-500 transition-colors", children: [
          /* @__PURE__ */ (0, import_jsx_runtime42.jsxs)("div", { className: "mb-4", children: [
            /* @__PURE__ */ (0, import_jsx_runtime42.jsx)("h2", { className: "text-lg font-bold text-neutral-100", children: "AI Agents" }),
            /* @__PURE__ */ (0, import_jsx_runtime42.jsx)("p", { className: "text-sm text-neutral-400 mt-1", children: "User-side AI is controlled both by admin configuration and your own opt-in setting." })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime42.jsxs)("div", { className: "grid grid-cols-1 sm:grid-cols-2 gap-3 mb-6", children: [
            /* @__PURE__ */ (0, import_jsx_runtime42.jsx)(MetricItem, { title: "Admin switch", value: pageData.aiAdminEnabled ? "Enabled" : "Disabled", active: pageData.aiAdminEnabled, note: "Global AI availability from admin settings." }),
            /* @__PURE__ */ (0, import_jsx_runtime42.jsx)(MetricItem, { title: "Provider state", value: pageData.aiProviderReady ? "Ready" : "Not ready", active: pageData.aiProviderReady, note: "At least one enabled provider with an API key." }),
            /* @__PURE__ */ (0, import_jsx_runtime42.jsx)("div", { className: "sm:col-span-2", children: /* @__PURE__ */ (0, import_jsx_runtime42.jsx)(MetricItem, { title: "Daily quota", value: `${pageData.quotaUsed || 0}/${pageData.quotaLimit || 100}`, active: true, note: "Usage resets daily." }) })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime42.jsxs)("form", { method: "POST", action: "/instable/outdated/ai", className: "mt-auto border-t border-neutral-700 pt-5", children: [
            /* @__PURE__ */ (0, import_jsx_runtime42.jsxs)("label", { className: `flex items-start gap-3 cursor-pointer ${!aiAvailable ? "opacity-50" : ""}`, children: [
              /* @__PURE__ */ (0, import_jsx_runtime42.jsx)(
                "input",
                {
                  type: "checkbox",
                  name: "enabled",
                  value: "true",
                  className: "w-5 h-5 mt-0.5 rounded border-neutral-600 bg-neutral-900 text-primary-600 focus:ring-primary-600 focus:ring-offset-neutral-800",
                  defaultChecked: Boolean(user.experimentalAiEnabled),
                  disabled: !aiAvailable
                }
              ),
              /* @__PURE__ */ (0, import_jsx_runtime42.jsxs)("div", { children: [
                /* @__PURE__ */ (0, import_jsx_runtime42.jsx)("strong", { className: "block text-sm font-bold text-neutral-200", children: "Enable experimental AI for this account" }),
                /* @__PURE__ */ (0, import_jsx_runtime42.jsx)("span", { className: "block text-sm text-neutral-400 mt-0.5", children: aiAvailable ? "You can opt in safely from here." : "Admin must enable AI and configure at least one provider first." })
              ] })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime42.jsx)("div", { className: "mt-5", children: /* @__PURE__ */ (0, import_jsx_runtime42.jsx)("button", { type: "submit", className: "bg-primary-600 hover:bg-primary-500 text-white font-semibold py-2 px-6 rounded transition-colors text-sm shadow-sm disabled:opacity-50 disabled:cursor-not-allowed", disabled: !aiAvailable, children: "Save Experimental AI" }) })
          ] })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime42.jsxs)("section", { className: "bg-neutral-800 border border-neutral-700 rounded-lg p-6 lg:col-span-2", children: [
          /* @__PURE__ */ (0, import_jsx_runtime42.jsx)("h2", { className: "text-lg font-bold text-neutral-100 mb-4", children: "Current Beta Notes" }),
          /* @__PURE__ */ (0, import_jsx_runtime42.jsxs)("div", { className: "grid grid-cols-1 md:grid-cols-3 gap-4", children: [
            /* @__PURE__ */ (0, import_jsx_runtime42.jsxs)("div", { className: "bg-primary-900/20 border border-primary-500/30 rounded p-4", children: [
              /* @__PURE__ */ (0, import_jsx_runtime42.jsxs)("div", { className: "text-xs font-bold text-primary-400 uppercase tracking-wide mb-1 flex justify-between", children: [
                "Dark fixed renderer ",
                /* @__PURE__ */ (0, import_jsx_runtime42.jsx)("span", { children: "React" })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime42.jsx)("p", { className: "text-sm text-primary-200/70 mt-2", children: "React beta ignores custom themes and uses a fixed dark surface." })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime42.jsxs)("div", { className: "bg-yellow-900/20 border border-yellow-500/30 rounded p-4", children: [
              /* @__PURE__ */ (0, import_jsx_runtime42.jsxs)("div", { className: "text-xs font-bold text-yellow-400 uppercase tracking-wide mb-1 flex justify-between", children: [
                "Partial route coverage ",
                /* @__PURE__ */ (0, import_jsx_runtime42.jsx)("span", { children: "Migrating" })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime42.jsx)("p", { className: "text-sm text-yellow-200/70 mt-2", children: "Only migrated pages use React. Everything else falls back to EJS." })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime42.jsxs)("div", { className: "bg-neutral-900/50 border border-neutral-700 rounded p-4", children: [
              /* @__PURE__ */ (0, import_jsx_runtime42.jsxs)("div", { className: "text-xs font-bold text-neutral-400 uppercase tracking-wide mb-1 flex justify-between", children: [
                "Storage reset on switch ",
                /* @__PURE__ */ (0, import_jsx_runtime42.jsx)("span", { children: "Local only" })
              ] }),
              /* @__PURE__ */ (0, import_jsx_runtime42.jsx)("p", { className: "text-sm text-neutral-400 mt-2", children: "Changing the renderer clears localStorage to avoid stale client state." })
            ] })
          ] })
        ] })
      ] })
    ] }) });
  }
  if (root30) {
    root30.render(
      /* @__PURE__ */ (0, import_jsx_runtime42.jsx)(ThemeContext_default, { pageData: data30, children: /* @__PURE__ */ (0, import_jsx_runtime42.jsx)(BrowserRouter, { children: /* @__PURE__ */ (0, import_jsx_runtime42.jsx)(ExperimentalFeaturesPage, { pageData: data30 }) }) })
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === "function") {
      window.__CPANEL_REACT_BOOTED__();
    }
  }

  // views/react/change-view.jsx
  var import_react43 = __toESM(require_react());
  var import_client31 = __toESM(require_client());
  var import_jsx_runtime43 = __toESM(require_jsx_runtime());
  var data31 = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var standaloneEntry31 = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || "").trim() === "change-view";
  var root31 = standaloneEntry31 ? (0, import_client31.createRoot)(document.getElementById("reactRoot")) : null;
  function ChangeViewPage({ pageData = data31 }) {
    import_react43.default.useEffect(() => {
      if (!pageData.applied) return;
      try {
        window.localStorage.clear();
      } catch (_) {
      }
      const timer = window.setTimeout(() => {
        window.location.replace(ReactRoutes.dashboard);
      }, 150);
      return () => window.clearTimeout(timer);
    }, []);
    return /* @__PURE__ */ (0, import_jsx_runtime43.jsx)(ReactAppShell, { pageData, subtitle: "Change renderer", children: /* @__PURE__ */ (0, import_jsx_runtime43.jsxs)(PageContentBlock, { title: "Renderer Mode", children: [
      pageData.success && /* @__PURE__ */ (0, import_jsx_runtime43.jsx)("div", { className: "bg-green-600/20 border border-green-600/50 text-green-100 p-4 rounded-lg mb-6 shadow-sm", children: pageData.success }),
      pageData.error && /* @__PURE__ */ (0, import_jsx_runtime43.jsx)("div", { className: "bg-red-600/20 border border-red-600/50 text-red-100 p-4 rounded-lg mb-6 shadow-sm", children: pageData.error }),
      /* @__PURE__ */ (0, import_jsx_runtime43.jsxs)("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-6", children: [
        /* @__PURE__ */ (0, import_jsx_runtime43.jsxs)("section", { className: "bg-neutral-800 border border-neutral-700 rounded-lg p-6 flex flex-col hover:border-neutral-500 transition-colors", children: [
          /* @__PURE__ */ (0, import_jsx_runtime43.jsxs)("div", { className: "flex justify-between items-start mb-4", children: [
            /* @__PURE__ */ (0, import_jsx_runtime43.jsxs)("div", { children: [
              /* @__PURE__ */ (0, import_jsx_runtime43.jsx)("h2", { className: "text-lg font-bold text-neutral-100", children: "Legacy EJS View" }),
              /* @__PURE__ */ (0, import_jsx_runtime43.jsx)("p", { className: "text-sm text-neutral-400 mt-1", children: "Stable production renderer. Full theme support and complete route coverage." })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime43.jsx)("span", { className: `px-2 py-1 rounded text-xs font-semibold uppercase tracking-wide ${pageData.currentViewMode === "ejs" ? "bg-green-600 text-white" : "bg-neutral-700 text-neutral-400"}`, children: pageData.currentViewMode === "ejs" ? "Active" : "Available" })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime43.jsx)("div", { className: "mt-auto pt-4 border-t border-neutral-700", children: /* @__PURE__ */ (0, import_jsx_runtime43.jsxs)("form", { method: "POST", action: "/experimental/change-view", children: [
            /* @__PURE__ */ (0, import_jsx_runtime43.jsx)("input", { type: "hidden", name: "viewMode", value: "ejs" }),
            /* @__PURE__ */ (0, import_jsx_runtime43.jsx)("button", { type: "submit", className: "w-full bg-neutral-700 hover:bg-neutral-600 text-neutral-200 font-semibold py-2 px-4 rounded transition-colors text-sm", children: "Use EJS View" })
          ] }) })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime43.jsxs)("section", { className: "bg-neutral-800 border border-neutral-700 rounded-lg p-6 flex flex-col hover:border-neutral-500 transition-colors", children: [
          /* @__PURE__ */ (0, import_jsx_runtime43.jsxs)("div", { className: "flex justify-between items-start mb-4", children: [
            /* @__PURE__ */ (0, import_jsx_runtime43.jsxs)("div", { children: [
              /* @__PURE__ */ (0, import_jsx_runtime43.jsx)("h2", { className: "text-lg font-bold text-neutral-100", children: "React Beta View" }),
              /* @__PURE__ */ (0, import_jsx_runtime43.jsx)("p", { className: "text-sm text-neutral-400 mt-1", children: "Dark fixed renderer for migrated pages. Faster iteration, partial route coverage, no custom themes." })
            ] }),
            /* @__PURE__ */ (0, import_jsx_runtime43.jsx)("span", { className: `px-2 py-1 rounded text-xs font-semibold uppercase tracking-wide ${pageData.currentViewMode === "react" ? "bg-primary-600 text-white" : "bg-neutral-700 text-neutral-400"}`, children: pageData.currentViewMode === "react" ? "Active" : "Available" })
          ] }),
          /* @__PURE__ */ (0, import_jsx_runtime43.jsx)("div", { className: "mt-auto pt-4 border-t border-neutral-700", children: /* @__PURE__ */ (0, import_jsx_runtime43.jsxs)("form", { method: "POST", action: "/experimental/change-view", children: [
            /* @__PURE__ */ (0, import_jsx_runtime43.jsx)("input", { type: "hidden", name: "viewMode", value: "react" }),
            /* @__PURE__ */ (0, import_jsx_runtime43.jsx)("button", { type: "submit", className: "w-full bg-primary-600 hover:bg-primary-500 text-white font-semibold py-2 px-4 rounded transition-colors text-sm shadow-sm opacity-90 shadow-primary-900/50", children: "Use React Beta" })
          ] }) })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime43.jsxs)("section", { className: "bg-neutral-800 border border-neutral-700 rounded-lg p-6 md:col-span-2", children: [
          /* @__PURE__ */ (0, import_jsx_runtime43.jsx)("h2", { className: "text-lg font-bold text-neutral-100 mb-2", children: "Apply Behavior" }),
          /* @__PURE__ */ (0, import_jsx_runtime43.jsx)("p", { className: "text-sm text-neutral-400", children: "Switching renderer clears localStorage and redirects back to the main dashboard. This avoids stale UI state crossing between EJS and React." })
        ] })
      ] })
    ] }) });
  }
  if (root31) {
    root31.render(
      /* @__PURE__ */ (0, import_jsx_runtime43.jsx)(ThemeContext_default, { pageData: data31, children: /* @__PURE__ */ (0, import_jsx_runtime43.jsx)(ChangeViewPage, { pageData: data31 }) })
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === "function") {
      window.__CPANEL_REACT_BOOTED__();
    }
  }

  // views/react/app.jsx
  var import_jsx_runtime44 = __toESM(require_jsx_runtime());
  var initialPageData = window.__CPANEL_REACT_PAGE_DATA__ || {};
  var root32 = (0, import_client32.createRoot)(document.getElementById("reactRoot"));
  var HARD_FALLBACK_GUARD_KEY = "cpanel.react.hard-fallback";
  function normalizePathname2(pathname) {
    const value = String(pathname || "/").trim();
    if (!value || value === "") return ReactRoutes.dashboard;
    return value.endsWith("/") && value !== "/" ? value.slice(0, -1) : value;
  }
  function resolveComponentForPath(pathname) {
    const current = normalizePathname2(pathname);
    if (current === ReactRoutes.dashboard) return DashboardPage;
    const serverRoute = resolveServerReactPage(current);
    if (serverRoute) {
      if (serverRoute.page === "console") return ServerConsolePage;
      if (serverRoute.page === "files") return ServerFilesPage;
      if (serverRoute.page === "backups") return ServerBackupsPage;
      if (serverRoute.page === "network") return ServerNetworkPage;
      if (serverRoute.page === "api") return ServerApiPage;
      if (serverRoute.page === "databases") return ServerDatabasesPage;
      if (serverRoute.page === "users") return ServerUsersPage;
      if (serverRoute.page === "schedules") return ServerSchedulesPage;
      if (serverRoute.page === "startup") return ServerStartupPage;
      if (serverRoute.page === "files/edit") return ServerFileEditorPage;
      if (serverRoute.page === "minecraft-center") return ServerMinecraftCenterPage;
      if (serverRoute.page === "minecraft/world-center") return ServerMinecraftWorldCenterPage;
      if (serverRoute.page === "minecraft/addons") return ServerMinecraftAddonsPage;
      if (serverRoute.page === "minecraft/installer") return ServerMinecraftInstallerPage;
      if (serverRoute.page === "minecraft/admin") return ServerMinecraftAdminPage;
      if (serverRoute.page === "minecraft/configs") return ServerMinecraftConfigsPage;
      if (serverRoute.page === "overview") return ServerOverviewPage;
      if (serverRoute.page === "activity") return ServerActivityPage;
      if (serverRoute.page === "timeline") return ServerTimelinePage;
      if (serverRoute.page === "notfound") return ServerNotFoundPage;
      if (serverRoute.page === "no-permissions") return ServerNoPermissionsPage;
      if (serverRoute.page === "suspended") return ServerSuspendedPage;
    }
    if (current === ReactRoutes.account) return AccountPage;
    if (current === ReactRoutes.deviceLogin) return DeviceLoginPage;
    if (current === ReactRoutes.themes) return ThemesPage;
    if (current === ReactRoutes.rewards) return RewardsPage;
    if (current === ReactRoutes.afk) return AFKPage;
    if (current === ReactRoutes.notifications) return NotificationsPage;
    if (current === ReactRoutes.experimentalFeatures) return ExperimentalFeaturesPage;
    if (current === ReactRoutes.changeView) return ChangeViewPage;
    return null;
  }
  async function fetchReactPageData(pathname, search = "") {
    const target = new URL(`${pathname || "/"}${search || ""}`, window.location.origin);
    target.searchParams.set("__reactData", "1");
    const response = await fetch(target.toString(), {
      headers: {
        Accept: "application/json",
        "X-React-Page-Data": "1"
      },
      credentials: "same-origin"
    });
    if (!response.ok) {
      throw new Error(`Failed to load route data (${response.status})`);
    }
    const payload = await response.json();
    if (!payload || typeof payload !== "object" || !payload.routePath) {
      throw new Error("Invalid route payload");
    }
    return payload;
  }
  function readHardFallbackGuard() {
    try {
      const raw = sessionStorage.getItem(HARD_FALLBACK_GUARD_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  }
  function clearHardFallbackGuard(pathname = "") {
    try {
      const current = readHardFallbackGuard();
      const normalized = `${pathname || ""}`;
      if (!current || !normalized || current.path === normalized) {
        sessionStorage.removeItem(HARD_FALLBACK_GUARD_KEY);
      }
    } catch {
    }
  }
  function performSafeHardFallback(pathname, search = "") {
    const target = `${pathname || "/"}${search || ""}`;
    const now = Date.now();
    const current = readHardFallbackGuard();
    if (current && current.path === target && now - Number(current.at || 0) < 8e3) {
      return false;
    }
    try {
      sessionStorage.setItem(HARD_FALLBACK_GUARD_KEY, JSON.stringify({
        path: target,
        at: now
      }));
    } catch {
    }
    window.location.replace(target);
    return true;
  }
  function LoadingRoute({ pageData, pathname }) {
    return /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(ReactAppShell, { pageData, subtitle: "Loading React route", children: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)("main", { className: "react-experimental-layout", children: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)("div", { className: "react-experimental-scroll", children: /* @__PURE__ */ (0, import_jsx_runtime44.jsxs)("div", { className: "react-account-card", children: [
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)("div", { className: "react-account-section-title", children: "Loading" }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)("div", { className: "react-account-muted", children: `Loading ${pathname}...` })
    ] }) }) }) });
  }
  function FullReloadFallback() {
    const location = useLocation();
    const [blocked, setBlocked] = import_react44.default.useState(false);
    import_react44.default.useEffect(() => {
      const didFallback = performSafeHardFallback(location.pathname, location.search || "");
      if (!didFallback) {
        setBlocked(true);
      }
    }, [location.pathname, location.search]);
    if (!blocked) return null;
    return /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(ReactAppShell, { pageData: initialPageData, subtitle: "React fallback blocked", children: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)("main", { className: "react-experimental-layout", children: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)("div", { className: "react-experimental-scroll", children: /* @__PURE__ */ (0, import_jsx_runtime44.jsxs)("div", { className: "react-account-card", children: [
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)("div", { className: "react-account-section-title", children: "React route fallback was blocked" }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)("div", { className: "react-account-muted", children: "The same route tried to hard-reload repeatedly. The auto-reload was stopped to avoid an infinite loop." }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)("div", { className: "react-account-inline-actions", style: { marginTop: "14px" }, children: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)("a", { href: "/experimental/change-view", className: "react-account-button is-primary", children: "Open Change View" }) })
    ] }) }) }) });
  }
  function RoutedPage() {
    const location = useLocation();
    const pathname = normalizePathname2(location.pathname);
    const [pageData, setPageData] = import_react44.default.useState(initialPageData);
    const [loading, setLoading] = import_react44.default.useState(false);
    const [fallbackBlocked, setFallbackBlocked] = import_react44.default.useState(false);
    import_react44.default.useEffect(() => {
      const targetPath = normalizePathname2(location.pathname);
      const currentPath = normalizePathname2(pageData.routePath || initialPageData.routePath || "/");
      const PageComponent = resolveComponentForPath(targetPath);
      if (!PageComponent) {
        const didFallback = performSafeHardFallback(location.pathname, location.search || "");
        if (!didFallback) {
          setFallbackBlocked(true);
        }
        return;
      }
      clearHardFallbackGuard(`${location.pathname}${location.search || ""}`);
      setFallbackBlocked(false);
      if (targetPath === currentPath) return;
      let cancelled = false;
      setLoading(true);
      fetchReactPageData(targetPath, location.search || "").then((nextPageData) => {
        if (cancelled) return;
        setPageData(nextPageData);
        setLoading(false);
        clearHardFallbackGuard(`${location.pathname}${location.search || ""}`);
        setFallbackBlocked(false);
      }).catch(() => {
        if (cancelled) return;
        const didFallback = performSafeHardFallback(location.pathname, location.search || "");
        if (!didFallback) {
          setLoading(false);
          setFallbackBlocked(true);
        }
      });
      return () => {
        cancelled = true;
      };
    }, [location.pathname, location.search, pageData.routePath]);
    const CurrentComponent = resolveComponentForPath(pathname);
    if (!CurrentComponent) {
      return /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(FullReloadFallback, {});
    }
    if (fallbackBlocked) {
      return /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(ReactAppShell, { pageData, subtitle: "React route fallback blocked", children: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)("main", { className: "react-experimental-layout", children: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)("div", { className: "react-experimental-scroll", children: /* @__PURE__ */ (0, import_jsx_runtime44.jsxs)("div", { className: "react-account-card", children: [
        /* @__PURE__ */ (0, import_jsx_runtime44.jsx)("div", { className: "react-account-section-title", children: "React route fallback was blocked" }),
        /* @__PURE__ */ (0, import_jsx_runtime44.jsx)("div", { className: "react-account-muted", children: "This route kept trying to reload itself. Auto-reload was stopped so you can switch back to EJS or report the route." }),
        /* @__PURE__ */ (0, import_jsx_runtime44.jsx)("div", { className: "react-account-inline-actions", style: { marginTop: "14px" }, children: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)("a", { href: "/experimental/change-view", className: "react-account-button is-primary", children: "Open Change View" }) })
      ] }) }) }) });
    }
    if (loading && normalizePathname2(pageData.routePath || "/") !== pathname) {
      return /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(LoadingRoute, { pageData, pathname });
    }
    return /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(CurrentComponent, { pageData });
  }
  function AppRouter() {
    return /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(BrowserRouter, { children: /* @__PURE__ */ (0, import_jsx_runtime44.jsxs)(Routes, { children: [
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.dashboard, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.serverConsolePattern, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.serverFilesPattern, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.serverBackupsPattern, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.serverNetworkPattern, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.serverApiPattern, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.serverDatabasesPattern, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.serverUsersPattern, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.serverSchedulesPattern, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.serverStartupPattern, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.serverFilesEditPattern, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.serverMinecraftCenterPattern, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.serverMinecraftWorldCenterPattern, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.serverMinecraftAddonsPattern, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.serverMinecraftInstallerPattern, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.serverMinecraftAdminPattern, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.serverMinecraftConfigsPattern, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.serverOverviewPattern, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.serverActivityPattern, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.serverTimelinePattern, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.serverNotFoundPattern, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.serverNoPermissionsPattern, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.serverSuspendedPattern, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.account, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.deviceLogin, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.themes, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.rewards, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.afk, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.notifications, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.experimentalFeatures, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: ReactRoutes.changeView, element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(RoutedPage, {}) }),
      /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(Route, { path: "*", element: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(FullReloadFallback, {}) })
    ] }) });
  }
  root32.render(
    /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(ThemeProvider2, { pageData: initialPageData, children: /* @__PURE__ */ (0, import_jsx_runtime44.jsx)(AppRouter, {}) })
  );
  if (typeof window.__CPANEL_REACT_BOOTED__ === "function") {
    window.__CPANEL_REACT_BOOTED__();
  }
})();
/*! Bundled license information:

react/cjs/react.production.min.js:
  (**
   * @license React
   * react.production.min.js
   *
   * Copyright (c) Facebook, Inc. and its affiliates.
   *
   * This source code is licensed under the MIT license found in the
   * LICENSE file in the root directory of this source tree.
   *)

scheduler/cjs/scheduler.production.min.js:
  (**
   * @license React
   * scheduler.production.min.js
   *
   * Copyright (c) Facebook, Inc. and its affiliates.
   *
   * This source code is licensed under the MIT license found in the
   * LICENSE file in the root directory of this source tree.
   *)

react-dom/cjs/react-dom.production.min.js:
  (**
   * @license React
   * react-dom.production.min.js
   *
   * Copyright (c) Facebook, Inc. and its affiliates.
   *
   * This source code is licensed under the MIT license found in the
   * LICENSE file in the root directory of this source tree.
   *)

react/cjs/react-jsx-runtime.production.min.js:
  (**
   * @license React
   * react-jsx-runtime.production.min.js
   *
   * Copyright (c) Facebook, Inc. and its affiliates.
   *
   * This source code is licensed under the MIT license found in the
   * LICENSE file in the root directory of this source tree.
   *)

@remix-run/router/dist/router.js:
  (**
   * @remix-run/router v1.23.2
   *
   * Copyright (c) Remix Software Inc.
   *
   * This source code is licensed under the MIT license found in the
   * LICENSE.md file in the root directory of this source tree.
   *
   * @license MIT
   *)

react-router/dist/index.js:
  (**
   * React Router v6.30.3
   *
   * Copyright (c) Remix Software Inc.
   *
   * This source code is licensed under the MIT license found in the
   * LICENSE.md file in the root directory of this source tree.
   *
   * @license MIT
   *)

react-router-dom/dist/index.js:
  (**
   * React Router DOM v6.30.3
   *
   * Copyright (c) Remix Software Inc.
   *
   * This source code is licensed under the MIT license found in the
   * LICENSE.md file in the root directory of this source tree.
   *
   * @license MIT
   *)
*/
