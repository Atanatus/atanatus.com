"use strict";

(() => {
  if (typeof globalThis.trustedTypes === "undefined") {
    return;
  }

  globalThis.trustedTypes.createPolicy("default", {
    createScript(value) {
      return value;
    }
  });
})();