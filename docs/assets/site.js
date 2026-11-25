// Copy buttons for the code blocks of the Spackle site. The page works
// without this script: the buttons exist only when it runs.
(function () {
  "use strict";

  // The text a block copies: comment spans removed, lines that held only a
  // comment dropped, and trailing whitespace trimmed.
  function copyText(code) {
    var full = code.textContent.split("\n");
    var bare = code.cloneNode(true);
    bare.querySelectorAll(".c").forEach(function (c) { c.remove(); });
    var stripped = bare.textContent.split("\n");
    var out = [];
    for (var i = 0; i < stripped.length; i++) {
      var line = stripped[i].replace(/\s+$/, "");
      if (line === "" && (full[i] || "").trim() !== "") {
        continue;
      }
      out.push(line);
    }
    return out.join("\n").replace(/\n+$/, "");
  }

  function init() {
    if (!navigator.clipboard || !navigator.clipboard.writeText) {
      return;
    }
    var status = document.createElement("p");
    status.className = "sr-only";
    status.setAttribute("aria-live", "polite");
    document.body.appendChild(status);

    document.querySelectorAll("pre > code").forEach(function (code) {
      var pre = code.parentElement;
      var wrap = document.createElement("div");
      wrap.className = "codeblock";
      pre.parentNode.insertBefore(wrap, pre);
      wrap.appendChild(pre);

      var button = document.createElement("button");
      button.type = "button";
      button.className = "copy";
      button.textContent = "Copy";
      button.setAttribute("aria-label", "Copy this code");
      var timer;
      button.addEventListener("click", function () {
        navigator.clipboard.writeText(copyText(code)).then(function () {
          button.textContent = "Copied";
          status.textContent = "Copied to the clipboard.";
        }, function () {
          button.textContent = "Copy failed";
          status.textContent = "Copy failed. Select the text instead.";
        });
        clearTimeout(timer);
        timer = setTimeout(function () {
          button.textContent = "Copy";
          status.textContent = "";
        }, 2000);
      });
      wrap.appendChild(button);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
