// EvidenceGuard — small client-side enhancements. No framework needed.

document.addEventListener("DOMContentLoaded", function () {

  // ---- Copy-to-clipboard for hash / evidence-id chips -------------------
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      const text = btn.getAttribute("data-copy");
      navigator.clipboard.writeText(text).then(function () {
        const original = btn.textContent;
        btn.textContent = "Copied";
        setTimeout(function () { btn.textContent = original; }, 1200);
      });
    });
  });

  // ---- Confirm dialogs for destructive/administrative actions -----------
  document.querySelectorAll("[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      if (!window.confirm(form.getAttribute("data-confirm"))) {
        e.preventDefault();
      }
    });
  });

  // ---- Character-level hash diff highlighting ----------------------------
  // Makes the avalanche effect visible: on a mismatch, every differing
  // hex character between the original and current hash is highlighted.
  const originalEl = document.querySelector("[data-hash-original]");
  const currentEl = document.querySelector("[data-hash-current]");
  if (originalEl && currentEl) {
    const a = originalEl.getAttribute("data-hash-original");
    const b = currentEl.getAttribute("data-hash-current");
    if (a !== b) {
      originalEl.innerHTML = diffHighlight(a, b);
      currentEl.innerHTML = diffHighlight(b, a);
    }
  }

  function diffHighlight(str, other) {
    let out = "";
    for (let i = 0; i < str.length; i++) {
      const ch = str[i];
      if (other[i] !== ch) {
        out += '<span class="diff-char">' + ch + "</span>";
      } else {
        out += ch;
      }
    }
    return out;
  }

  // ---- Dropzone visual state for the upload page -------------------------
  const dropzone = document.querySelector(".dropzone");
  const fileInput = document.querySelector("#evidence_file");
  const fileNameLabel = document.querySelector("#selected-file-name");
  if (dropzone && fileInput) {
    ["dragenter", "dragover"].forEach(function (evt) {
      dropzone.addEventListener(evt, function (e) {
        e.preventDefault();
        dropzone.classList.add("dragover");
      });
    });
    ["dragleave", "drop"].forEach(function (evt) {
      dropzone.addEventListener(evt, function (e) {
        e.preventDefault();
        dropzone.classList.remove("dragover");
      });
    });
    dropzone.addEventListener("drop", function (e) {
      if (e.dataTransfer.files.length) {
        fileInput.files = e.dataTransfer.files;
        updateFileLabel();
      }
    });
    fileInput.addEventListener("change", updateFileLabel);
    function updateFileLabel() {
      if (fileInput.files.length && fileNameLabel) {
        fileNameLabel.textContent = fileInput.files[0].name;
      }
    }
  }
});
