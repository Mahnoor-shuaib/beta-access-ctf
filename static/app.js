document.querySelectorAll(".pw").forEach(function (box) {
  var input = box.querySelector("input");
  var btn = box.querySelector(".toggle");
  if (!input || !btn) return;
  btn.addEventListener("click", function () {
    var show = input.type === "password";
    input.type = show ? "text" : "password";
    btn.textContent = show ? "Hide" : "Show";
    btn.setAttribute("aria-pressed", show ? "true" : "false");
    input.focus();
  });
});
