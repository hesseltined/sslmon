// Simple 5‑minute countdown auto‑refresh
let seconds = 300;
const timer = document.getElementById("refreshTimer");

function updateTimer() {
  seconds--;
  if (timer) timer.textContent = seconds;
  if (seconds <= 0) location.reload();
}
setInterval(updateTimer, 1000);
