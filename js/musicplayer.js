const floatingAudioPlayer = document.getElementById("floatingAudioPlayer");
const playPauseButton = document.getElementById("playPauseButton");
const stopButton = document.getElementById("stopButton");
const playerRoot = document.querySelector(".floating-player");

if (floatingAudioPlayer && playPauseButton && stopButton) {
  const STATE_KEY = "vr2050_player_state_v1";
  let isPlaying = false;

  function readState() {
    try {
      const raw = localStorage.getItem(STATE_KEY);
      if (!raw) return { currentTime: 0, playing: false };
      const parsed = JSON.parse(raw);
      return {
        currentTime: Number(parsed.currentTime) || 0,
        playing: Boolean(parsed.playing),
      };
    } catch (e) {
      return { currentTime: 0, playing: false };
    }
  }

  function writeState() {
    try {
      localStorage.setItem(
        STATE_KEY,
        JSON.stringify({
          currentTime: floatingAudioPlayer.currentTime || 0,
          playing: isPlaying,
        }),
      );
    } catch (e) {}
  }

  function updateUI() {
    playPauseButton.textContent = isPlaying ? "Pause" : "Play";
    if (playerRoot) playerRoot.classList.toggle("is-playing", isPlaying);
  }

  const saved = readState();

  floatingAudioPlayer.addEventListener("loadedmetadata", () => {
    if (saved.currentTime > 0 && saved.currentTime < floatingAudioPlayer.duration) {
      floatingAudioPlayer.currentTime = saved.currentTime;
    }
    if (saved.playing) {
      floatingAudioPlayer.play().catch(() => {
        isPlaying = false;
        updateUI();
      });
    }
  });

  floatingAudioPlayer.addEventListener("play", () => {
    isPlaying = true;
    updateUI();
    writeState();
  });

  floatingAudioPlayer.addEventListener("pause", () => {
    isPlaying = false;
    updateUI();
    writeState();
  });

  floatingAudioPlayer.addEventListener("timeupdate", () => {
    if (Math.floor(floatingAudioPlayer.currentTime) % 2 === 0) writeState();
  });

  playPauseButton.addEventListener("click", () => {
    if (isPlaying) floatingAudioPlayer.pause();
    else floatingAudioPlayer.play().catch(() => {});
  });

  stopButton.addEventListener("click", () => {
    floatingAudioPlayer.pause();
    floatingAudioPlayer.currentTime = 0;
    writeState();
  });

  window.addEventListener("beforeunload", writeState);
  updateUI();
}
