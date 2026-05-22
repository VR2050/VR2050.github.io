const floatingAudioPlayer = document.getElementById('floatingAudioPlayer');
const playPauseButton = document.getElementById('playPauseButton');
const stopButton = document.getElementById('stopButton');

let isPlaying = false;

floatingAudioPlayer.addEventListener('play', () => {
    isPlaying = true;
    playPauseButton.textContent = 'Pause';
});

floatingAudioPlayer.addEventListener('pause', () => {
    isPlaying = false;
    playPauseButton.textContent = 'Play';
});

playPauseButton.addEventListener('click', () => {
    if (isPlaying) {
        floatingAudioPlayer.pause();
    } else {
        floatingAudioPlayer.play();
    }
});

stopButton.addEventListener('click', () => {
    floatingAudioPlayer.pause();
    floatingAudioPlayer.currentTime = 0;
    playPauseButton.textContent = 'Play';
    isPlaying = false;
});
