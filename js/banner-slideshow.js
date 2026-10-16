/**
 * Supinkly.AI - Full Featured Hero / Banner Showcase Slider Controller
 * Multi-compatible: supports both hero-slider and banner-slideshow selectors
 * Features:
 *  - Auto-play with smooth progress bar (5s duration)
 *  - Touch swipe gestures for mobile & tablet
 *  - Pause on mouse enter / resume on mouse leave
 *  - Responsive dots navigation & direct slide index selection
 *  - Slide counter and animated badge
 *  - Modal trigger integration for Google Gemini Argon, Creative AI Suite, and Security Announcement
 */
(function () {
    'use strict';

    if (window.__bannerSlideshowInitialized) {
        return;
    }
    window.__bannerSlideshowInitialized = true;

    const SLIDE_DURATION = 5000;

    const SLIDES_META = [
        {
            id: 'gemini-argon',
            badgeText: '🔥 เปิดตัวใหม่! Gemini Argon x4',
            badgeClass: 'border-amber-400/40 text-amber-300',
            action: function () {
                if (typeof window.openProductDetailModal === 'function') {
                    window.openProductDetailModal('goo-02');
                } else if (typeof window.openLogoPopup === 'function') {
                    window.openLogoPopup();
                }
            }
        },
        {
            id: 'creative-suite',
            badgeText: '✨ ครีเอทีฟ AI สูท สร้างงานด้วย AI',
            badgeClass: 'border-pink-400/40 text-pink-300',
            action: function () {
                if (typeof window.openLogoPopup === 'function') {
                    window.openLogoPopup();
                }
            }
        },
        {
            id: 'security-notice',
            badgeText: '⚠️ ประกาศสำคัญ ระวังมิจฉาชีพ',
            badgeClass: 'border-rose-400/50 text-rose-300',
            action: function () {
                if (typeof window.openAnnouncementModal === 'function') {
                    window.openAnnouncementModal();
                } else if (typeof window.openLogoPopup === 'function') {
                    window.openLogoPopup();
                }
            }
        }
    ];

    let currentSlide = 0;
    let autoPlayTimer = null;
    let isPaused = false;
    let touchStartX = 0;
    let touchStartY = 0;
    let touchEndX = 0;

    function getElements() {
        return {
            container: document.getElementById('hero-showcase-slider') || document.getElementById('banner-slideshow-container'),
            track: document.getElementById('hero-slider-track') || document.getElementById('banner-slides-track'),
            dots: document.querySelectorAll('.slider-dot, .banner-dot'),
            progressBar: document.getElementById('slider-progress-bar') || document.getElementById('banner-progress-bar'),
            badgeText: document.getElementById('slider-slide-badge-text') || document.getElementById('banner-slide-badge-text'),
            counter: document.getElementById('slider-slide-counter') || document.getElementById('banner-slide-counter')
        };
    }

    function updateSlideUI() {
        const els = getElements();
        if (!els.track) return;

        const total = SLIDES_META.length;
        currentSlide = (currentSlide + total) % total;

        // Shift track proportionally: (currentSlide * 100) / total
        const shiftPercent = (currentSlide * 100) / total;
        els.track.style.transform = `translateX(-${shiftPercent}%)`;

        // Update indicator dots
        if (els.dots && els.dots.length) {
            els.dots.forEach((dot, idx) => {
                if (idx === currentSlide) {
                    dot.className = 'slider-dot banner-dot w-6 sm:w-8 h-2 sm:h-2.5 rounded-full bg-gradient-to-r from-pink-500 to-purple-500 shadow-sm transition-all duration-300 cursor-pointer';
                } else {
                    dot.className = 'slider-dot banner-dot w-2 sm:w-2.5 h-2 sm:h-2.5 rounded-full bg-white/50 hover:bg-white transition-all duration-300 cursor-pointer';
                }
            });
        }

        // Update badge text and counter
        const meta = SLIDES_META[currentSlide] || SLIDES_META[0];
        if (els.badgeText) {
            els.badgeText.textContent = meta.badgeText;
        }
        if (els.counter) {
            els.counter.textContent = `${currentSlide + 1} / ${total}`;
        }

        startProgress();
    }

    function startProgress() {
        const els = getElements();
        if (autoPlayTimer) clearTimeout(autoPlayTimer);

        if (!els.progressBar) return;

        els.progressBar.style.transition = 'none';
        els.progressBar.style.width = '0%';

        if (isPaused) return;

        void els.progressBar.offsetWidth;
        els.progressBar.style.transition = `width ${SLIDE_DURATION}ms linear`;
        els.progressBar.style.width = '100%';

        autoPlayTimer = setTimeout(() => {
            nextSlide();
        }, SLIDE_DURATION);
    }

    function pauseAutoPlay() {
        isPaused = true;
        if (autoPlayTimer) {
            clearTimeout(autoPlayTimer);
            autoPlayTimer = null;
        }
        const els = getElements();
        if (els.progressBar) {
            const computedWidth = window.getComputedStyle(els.progressBar).width;
            els.progressBar.style.transition = 'none';
            els.progressBar.style.width = computedWidth;
        }
    }

    function resumeAutoPlay() {
        if (!isPaused) return;
        isPaused = false;
        startProgress();
    }

    function nextSlide(e) {
        if (e && e.stopPropagation) e.stopPropagation();
        currentSlide++;
        updateSlideUI();
    }

    function prevSlide(e) {
        if (e && e.stopPropagation) e.stopPropagation();
        currentSlide--;
        updateSlideUI();
    }

    function goToSlide(index, e) {
        if (e && e.stopPropagation) e.stopPropagation();
        currentSlide = index;
        updateSlideUI();
    }

    function handleSlideClick(index) {
        const meta = SLIDES_META[index];
        if (meta && typeof meta.action === 'function') {
            meta.action();
        }
    }

    // Modal controllers for security announcement
    function openAnnouncementModal() {
        const modal = document.getElementById('announcement-popup-modal');
        if (modal) {
            modal.classList.remove('hidden');
            document.body.classList.add('overflow-hidden');
        }
    }

    function closeAnnouncementModal() {
        const modal = document.getElementById('announcement-popup-modal');
        if (modal) {
            modal.classList.add('hidden');
            document.body.classList.remove('overflow-hidden');
        }
    }

    // Touch & swipe handling
    function setupTouchGestures(container) {
        if (!container) return;

        container.addEventListener('touchstart', (e) => {
            touchStartX = e.changedTouches[0].screenX;
            touchStartY = e.changedTouches[0].screenY;
            pauseAutoPlay();
        }, { passive: true });

        container.addEventListener('touchend', (e) => {
            touchEndX = e.changedTouches[0].screenX;
            const touchEndY = e.changedTouches[0].screenY;
            const diffX = touchEndX - touchStartX;
            const diffY = touchEndY - touchStartY;

            if (Math.abs(diffX) > Math.abs(diffY) && Math.abs(diffX) > 40) {
                if (diffX < 0) {
                    nextSlide();
                } else {
                    prevSlide();
                }
            }
            resumeAutoPlay();
        }, { passive: true });

        container.addEventListener('mouseenter', pauseAutoPlay);
        container.addEventListener('mouseleave', resumeAutoPlay);
    }

    function init() {
        const els = getElements();
        if (els.container && els.track) {
            els.track.style.width = `${SLIDES_META.length * 100}%`;
            els.track.style.display = 'flex';
            setupTouchGestures(els.container);
            updateSlideUI();
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        setTimeout(init, 50);
    }

    // Export public methods with both naming conventions
    window.nextHeroSlide = nextSlide;
    window.prevHeroSlide = prevSlide;
    window.goToHeroSlide = goToSlide;
    window.handleHeroSlideClick = handleSlideClick;

    window.nextBannerSlide = nextSlide;
    window.prevBannerSlide = prevSlide;
    window.goToBannerSlide = goToSlide;
    window.handleBannerSlideClick = handleSlideClick;

    window.openAnnouncementModal = openAnnouncementModal;
    window.closeAnnouncementModal = closeAnnouncementModal;

})();
