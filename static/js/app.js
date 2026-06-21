(() => {
    "use strict";

    const body = document.body;
    const sidebar = document.getElementById("appSidebar");
    const overlay = document.getElementById("sidebarOverlay");
    const menuButton = document.getElementById("mobileMenuButton");
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    function setSidebar(open) {
        body.classList.toggle("sidebar-open", open);

        if (menuButton) {
            menuButton.setAttribute("aria-expanded", String(open));
        }

        if (open && sidebar) {
            const firstLink = sidebar.querySelector("a");
            firstLink?.focus({ preventScroll: true });
        }
    }

    menuButton?.addEventListener("click", () => {
        setSidebar(!body.classList.contains("sidebar-open"));
    });

    overlay?.addEventListener("click", () => setSidebar(false));

    window.addEventListener("keydown", (event) => {
        if (event.key === "Escape") {
            setSidebar(false);
        }
    });

    window.addEventListener("resize", () => {
        if (window.innerWidth > 820) {
            setSidebar(false);
        }
    });

    document.querySelectorAll("[data-toast]").forEach((toast) => {
        window.setTimeout(() => {
            toast.style.opacity = "0";
            toast.style.transform = "translateY(-8px)";
            window.setTimeout(() => toast.remove(), 250);
        }, 4200);
    });

    function animateCount(element) {
        const target = Number.parseFloat(element.dataset.count || "0");
        const decimals = Number.parseInt(element.dataset.decimals || "0", 10);

        if (!Number.isFinite(target)) {
            return;
        }

        const state = { value: 0 };

        gsap.to(state, {
            value: target,
            duration: 1.05,
            ease: "power2.out",
            onUpdate: () => {
                element.textContent = state.value.toFixed(decimals);
            }
        });
    }

    if (!reducedMotion && window.gsap) {
        gsap.registerPlugin(window.ScrollTrigger || {});

        const introTimeline = gsap.timeline({
            defaults: {
                ease: "power3.out"
            }
        });

        introTimeline
            .from(".page-heading", {
                y: 12,
                opacity: 0,
                duration: 0.48
            })
            .from(".topbar-actions > *", {
                y: 8,
                opacity: 0,
                stagger: 0.06,
                duration: 0.36
            }, "-=0.25")
            .from("[data-stagger] > *", {
                y: 14,
                opacity: 0,
                stagger: 0.07,
                duration: 0.48
            }, "-=0.20")
            .from("[data-animate]", {
                y: 12,
                opacity: 0,
                stagger: 0.06,
                duration: 0.45
            }, "-=0.32");

        gsap.from(".sidebar-brand", {
            x: -12,
            opacity: 0,
            duration: 0.45,
            ease: "power2.out"
        });

        gsap.from(".nav-link", {
            x: -10,
            opacity: 0,
            stagger: 0.045,
            duration: 0.34,
            ease: "power2.out"
        });

        document.querySelectorAll("[data-count]").forEach(animateCount);

        if (window.ScrollTrigger) {
            document.querySelectorAll("[data-scroll-reveal]").forEach((element) => {
                gsap.from(element, {
                    scrollTrigger: {
                        trigger: element,
                        start: "top 90%",
                        once: true
                    },
                    y: 20,
                    opacity: 0,
                    duration: 0.58,
                    ease: "power3.out"
                });
            });
        }

        document.querySelectorAll(".button").forEach((button) => {
            button.addEventListener("mouseenter", () => {
                gsap.to(button, {
                    y: -2,
                    duration: 0.18,
                    ease: "power2.out"
                });
            });

            button.addEventListener("mouseleave", () => {
                gsap.to(button, {
                    y: 0,
                    duration: 0.18,
                    ease: "power2.out"
                });
            });
        });

        document.querySelectorAll(".alert-group").forEach((group) => {
            group.addEventListener("toggle", () => {
                if (group.open) {
                    const bodyPanel = group.querySelector(".alert-group-body");
                    if (bodyPanel) {
                        gsap.fromTo(
                            bodyPanel,
                            { opacity: 0, y: -6 },
                            { opacity: 1, y: 0, duration: 0.28, ease: "power2.out" }
                        );
                    }
                }
            });
        });
    }
})();
