export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        abyss: "#F6F7FF",      // luminous inset surface
        slab: "#FFFFFF",       // paper-white panels
        hairline: "#D9DDF0",   // quiet lavender border
        daylight: "#007EBC",   // public world: crisp cyan-blue
        veil: "#6847F5",       // shielded world: electric violet
        observer: "#C87808",   // node-provider lens: warm amber
        ok: "#087C59",
        danger: "#D04457",
        dim: "#66708C",
        bright: "#17203D",
      },
      boxShadow: {
        card: "0 18px 55px -32px rgba(44, 38, 110, .38), 0 4px 18px -12px rgba(44, 38, 110, .18)",
        glow: "0 16px 50px -24px rgba(104, 71, 245, .48)",
      },
      fontFamily: {
        display: ["Unbounded", "system-ui", "sans-serif"],
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      keyframes: {
        pulseonce: {
          "0%": { boxShadow: "0 0 0 0 rgba(104,71,245,0.45)" },
          "100%": { boxShadow: "0 0 0 14px rgba(104,71,245,0)" },
        },
        stampin: {
          "0%": { transform: "scale(1.6) rotate(-8deg)", opacity: "0" },
          "60%": { transform: "scale(0.96) rotate(-3deg)", opacity: "1" },
          "100%": { transform: "scale(1) rotate(-3deg)", opacity: "1" },
        },
        risein: {
          "0%": { transform: "translateY(8px)", opacity: "0" },
          "100%": { transform: "translateY(0)", opacity: "1" },
        },
      },
      animation: {
        pulseonce: "pulseonce 1.2s ease-out 1",
        stampin: "stampin 0.5s cubic-bezier(.2,1.4,.4,1) 1 both",
        risein: "risein 0.35s ease-out 1 both",
      },
    },
  },
  plugins: [],
};
