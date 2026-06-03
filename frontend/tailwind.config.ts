import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        abyss: "#07141b",
        panel: "#0d1b24",
        line: "#173140",
        accent: "#4fd1c5",
        mint: "#7ee7c5",
        amber: "#fbbf24",
        danger: "#f87171",
        ink: "#d6e7ef",
        muted: "#83a1ae",
      },
      fontFamily: {
        sans: ["IBM Plex Sans", "ui-sans-serif", "system-ui"],
        mono: ["IBM Plex Mono", "ui-monospace", "SFMono-Regular"],
      },
      boxShadow: {
        panel: "0 16px 48px rgba(0, 0, 0, 0.28)",
      },
    },
  },
  plugins: [],
} satisfies Config;

