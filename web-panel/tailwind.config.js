/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Custom near-black background matching Grafana's dark theme
        surface: {
          50:  '#f0f4ff',
          100: '#e8eeff',
          DEFAULT: '#181b24',
          1: '#1e2130',
          2: '#242840',
          3: '#2d3150',
        },
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'monospace'],
      },
    },
  },
  plugins: [],
}
