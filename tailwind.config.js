/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./views/react/**/*.{js,jsx}",
  ],
  theme: {
    extend: {
      colors: {
        neutral: {
          900: '#131517',
          800: '#1f2023',
          700: '#2e3036',
          600: '#3f3f46',
          500: '#52525b',
          400: '#9ca3af',
          300: '#d1d5db',
          200: '#e5e7eb',
          100: '#f3f4f6',
          50: '#f9fafb',
        },
        primary: {
          600: '#2563eb',
          500: '#3b82f6',
          400: '#60a5fa',
        }
      },
      fontFamily: {
        sans: ['Manrope', 'system-ui', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'monospace'],
      }
    },
  },
  plugins: [],
}
