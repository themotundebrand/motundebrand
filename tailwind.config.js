/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./public/**/*.html", "./public/**/*.js"],
  theme: {
    extend: {
      colors: {
        'brand-white': '#FFFFFF',
        'brand-black': '#000000',
        'brand-pink': '#F7C8D0', // A sophisticated soft pink
        'brand-pink-dark': '#E2A9B3', // For hover states
      },
      letterSpacing: {
        'luxury': '0.2em',
      }
    },
  },
  plugins: [],
}