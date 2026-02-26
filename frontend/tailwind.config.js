/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'qg-dark': '#F5F6F8',
        'qg-card': '#FFFFFF',
        'qg-border': '#E2E5EA',
        'qg-accent': '#0174C3',
        'qg-green': '#27A872',
        'qg-red': '#DC2626',
        'qg-yellow': '#F5B517',
        'qg-purple': '#7C3AED',
        'qg-orange': '#EA580C',
      },
    },
  },
  plugins: [],
};
