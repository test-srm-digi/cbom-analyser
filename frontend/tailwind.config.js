/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'qg-dark': '#0d1117',
        'qg-card': '#161b22',
        'qg-border': '#30363d',
        'qg-accent': '#58a6ff',
        'qg-green': '#3fb950',
        'qg-red': '#f85149',
        'qg-yellow': '#d29922',
        'qg-purple': '#bc8cff',
        'qg-orange': '#f0883e',
      },
    },
  },
  plugins: [],
};
