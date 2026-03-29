/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{vue,js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Dark theme colors
        dark: {
          bg:       '#0f0f17',
          surface:  '#16161f',
          card:     '#1e1e2e',
          border:   '#2a2a3e',
          hover:    '#252535',
          text:     '#e4e4f0',
          muted:    '#8888a8',
          accent:   '#7c6af7',
          accentHover: '#9080ff',
          success:  '#2dd4bf',
          warning:  '#f59e0b',
          error:    '#f87171',
          cyan:     '#22d3ee',
          purple:   '#a78bfa',
          pink:     '#f472b6',
          green:    '#34d399',
        },
        // Light theme colors
        light: {
          bg:       '#f5f5fb',
          surface:  '#ffffff',
          card:     '#f0f0fa',
          border:   '#dddded',
          hover:    '#e8e8f5',
          text:     '#1a1a2e',
          muted:    '#6b6b8a',
          accent:   '#5b4cf5',
          accentHover: '#7060ff',
          success:  '#059669',
          warning:  '#d97706',
          error:    '#dc2626',
          cyan:     '#0891b2',
          purple:   '#7c3aed',
          pink:     '#db2777',
          green:    '#047857',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
      animation: {
        'fade-in': 'fadeIn 0.2s ease-out',
        'slide-in': 'slideIn 0.2s ease-out',
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0', transform: 'translateY(4px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        slideIn: {
          '0%': { opacity: '0', transform: 'translateX(-8px)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
      },
    },
  },
  plugins: [],
}
