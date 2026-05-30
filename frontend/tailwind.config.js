/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{vue,js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // 使用CSS变量 (RGB格式，支持opacity modifier)
        dark: {
          bg: 'rgb(var(--dark-bg-rgb) / <alpha-value>)',
          surface: 'rgb(var(--dark-surface-rgb) / <alpha-value>)',
          card: 'rgb(var(--dark-card-rgb) / <alpha-value>)',
          border: 'rgb(var(--dark-border-rgb) / <alpha-value>)',
          hover: 'rgb(var(--dark-hover-rgb) / <alpha-value>)',
          text: 'rgb(var(--dark-text-rgb) / <alpha-value>)',
          muted: 'rgb(var(--dark-muted-rgb) / <alpha-value>)',
          accent: 'rgb(var(--dark-accent-rgb) / <alpha-value>)',
          accentHover: 'rgb(var(--dark-accentHover-rgb) / <alpha-value>)',
          success: 'rgb(var(--dark-success-rgb) / <alpha-value>)',
          warning: 'rgb(var(--dark-warning-rgb) / <alpha-value>)',
          error: 'rgb(var(--dark-error-rgb) / <alpha-value>)',
        },
        light: {
          bg: 'rgb(var(--light-bg-rgb) / <alpha-value>)',
          surface: 'rgb(var(--light-surface-rgb) / <alpha-value>)',
          card: 'rgb(var(--light-card-rgb) / <alpha-value>)',
          border: 'rgb(var(--light-border-rgb) / <alpha-value>)',
          hover: 'rgb(var(--light-hover-rgb) / <alpha-value>)',
          text: 'rgb(var(--light-text-rgb) / <alpha-value>)',
          muted: 'rgb(var(--light-muted-rgb) / <alpha-value>)',
          accent: 'rgb(var(--light-accent-rgb) / <alpha-value>)',
          accentHover: 'rgb(var(--light-accentHover-rgb) / <alpha-value>)',
          success: 'rgb(var(--light-success-rgb) / <alpha-value>)',
          warning: 'rgb(var(--light-warning-rgb) / <alpha-value>)',
          error: 'rgb(var(--light-error-rgb) / <alpha-value>)',
        },
        // 算法类型色彩
        algo: {
          symmetric: 'rgb(var(--algo-symmetric-rgb) / <alpha-value>)',
          asymmetric: 'rgb(var(--algo-asymmetric-rgb) / <alpha-value>)',
          hash: 'rgb(var(--algo-hash-rgb) / <alpha-value>)',
          mac: 'rgb(var(--algo-mac-rgb) / <alpha-value>)',
          gm: 'rgb(var(--algo-gm-rgb) / <alpha-value>)',
          pqc: 'rgb(var(--algo-pqc-rgb) / <alpha-value>)',
          tools: 'rgb(var(--algo-tools-rgb) / <alpha-value>)',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
      fontSize: {
        'xs': ['10px', { lineHeight: '1.4' }],
        'sm': ['11px', { lineHeight: '1.5' }],
        'base': ['12px', { lineHeight: '1.5' }],
        'md': ['13px', { lineHeight: '1.5' }],
        'lg': ['14px', { lineHeight: '1.5' }],
        'xl': ['16px', { lineHeight: '1.4' }],
        '2xl': ['20px', { lineHeight: '1.3' }],
      },
      spacing: {
        'xs': '4px',
        'sm': '8px',
        'md': '12px',
        'lg': '16px',
        'xl': '24px',
        '2xl': '32px',
      },
      borderRadius: {
        'sm': '4px',
        'md': '6px',
        'lg': '8px',
        'xl': '10px',
      },
      boxShadow: {
        'sm': '0 1px 2px rgba(0,0,0,0.1)',
        'md': '0 2px 8px rgba(0,0,0,0.1)',
        'lg': '0 4px 12px rgba(0,0,0,0.15)',
        'xl': '0 8px 24px rgba(0,0,0,0.2)',
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
