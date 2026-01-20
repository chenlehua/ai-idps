/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      // Stripe 品牌色
      colors: {
        stripe: {
          primary: '#635BFF',
          'primary-light': '#7A73FF',
          'primary-dark': '#5851EA',
          cyan: '#00D4FF',
          blue: '#0A2540',
          purple: '#635BFF',
          pink: '#FF80BF',
          orange: '#FF7B5C',
          green: '#33C27F',
        },
        // 覆盖默认的 slate 色板以匹配 Stripe 风格
        slate: {
          50: '#F6F9FC',
          100: '#E3E8EF',
          200: '#C1CBD6',
          300: '#A3B1BF',
          400: '#8898A8',
          500: '#5B7083',
          600: '#425B76',
          700: '#2D4A6F',
          800: '#1A3A5C',
          900: '#0A2540',
        },
        // 功能色
        success: {
          DEFAULT: '#33C27F',
          light: '#D4F4E2',
          dark: '#228B5B',
        },
        warning: {
          DEFAULT: '#F5A623',
          light: '#FEF3D9',
          dark: '#B87D18',
        },
        error: {
          DEFAULT: '#DF1B41',
          light: '#FCDEDE',
          dark: '#A31431',
        },
        info: {
          DEFAULT: '#0073E6',
          light: '#D9EDFF',
          dark: '#0055A8',
        },
      },
      // 字体
      fontFamily: {
        sans: [
          '-apple-system',
          'BlinkMacSystemFont',
          'Segoe UI',
          'Roboto',
          'Helvetica Neue',
          'Ubuntu',
          'sans-serif',
        ],
        mono: [
          'SF Mono',
          'Monaco',
          'Inconsolata',
          'Fira Code',
          'monospace',
        ],
      },
      // 圆角
      borderRadius: {
        'sm': '4px',
        'DEFAULT': '6px',
        'md': '8px',
        'lg': '12px',
        'xl': '16px',
        '2xl': '24px',
      },
      // 阴影
      boxShadow: {
        'xs': '0 1px 2px rgba(0, 0, 0, 0.04)',
        'sm': '0 2px 4px rgba(0, 0, 0, 0.06)',
        'DEFAULT': '0 4px 6px -1px rgba(0, 0, 0, 0.08), 0 2px 4px -1px rgba(0, 0, 0, 0.04)',
        'md': '0 8px 16px -2px rgba(0, 0, 0, 0.1), 0 4px 6px -1px rgba(0, 0, 0, 0.05)',
        'lg': '0 16px 32px -4px rgba(0, 0, 0, 0.12), 0 8px 16px -4px rgba(0, 0, 0, 0.08)',
        'xl': '0 24px 48px -8px rgba(0, 0, 0, 0.15), 0 12px 24px -4px rgba(0, 0, 0, 0.1)',
        'focus': '0 0 0 3px rgba(99, 91, 255, 0.25)',
        'focus-error': '0 0 0 3px rgba(223, 27, 65, 0.2)',
        'button': '0 4px 6px rgba(99, 91, 255, 0.25)',
        'button-hover': '0 6px 12px rgba(99, 91, 255, 0.35)',
      },
      // 过渡时间
      transitionDuration: {
        'fast': '100ms',
        'DEFAULT': '150ms',
        'medium': '200ms',
        'slow': '300ms',
      },
      // 动画
      animation: {
        'fade-in': 'fadeIn 0.2s ease-out',
        'fade-in-up': 'fadeInUp 0.3s ease-out',
        'fade-in-scale': 'fadeInScale 0.2s ease-out',
        'pulse-slow': 'pulse 2s ease-in-out infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        fadeInUp: {
          '0%': { opacity: '0', transform: 'translateY(16px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        fadeInScale: {
          '0%': { opacity: '0', transform: 'scale(0.95)' },
          '100%': { opacity: '1', transform: 'scale(1)' },
        },
      },
    },
  },
  plugins: [],
}
