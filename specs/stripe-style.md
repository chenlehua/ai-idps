# Stripe 设计风格指南

> 本文档提取了 Stripe 官网 (https://stripe.com) 的核心设计要素，可用于复刻其现代、专业、优雅的网站设计风格。

---

## 目录

1. [设计理念](#设计理念)
2. [颜色系统](#颜色系统)
3. [排版系统](#排版系统)
4. [间距系统](#间距系统)
5. [边框与圆角](#边框与圆角)
6. [阴影系统](#阴影系统)
7. [组件规范](#组件规范)
8. [动画与过渡](#动画与过渡)
9. [布局原则](#布局原则)
10. [响应式设计](#响应式设计)
11. [代码示例](#代码示例)

---

## 设计理念

Stripe 的设计哲学基于以下核心原则：

- **简洁至上**：去除不必要的装饰，专注于内容本身
- **精致细节**：每一个微交互都经过精心打磨
- **专业可信**：传达技术专业性和企业级可靠性
- **视觉层次**：通过对比和留白创造清晰的信息层级
- **渐变魅力**：标志性的渐变色彩增添视觉活力

---

## 颜色系统

### 品牌主色

```css
:root {
  /* 主品牌色 - Stripe 标志性紫蓝色 */
  --stripe-primary: #635BFF;
  --stripe-primary-light: #7A73FF;
  --stripe-primary-dark: #5851EA;
  
  /* 渐变色系 */
  --stripe-gradient-start: #80E9FF;  /* 青色 */
  --stripe-gradient-mid: #7C8AFF;    /* 紫蓝 */
  --stripe-gradient-end: #FF80BF;    /* 粉色 */
  
  /* 辅助品牌色 */
  --stripe-cyan: #00D4FF;
  --stripe-blue: #0A2540;
  --stripe-purple: #635BFF;
  --stripe-pink: #FF80BF;
  --stripe-orange: #FF7B5C;
  --stripe-green: #33C27F;
}
```

### 中性色

```css
:root {
  /* 深色系 - 用于文字和深色背景 */
  --stripe-slate-900: #0A2540;  /* 主要文字色/深色背景 */
  --stripe-slate-800: #1A3A5C;
  --stripe-slate-700: #2D4A6F;
  --stripe-slate-600: #425B76;
  --stripe-slate-500: #5B7083;
  
  /* 中间色 - 用于次要文字和边框 */
  --stripe-slate-400: #8898A8;
  --stripe-slate-300: #A3B1BF;
  --stripe-slate-200: #C1CBD6;
  
  /* 浅色系 - 用于背景和分隔 */
  --stripe-slate-100: #E3E8EF;
  --stripe-slate-50: #F6F9FC;
  --stripe-white: #FFFFFF;
}
```

### 功能色

```css
:root {
  /* 成功色 */
  --stripe-success: #33C27F;
  --stripe-success-light: #D4F4E2;
  --stripe-success-dark: #228B5B;
  
  /* 警告色 */
  --stripe-warning: #F5A623;
  --stripe-warning-light: #FEF3D9;
  --stripe-warning-dark: #B87D18;
  
  /* 错误色 */
  --stripe-error: #DF1B41;
  --stripe-error-light: #FCDEDE;
  --stripe-error-dark: #A31431;
  
  /* 信息色 */
  --stripe-info: #0073E6;
  --stripe-info-light: #D9EDFF;
  --stripe-info-dark: #0055A8;
}
```

### 渐变色

```css
:root {
  /* 主渐变 - 网站头部常用 */
  --stripe-gradient-primary: linear-gradient(
    135deg,
    #80E9FF 0%,
    #7C8AFF 50%,
    #FF80BF 100%
  );
  
  /* 暗色渐变背景 */
  --stripe-gradient-dark: linear-gradient(
    135deg,
    #0A2540 0%,
    #1E3A5F 50%,
    #0A2540 100%
  );
  
  /* 按钮渐变 */
  --stripe-gradient-button: linear-gradient(
    135deg,
    #635BFF 0%,
    #7C8AFF 100%
  );
  
  /* 卡片光晕效果 */
  --stripe-gradient-glow: radial-gradient(
    ellipse at 50% 0%,
    rgba(99, 91, 255, 0.15) 0%,
    transparent 70%
  );
}
```

### 颜色使用规范

| 用途 | 颜色变量 | 示例 |
|------|----------|------|
| 主标题 | `--stripe-slate-900` | 页面大标题、重要文字 |
| 正文 | `--stripe-slate-700` | 段落文字、描述文本 |
| 次要文字 | `--stripe-slate-500` | 辅助信息、元数据 |
| 链接 | `--stripe-primary` | 文字链接 |
| 链接悬停 | `--stripe-primary-dark` | 链接悬停状态 |
| 页面背景 | `--stripe-white` / `--stripe-slate-50` | 主背景 |
| 卡片背景 | `--stripe-white` | 卡片组件 |
| 边框 | `--stripe-slate-200` | 分隔线、卡片边框 |

---

## 排版系统

### 字体家族

```css
:root {
  /* 主字体 - 无衬线字体栈 */
  --font-primary: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 
    'Helvetica Neue', Ubuntu, sans-serif;
  
  /* 等宽字体 - 代码展示 */
  --font-mono: 'SF Mono', 'Monaco', 'Inconsolata', 'Fira Code', 
    'Droid Sans Mono', 'Source Code Pro', monospace;
  
  /* 显示字体 - 大标题 (可选使用 Söhne 或类似字体) */
  --font-display: 'Söhne', var(--font-primary);
}

body {
  font-family: var(--font-primary);
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-rendering: optimizeLegibility;
}
```

### 字体大小

```css
:root {
  /* 基础字号 */
  --text-xs: 0.75rem;     /* 12px */
  --text-sm: 0.875rem;    /* 14px */
  --text-base: 1rem;      /* 16px */
  --text-lg: 1.125rem;    /* 18px */
  --text-xl: 1.25rem;     /* 20px */
  --text-2xl: 1.5rem;     /* 24px */
  --text-3xl: 1.875rem;   /* 30px */
  --text-4xl: 2.25rem;    /* 36px */
  --text-5xl: 3rem;       /* 48px */
  --text-6xl: 3.75rem;    /* 60px */
  --text-7xl: 4.5rem;     /* 72px */
  --text-8xl: 6rem;       /* 96px */
}
```

### 字重

```css
:root {
  --font-light: 300;
  --font-normal: 400;
  --font-medium: 500;
  --font-semibold: 600;
  --font-bold: 700;
}
```

### 行高

```css
:root {
  --leading-none: 1;
  --leading-tight: 1.25;
  --leading-snug: 1.375;
  --leading-normal: 1.5;
  --leading-relaxed: 1.625;
  --leading-loose: 2;
}
```

### 字间距

```css
:root {
  --tracking-tighter: -0.05em;
  --tracking-tight: -0.025em;
  --tracking-normal: 0;
  --tracking-wide: 0.025em;
  --tracking-wider: 0.05em;
  --tracking-widest: 0.1em;
}
```

### 标题样式

```css
/* 超大标题 - Hero 区域 */
.heading-hero {
  font-size: var(--text-7xl);
  font-weight: var(--font-semibold);
  line-height: var(--leading-tight);
  letter-spacing: var(--tracking-tight);
  color: var(--stripe-slate-900);
}

/* H1 - 页面标题 */
.heading-1 {
  font-size: var(--text-5xl);
  font-weight: var(--font-semibold);
  line-height: var(--leading-tight);
  letter-spacing: var(--tracking-tight);
  color: var(--stripe-slate-900);
}

/* H2 - 章节标题 */
.heading-2 {
  font-size: var(--text-4xl);
  font-weight: var(--font-semibold);
  line-height: var(--leading-snug);
  color: var(--stripe-slate-900);
}

/* H3 - 子标题 */
.heading-3 {
  font-size: var(--text-2xl);
  font-weight: var(--font-semibold);
  line-height: var(--leading-snug);
  color: var(--stripe-slate-900);
}

/* H4 - 小标题 */
.heading-4 {
  font-size: var(--text-xl);
  font-weight: var(--font-medium);
  line-height: var(--leading-normal);
  color: var(--stripe-slate-900);
}
```

### 正文样式

```css
/* 大段落 - 介绍性文字 */
.body-large {
  font-size: var(--text-xl);
  font-weight: var(--font-normal);
  line-height: var(--leading-relaxed);
  color: var(--stripe-slate-700);
}

/* 默认段落 */
.body-default {
  font-size: var(--text-base);
  font-weight: var(--font-normal);
  line-height: var(--leading-relaxed);
  color: var(--stripe-slate-700);
}

/* 小字 */
.body-small {
  font-size: var(--text-sm);
  font-weight: var(--font-normal);
  line-height: var(--leading-normal);
  color: var(--stripe-slate-600);
}

/* 代码文本 */
.code-inline {
  font-family: var(--font-mono);
  font-size: 0.875em;
  padding: 0.125em 0.375em;
  background-color: var(--stripe-slate-100);
  border-radius: 4px;
}
```

---

## 间距系统

### 间距比例

Stripe 使用 8px 基础网格系统：

```css
:root {
  --space-0: 0;
  --space-1: 0.25rem;   /* 4px */
  --space-2: 0.5rem;    /* 8px */
  --space-3: 0.75rem;   /* 12px */
  --space-4: 1rem;      /* 16px */
  --space-5: 1.25rem;   /* 20px */
  --space-6: 1.5rem;    /* 24px */
  --space-8: 2rem;      /* 32px */
  --space-10: 2.5rem;   /* 40px */
  --space-12: 3rem;     /* 48px */
  --space-16: 4rem;     /* 64px */
  --space-20: 5rem;     /* 80px */
  --space-24: 6rem;     /* 96px */
  --space-32: 8rem;     /* 128px */
  --space-40: 10rem;    /* 160px */
  --space-48: 12rem;    /* 192px */
}
```

### 间距使用规范

| 场景 | 推荐间距 | 说明 |
|------|----------|------|
| 组件内部小间距 | `--space-2` 到 `--space-4` | 按钮内边距、图标间距 |
| 元素间距 | `--space-4` 到 `--space-6` | 相关元素之间 |
| 卡片内边距 | `--space-6` 到 `--space-8` | 卡片内容边距 |
| 章节间距 | `--space-16` 到 `--space-24` | 页面各部分之间 |
| 页面垂直间距 | `--space-24` 到 `--space-32` | 大区块之间 |
| 页面顶部边距 | `--space-20` 到 `--space-32` | Header 后的第一个区块 |

### 容器间距

```css
/* 页面容器 */
.container {
  width: 100%;
  max-width: 1280px;
  margin-left: auto;
  margin-right: auto;
  padding-left: var(--space-6);
  padding-right: var(--space-6);
}

/* 窄容器 - 文章/表单 */
.container-narrow {
  max-width: 720px;
}

/* 中等容器 */
.container-medium {
  max-width: 960px;
}

/* 宽容器 */
.container-wide {
  max-width: 1440px;
}
```

---

## 边框与圆角

### 边框

```css
:root {
  /* 边框宽度 */
  --border-width-thin: 1px;
  --border-width-default: 1px;
  --border-width-medium: 2px;
  --border-width-thick: 4px;
  
  /* 边框颜色 */
  --border-color-default: var(--stripe-slate-200);
  --border-color-light: var(--stripe-slate-100);
  --border-color-focus: var(--stripe-primary);
  --border-color-error: var(--stripe-error);
  
  /* 边框样式 */
  --border-default: 1px solid var(--border-color-default);
  --border-light: 1px solid var(--border-color-light);
}
```

### 圆角

Stripe 使用微妙的圆角，保持专业感：

```css
:root {
  --radius-none: 0;
  --radius-sm: 4px;       /* 小元素：标签、徽章 */
  --radius-default: 6px;  /* 默认：输入框、小按钮 */
  --radius-md: 8px;       /* 中等：按钮、卡片 */
  --radius-lg: 12px;      /* 大型：模态框、大卡片 */
  --radius-xl: 16px;      /* 超大：突出区块 */
  --radius-2xl: 24px;     /* 特大：特殊设计元素 */
  --radius-full: 9999px;  /* 完全圆角：药丸按钮、头像 */
}
```

### 圆角使用规范

| 元素 | 圆角值 | 说明 |
|------|--------|------|
| 徽章/标签 | `--radius-sm` | 4px |
| 输入框 | `--radius-default` | 6px |
| 按钮 | `--radius-md` | 8px |
| 卡片 | `--radius-lg` | 12px |
| 模态框 | `--radius-xl` | 16px |
| 药丸按钮 | `--radius-full` | 完全圆角 |

---

## 阴影系统

Stripe 使用精致的阴影来创建深度感：

```css
:root {
  /* 微弱阴影 - 悬停效果 */
  --shadow-xs: 0 1px 2px rgba(0, 0, 0, 0.04);
  
  /* 小阴影 - 卡片默认 */
  --shadow-sm: 0 2px 4px rgba(0, 0, 0, 0.06);
  
  /* 默认阴影 - 下拉菜单 */
  --shadow-default: 0 4px 6px -1px rgba(0, 0, 0, 0.08),
                    0 2px 4px -1px rgba(0, 0, 0, 0.04);
  
  /* 中等阴影 - 卡片悬停 */
  --shadow-md: 0 8px 16px -2px rgba(0, 0, 0, 0.1),
               0 4px 6px -1px rgba(0, 0, 0, 0.05);
  
  /* 大阴影 - 模态框 */
  --shadow-lg: 0 16px 32px -4px rgba(0, 0, 0, 0.12),
               0 8px 16px -4px rgba(0, 0, 0, 0.08);
  
  /* 超大阴影 - 浮动元素 */
  --shadow-xl: 0 24px 48px -8px rgba(0, 0, 0, 0.15),
               0 12px 24px -4px rgba(0, 0, 0, 0.1);
  
  /* 边框阴影 - 输入框焦点 */
  --shadow-focus: 0 0 0 3px rgba(99, 91, 255, 0.25);
  
  /* 错误阴影 */
  --shadow-error: 0 0 0 3px rgba(223, 27, 65, 0.2);
  
  /* 内阴影 */
  --shadow-inner: inset 0 2px 4px rgba(0, 0, 0, 0.06);
}
```

### 阴影使用技巧

```css
/* 卡片悬停效果 */
.card {
  box-shadow: var(--shadow-sm);
  transition: box-shadow 0.2s ease, transform 0.2s ease;
}

.card:hover {
  box-shadow: var(--shadow-md);
  transform: translateY(-2px);
}

/* 输入框焦点 */
.input:focus {
  outline: none;
  border-color: var(--stripe-primary);
  box-shadow: var(--shadow-focus);
}

/* 按钮阴影 */
.button-primary {
  box-shadow: 0 4px 6px rgba(99, 91, 255, 0.25);
}

.button-primary:hover {
  box-shadow: 0 6px 12px rgba(99, 91, 255, 0.35);
}
```

---

## 组件规范

### 按钮

#### 主按钮

```css
.button-primary {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 12px 20px;
  font-size: var(--text-base);
  font-weight: var(--font-medium);
  line-height: 1;
  color: white;
  background-color: var(--stripe-primary);
  border: none;
  border-radius: var(--radius-md);
  cursor: pointer;
  transition: all 0.15s ease;
  box-shadow: 0 4px 6px rgba(99, 91, 255, 0.25);
}

.button-primary:hover {
  background-color: var(--stripe-primary-light);
  box-shadow: 0 6px 12px rgba(99, 91, 255, 0.35);
  transform: translateY(-1px);
}

.button-primary:active {
  background-color: var(--stripe-primary-dark);
  box-shadow: 0 2px 4px rgba(99, 91, 255, 0.25);
  transform: translateY(0);
}

.button-primary:focus-visible {
  outline: none;
  box-shadow: var(--shadow-focus);
}
```

#### 次要按钮

```css
.button-secondary {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 12px 20px;
  font-size: var(--text-base);
  font-weight: var(--font-medium);
  line-height: 1;
  color: var(--stripe-slate-900);
  background-color: white;
  border: 1px solid var(--stripe-slate-200);
  border-radius: var(--radius-md);
  cursor: pointer;
  transition: all 0.15s ease;
}

.button-secondary:hover {
  background-color: var(--stripe-slate-50);
  border-color: var(--stripe-slate-300);
}

.button-secondary:active {
  background-color: var(--stripe-slate-100);
}
```

#### 文字按钮

```css
.button-text {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 8px 12px;
  font-size: var(--text-base);
  font-weight: var(--font-medium);
  color: var(--stripe-primary);
  background: transparent;
  border: none;
  border-radius: var(--radius-md);
  cursor: pointer;
  transition: all 0.15s ease;
}

.button-text:hover {
  background-color: rgba(99, 91, 255, 0.08);
  color: var(--stripe-primary-dark);
}

/* 带箭头的链接按钮 */
.button-text .arrow {
  transition: transform 0.15s ease;
}

.button-text:hover .arrow {
  transform: translateX(4px);
}
```

#### 按钮尺寸

```css
.button-sm {
  padding: 8px 14px;
  font-size: var(--text-sm);
  border-radius: var(--radius-default);
}

.button-md {
  padding: 12px 20px;
  font-size: var(--text-base);
}

.button-lg {
  padding: 16px 28px;
  font-size: var(--text-lg);
}
```

### 输入框

```css
.input {
  width: 100%;
  padding: 12px 14px;
  font-size: var(--text-base);
  font-family: var(--font-primary);
  color: var(--stripe-slate-900);
  background-color: white;
  border: 1px solid var(--stripe-slate-200);
  border-radius: var(--radius-default);
  transition: all 0.15s ease;
}

.input::placeholder {
  color: var(--stripe-slate-400);
}

.input:hover {
  border-color: var(--stripe-slate-300);
}

.input:focus {
  outline: none;
  border-color: var(--stripe-primary);
  box-shadow: var(--shadow-focus);
}

.input:disabled {
  background-color: var(--stripe-slate-50);
  color: var(--stripe-slate-400);
  cursor: not-allowed;
}

.input-error {
  border-color: var(--stripe-error);
}

.input-error:focus {
  box-shadow: var(--shadow-error);
}
```

### 卡片

```css
.card {
  background-color: white;
  border: 1px solid var(--stripe-slate-100);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-sm);
  overflow: hidden;
  transition: all 0.2s ease;
}

.card:hover {
  box-shadow: var(--shadow-md);
  transform: translateY(-2px);
}

.card-body {
  padding: var(--space-6);
}

.card-header {
  padding: var(--space-6);
  border-bottom: 1px solid var(--stripe-slate-100);
}

.card-footer {
  padding: var(--space-6);
  background-color: var(--stripe-slate-50);
  border-top: 1px solid var(--stripe-slate-100);
}

/* 突出卡片 - 带渐变边框 */
.card-featured {
  position: relative;
  border: none;
  background: linear-gradient(white, white) padding-box,
              var(--stripe-gradient-primary) border-box;
  border: 2px solid transparent;
}
```

### 导航栏

```css
.navbar {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  z-index: 1000;
  height: 64px;
  display: flex;
  align-items: center;
  padding: 0 var(--space-6);
  background-color: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--stripe-slate-100);
}

/* 深色导航栏 */
.navbar-dark {
  background-color: rgba(10, 37, 64, 0.95);
  border-bottom-color: rgba(255, 255, 255, 0.1);
}

.navbar-dark .nav-link {
  color: rgba(255, 255, 255, 0.8);
}

.navbar-dark .nav-link:hover {
  color: white;
}

.nav-link {
  display: inline-flex;
  align-items: center;
  padding: 8px 14px;
  font-size: var(--text-sm);
  font-weight: var(--font-medium);
  color: var(--stripe-slate-700);
  text-decoration: none;
  border-radius: var(--radius-md);
  transition: all 0.15s ease;
}

.nav-link:hover {
  color: var(--stripe-slate-900);
  background-color: var(--stripe-slate-50);
}
```

### 标签/徽章

```css
.badge {
  display: inline-flex;
  align-items: center;
  padding: 4px 10px;
  font-size: var(--text-xs);
  font-weight: var(--font-medium);
  line-height: 1;
  border-radius: var(--radius-full);
}

.badge-primary {
  color: var(--stripe-primary);
  background-color: rgba(99, 91, 255, 0.1);
}

.badge-success {
  color: var(--stripe-success-dark);
  background-color: var(--stripe-success-light);
}

.badge-warning {
  color: var(--stripe-warning-dark);
  background-color: var(--stripe-warning-light);
}

.badge-error {
  color: var(--stripe-error-dark);
  background-color: var(--stripe-error-light);
}
```

### 代码块

```css
.code-block {
  padding: var(--space-4);
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  line-height: var(--leading-relaxed);
  color: #e6edf3;
  background-color: #0D1117;
  border-radius: var(--radius-lg);
  overflow-x: auto;
}

/* 代码高亮色 */
.code-keyword { color: #ff7b72; }
.code-string { color: #a5d6ff; }
.code-function { color: #d2a8ff; }
.code-comment { color: #8b949e; }
.code-number { color: #79c0ff; }
```

### 表格

```css
.table {
  width: 100%;
  border-collapse: separate;
  border-spacing: 0;
  border-radius: var(--radius-lg);
  overflow: hidden;
  border: 1px solid var(--stripe-slate-200);
}

.table th {
  padding: 12px 16px;
  font-size: var(--text-sm);
  font-weight: var(--font-semibold);
  color: var(--stripe-slate-700);
  text-align: left;
  background-color: var(--stripe-slate-50);
  border-bottom: 1px solid var(--stripe-slate-200);
}

.table td {
  padding: 16px;
  font-size: var(--text-sm);
  color: var(--stripe-slate-700);
  border-bottom: 1px solid var(--stripe-slate-100);
}

.table tr:last-child td {
  border-bottom: none;
}

.table tr:hover td {
  background-color: var(--stripe-slate-50);
}
```

---

## 动画与过渡

### 过渡时间

```css
:root {
  --duration-fast: 0.1s;
  --duration-default: 0.15s;
  --duration-medium: 0.2s;
  --duration-slow: 0.3s;
  --duration-slower: 0.5s;
}
```

### 缓动函数

```css
:root {
  --ease-default: cubic-bezier(0.4, 0, 0.2, 1);
  --ease-in: cubic-bezier(0.4, 0, 1, 1);
  --ease-out: cubic-bezier(0, 0, 0.2, 1);
  --ease-in-out: cubic-bezier(0.4, 0, 0.2, 1);
  --ease-bounce: cubic-bezier(0.34, 1.56, 0.64, 1);
}
```

### 常用动画

```css
/* 淡入 */
@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}

/* 淡入上移 */
@keyframes fadeInUp {
  from {
    opacity: 0;
    transform: translateY(16px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

/* 淡入缩放 */
@keyframes fadeInScale {
  from {
    opacity: 0;
    transform: scale(0.95);
  }
  to {
    opacity: 1;
    transform: scale(1);
  }
}

/* 脉冲效果 */
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.6; }
}

/* 旋转加载 */
@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

/* 应用动画 */
.animate-fade-in {
  animation: fadeIn var(--duration-medium) var(--ease-out);
}

.animate-fade-in-up {
  animation: fadeInUp var(--duration-slow) var(--ease-out);
}

.animate-pulse {
  animation: pulse 2s var(--ease-in-out) infinite;
}

.animate-spin {
  animation: spin 1s linear infinite;
}
```

### 悬停过渡

```css
/* 标准悬停过渡 */
.hover-transition {
  transition: all var(--duration-default) var(--ease-default);
}

/* 按钮悬停 */
.button-hover {
  transition: 
    background-color var(--duration-fast) var(--ease-default),
    box-shadow var(--duration-default) var(--ease-default),
    transform var(--duration-default) var(--ease-default);
}

/* 卡片悬停 */
.card-hover {
  transition: 
    box-shadow var(--duration-medium) var(--ease-out),
    transform var(--duration-medium) var(--ease-out);
}
```

---

## 布局原则

### 网格系统

```css
/* 12列网格 */
.grid {
  display: grid;
  gap: var(--space-6);
}

.grid-cols-1 { grid-template-columns: repeat(1, 1fr); }
.grid-cols-2 { grid-template-columns: repeat(2, 1fr); }
.grid-cols-3 { grid-template-columns: repeat(3, 1fr); }
.grid-cols-4 { grid-template-columns: repeat(4, 1fr); }
.grid-cols-6 { grid-template-columns: repeat(6, 1fr); }
.grid-cols-12 { grid-template-columns: repeat(12, 1fr); }

/* 常用布局 */
.grid-auto-fit {
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
}
```

### Flexbox 工具

```css
.flex { display: flex; }
.flex-col { flex-direction: column; }
.flex-wrap { flex-wrap: wrap; }
.items-center { align-items: center; }
.items-start { align-items: flex-start; }
.items-end { align-items: flex-end; }
.justify-center { justify-content: center; }
.justify-between { justify-content: space-between; }
.justify-end { justify-content: flex-end; }
.gap-2 { gap: var(--space-2); }
.gap-4 { gap: var(--space-4); }
.gap-6 { gap: var(--space-6); }
.gap-8 { gap: var(--space-8); }
```

### 章节布局

```css
/* 页面章节 */
.section {
  padding-top: var(--space-24);
  padding-bottom: var(--space-24);
}

.section-sm {
  padding-top: var(--space-16);
  padding-bottom: var(--space-16);
}

.section-lg {
  padding-top: var(--space-32);
  padding-bottom: var(--space-32);
}

/* Hero 区域 */
.hero {
  padding-top: var(--space-32);
  padding-bottom: var(--space-24);
  text-align: center;
}

/* 两栏布局 */
.two-column {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--space-16);
  align-items: center;
}

/* 侧边栏布局 */
.sidebar-layout {
  display: grid;
  grid-template-columns: 280px 1fr;
  gap: var(--space-12);
}
```

---

## 响应式设计

### 断点

```css
:root {
  --breakpoint-sm: 640px;
  --breakpoint-md: 768px;
  --breakpoint-lg: 1024px;
  --breakpoint-xl: 1280px;
  --breakpoint-2xl: 1536px;
}

/* 媒体查询 */
@media (min-width: 640px) { /* sm */ }
@media (min-width: 768px) { /* md */ }
@media (min-width: 1024px) { /* lg */ }
@media (min-width: 1280px) { /* xl */ }
@media (min-width: 1536px) { /* 2xl */ }
```

### 响应式排版

```css
.heading-hero {
  font-size: var(--text-4xl);
}

@media (min-width: 768px) {
  .heading-hero {
    font-size: var(--text-5xl);
  }
}

@media (min-width: 1024px) {
  .heading-hero {
    font-size: var(--text-6xl);
  }
}

@media (min-width: 1280px) {
  .heading-hero {
    font-size: var(--text-7xl);
  }
}
```

### 响应式间距

```css
.section {
  padding-top: var(--space-16);
  padding-bottom: var(--space-16);
}

@media (min-width: 768px) {
  .section {
    padding-top: var(--space-20);
    padding-bottom: var(--space-20);
  }
}

@media (min-width: 1024px) {
  .section {
    padding-top: var(--space-24);
    padding-bottom: var(--space-24);
  }
}
```

### 响应式网格

```css
.grid-responsive {
  display: grid;
  grid-template-columns: 1fr;
  gap: var(--space-6);
}

@media (min-width: 640px) {
  .grid-responsive {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (min-width: 1024px) {
  .grid-responsive {
    grid-template-columns: repeat(3, 1fr);
  }
}

@media (min-width: 1280px) {
  .grid-responsive {
    grid-template-columns: repeat(4, 1fr);
  }
}
```

---

## 代码示例

### Tailwind CSS 配置

如果使用 Tailwind CSS，可以扩展配置以匹配 Stripe 风格：

```javascript
// tailwind.config.js
module.exports = {
  theme: {
    extend: {
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
      },
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
      borderRadius: {
        sm: '4px',
        DEFAULT: '6px',
        md: '8px',
        lg: '12px',
        xl: '16px',
        '2xl': '24px',
      },
      boxShadow: {
        xs: '0 1px 2px rgba(0, 0, 0, 0.04)',
        sm: '0 2px 4px rgba(0, 0, 0, 0.06)',
        DEFAULT: '0 4px 6px -1px rgba(0, 0, 0, 0.08), 0 2px 4px -1px rgba(0, 0, 0, 0.04)',
        md: '0 8px 16px -2px rgba(0, 0, 0, 0.1), 0 4px 6px -1px rgba(0, 0, 0, 0.05)',
        lg: '0 16px 32px -4px rgba(0, 0, 0, 0.12), 0 8px 16px -4px rgba(0, 0, 0, 0.08)',
        xl: '0 24px 48px -8px rgba(0, 0, 0, 0.15), 0 12px 24px -4px rgba(0, 0, 0, 0.1)',
        focus: '0 0 0 3px rgba(99, 91, 255, 0.25)',
      },
    },
  },
}
```

### React 组件示例

```tsx
// Button.tsx
import React from 'react';

interface ButtonProps {
  variant?: 'primary' | 'secondary' | 'text';
  size?: 'sm' | 'md' | 'lg';
  children: React.ReactNode;
  onClick?: () => void;
}

export const Button: React.FC<ButtonProps> = ({
  variant = 'primary',
  size = 'md',
  children,
  onClick,
}) => {
  const baseStyles = `
    inline-flex items-center justify-center
    font-medium transition-all duration-150
    focus:outline-none focus-visible:ring-2
    focus-visible:ring-stripe-primary focus-visible:ring-offset-2
  `;

  const variants = {
    primary: `
      text-white bg-stripe-primary
      hover:bg-stripe-primary-light
      active:bg-stripe-primary-dark
      shadow-[0_4px_6px_rgba(99,91,255,0.25)]
      hover:shadow-[0_6px_12px_rgba(99,91,255,0.35)]
      hover:-translate-y-0.5 active:translate-y-0
    `,
    secondary: `
      text-slate-900 bg-white
      border border-slate-200
      hover:bg-slate-50 hover:border-slate-300
      active:bg-slate-100
    `,
    text: `
      text-stripe-primary
      hover:bg-stripe-primary/8
    `,
  };

  const sizes = {
    sm: 'px-3.5 py-2 text-sm rounded-md',
    md: 'px-5 py-3 text-base rounded-lg',
    lg: 'px-7 py-4 text-lg rounded-lg',
  };

  return (
    <button
      className={`${baseStyles} ${variants[variant]} ${sizes[size]}`}
      onClick={onClick}
    >
      {children}
    </button>
  );
};
```

```tsx
// Card.tsx
import React from 'react';

interface CardProps {
  children: React.ReactNode;
  featured?: boolean;
  hoverable?: boolean;
}

export const Card: React.FC<CardProps> = ({
  children,
  featured = false,
  hoverable = true,
}) => {
  const baseStyles = `
    bg-white rounded-xl overflow-hidden
    border border-slate-100
  `;

  const hoverStyles = hoverable
    ? 'transition-all duration-200 hover:shadow-md hover:-translate-y-0.5'
    : '';

  const featuredStyles = featured
    ? 'border-2 border-transparent bg-gradient-to-r from-cyan-400 via-purple-500 to-pink-500 p-[2px]'
    : 'shadow-sm';

  if (featured) {
    return (
      <div className={featuredStyles}>
        <div className={`${baseStyles} ${hoverStyles} bg-white`}>
          {children}
        </div>
      </div>
    );
  }

  return (
    <div className={`${baseStyles} ${hoverStyles} ${featuredStyles}`}>
      {children}
    </div>
  );
};
```

---

## 设计检查清单

在应用 Stripe 风格时，请确保：

### 颜色
- [ ] 使用 `#0A2540` 作为主要深色文字
- [ ] 使用 `#635BFF` 作为主要品牌色
- [ ] 背景主要使用白色和 `#F6F9FC`
- [ ] 适当使用渐变效果增添视觉趣味

### 排版
- [ ] 标题使用 semibold (600) 字重
- [ ] 正文使用 regular (400) 字重
- [ ] 行高充足，提高可读性
- [ ] 大标题使用 tight letter-spacing

### 间距
- [ ] 遵循 8px 基础网格
- [ ] 章节之间使用大间距 (96-128px)
- [ ] 组件内部使用小间距 (16-32px)
- [ ] 留白充足，不要过于拥挤

### 组件
- [ ] 按钮使用 8px 圆角
- [ ] 卡片使用 12px 圆角
- [ ] 输入框使用 6px 圆角
- [ ] 悬停效果平滑自然

### 动效
- [ ] 过渡时间 150-200ms
- [ ] 使用 ease-out 缓动函数
- [ ] 悬停时有轻微上浮效果
- [ ] 焦点状态使用 focus ring

---

## 参考资源

- [Stripe 官网](https://stripe.com)
- [Stripe 文档](https://stripe.com/docs)
- [Stripe 设计博客](https://stripe.com/blog)

---

*本设计指南基于 Stripe 官网的视觉风格分析整理，用于参考学习目的。*
