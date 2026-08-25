import { defineConfig } from '@rspress/core';

const repository = 'https://github.com/Payhon/boxd';

export default defineConfig({
  root: 'site',
  base: process.env.DOCS_BASE ?? '/boxd/',
  title: 'boxd',
  description: '面向 macOS 开发者的本地 Upstash Box 兼容轻量级沙盒',
  icon: '/favicon.svg',
  logo: {
    light: '/logo.svg',
    dark: '/logo.svg',
  },
  lang: 'zh',
  markdown: {
    checkDeadLinks: true,
  },
  themeConfig: {
    outlineTitle: '本页内容',
    lastUpdated: true,
    editLink: {
      docRepoBaseUrl: `${repository}/edit/main/docs/site`,
      text: '在 GitHub 上编辑此页',
    },
    socialLinks: [
      {
        icon: 'github',
        mode: 'link',
        content: repository,
      },
    ],
    footer: {
      message: 'Released under the MIT License · Built with Rspress',
    },
  },
});
