// @ts-check
import { defineConfig } from 'astro/config';

import react from '@astrojs/react';

import tailwind from '@astrojs/tailwind';

import relativeLinks from 'astro-relative-links';

// https://astro.build/config
export default defineConfig({
  // output: 'static',
  // base: './',
  integrations: [
    react(),
    tailwind({
      applyBaseStyles: false,
    }),
    relativeLinks()]
});