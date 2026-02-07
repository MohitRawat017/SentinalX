/* Modal-Style Component Library
 * Reusable UI components inspired by Modal.com's design system
 * - Dark theme with gradient backgrounds
 * - Glassmorphism effects
 * - Large typography
 * - Clean spacing
 * - Rounded cards with soft shadows
 */

export { default as ModalNavbar } from './ModalNavbar';
export { default as ModalHero } from './ModalHero';
export { default as ModalFeatureCards } from './ModalFeatureCards';
export { default as ModalPricing } from './ModalPricing';
export { default as ModalFooter } from './ModalFooter';

// Shared style constants for consistency
export const modalStyles = {
    // Gradient backgrounds
    gradients: {
        dark: 'bg-gradient-to-br from-[#0a0a0f] via-[#0d0d15] to-[#12121c]',
        accent: 'bg-gradient-to-r from-emerald-500 to-teal-400',
        subtle: 'bg-gradient-to-br from-white/5 to-white/[0.02]',
    },
    // Glassmorphism card
    glassCard: 'bg-white/[0.03] backdrop-blur-xl border border-white/10 rounded-2xl',
    // Typography
    heading: {
        h1: 'text-5xl md:text-6xl lg:text-7xl font-bold tracking-tight',
        h2: 'text-3xl md:text-4xl lg:text-5xl font-bold tracking-tight',
        h3: 'text-xl md:text-2xl font-semibold',
        subtitle: 'text-lg md:text-xl text-gray-400',
    },
    // Buttons
    button: {
        primary: 'px-6 py-3 rounded-full bg-white text-black font-semibold hover:bg-gray-100 transition-all',
        secondary: 'px-6 py-3 rounded-full border border-white/20 text-white font-medium hover:bg-white/5 transition-all',
        accent: 'px-6 py-3 rounded-full bg-gradient-to-r from-emerald-500 to-teal-400 text-white font-semibold hover:opacity-90 transition-all',
    },
    // Spacing
    section: 'py-20 md:py-32',
    container: 'max-w-7xl mx-auto px-4 sm:px-6 lg:px-8',
};
